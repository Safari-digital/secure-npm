/**
 * The npm path.
 *
 * npm ships no release-age check, no trust policy and no resolution hook, so
 * every rule is enforced here, before the real command is allowed to start.
 */

import Logger from './logs/Logger.mjs';
import { loadPolicy } from './policy.mjs';
import { abort, delegate } from './execute.mjs';
import { classify, inspectArgv, unknownCommandReason } from './guard-argv.mjs';
import { gitSourcedManifestNames, inspectManifest } from './guard-manifest.mjs';
import { inspectLockfile, inspectPackages, lockfilePackages, previewResolution } from './guard-npm.mjs';
import {
    compromisedListSummary,
    compromisedListViolation,
    compromisedReason,
    loadCompromisedList,
} from './compromised.mjs';
import { resolveDistTag } from './registry.mjs';
import { registryFor } from './rules.mjs';
import { findManager } from './which.mjs';
import { POLICY_FILE, LOCAL_POLICY_FILE } from './paths.mjs';
import fs from 'node:fs';

/** npx targets are usually unpinned; resolve the tag so the age check has a version. */
async function resolveExecTargets(policy, targets) {
    const resolved = [];
    const violations = [];

    for (const target of targets) {
        if (!target.name || target.exotic) continue;

        const registry = registryFor(policy, target.name);
        if (registry === null) continue; // Already reported by the argv guard.

        if (target.version && /^\d/.test(target.version)) {
            resolved.push({ name: target.name, version: target.version });
            continue;
        }

        const { version, reason } = await resolveDistTag(registry, target.name, target.version ?? 'latest');
        if (version === null) {
            violations.push({ rule: 'unresolvable-target', subject: target.raw, reason });
            continue;
        }

        resolved.push({ name: target.name, version });
    }

    return { resolved, violations };
}

export async function runNpm({ command, argv, cwd }) {
    const policy = loadPolicy();
    const manager = findManager(command === 'npx' ? 'npx' : 'npm');

    Logger.banner({
        command: `${command} ${argv.join(' ')}`.trim(),
        policyFiles: fs.existsSync(LOCAL_POLICY_FILE) ? [POLICY_FILE, LOCAL_POLICY_FILE] : [POLICY_FILE],
        extras: manager ? { binary: manager.file } : {},
    });

    if (!manager) {
        Logger.warn(`no real ${command} found on PATH — is Node installed outside the shim directory?`);
        return 127;
    }

    const { command: subCommand, isInstall, isExec, targets } = classify(command, argv);
    const context = { command: `${command} ${argv.join(' ')}`.trim(), cwd };

    const unknown = unknownCommandReason(command, argv, cwd);
    if (unknown) {
        Logger.warn(unknown.reason);
        Logger.info(unknown.hint);
        Logger.audit({ event: 'warn', rule: 'unknown-command', command, argv, cwd, reason: unknown.reason });
    }

    const argvViolations = inspectArgv(policy, command, argv);
    if (argvViolations.length) return abort({ ...context, phase: 'argv', violations: argvViolations });

    // Only fetched for the commands that bring code in: `npm run build` has no
    // business waiting on a network request.
    const list = isInstall || isExec ? await loadCompromisedList(policy) : { index: null, reason: null };
    const listViolation = compromisedListViolation(list);
    if (listViolation) return abort({ ...context, phase: 'compromised-list', violations: [listViolation] });

    const compromised = list.index;

    // One line per cleared set, naming both checks rather than one: "it passed"
    // is only worth reading next to what it passed against.
    const summary = compromisedListSummary(list);
    const cleared = subject =>
        Logger.checked(
            summary
                ? `${subject} cleared the policy and the malicious-package list (${summary})`
                : `${subject} cleared the policy`
        );

    if (isInstall) {
        const manifestViolations = inspectManifest(policy, cwd, compromised);
        if (manifestViolations.length) return abort({ ...context, phase: 'manifest', violations: manifestViolations });
    }

    if (isExec && targets.length) {
        const { resolved, violations } = await resolveExecTargets(policy, targets);
        const packageViolations = [...violations, ...(await inspectPackages(policy, resolved, { compromised }))];
        if (packageViolations.length) return abort({ ...context, phase: 'exec-target', violations: packageViolations });
        if (resolved.length) cleared(resolved.map(p => `${p.name}@${p.version}`).join(', '));
    }

    // `npm ci` reinstalls the whole lockfile, and its dry-run report says
    // nothing when node_modules is already populated. The lockfile is the
    // package set, so it is checked directly and the preview is skipped.
    if (subCommand === 'ci' || subCommand === 'clean-install') {
        const { packages: pinned, gitSourced } = lockfilePackages(cwd);
        Logger.info(`checking the ${pinned.length} package(s) pinned in package-lock.json…`);

        // The malicious-package list is checked by the lockfile pass alone: both
        // passes walk the same entries here, and only that one knows the install
        // path each of them sits at. A package it has already refused is then
        // kept out of the age check — a second rule firing on a package that is
        // not going to be installed either way only buries the first one.
        const lockViolations = inspectLockfile(policy, cwd, compromised);
        const candidates = pinned.filter(({ name, version }) => !compromisedReason(compromised, name, version));

        const violations = [...lockViolations, ...(await inspectPackages(policy, candidates, { gitSourced }))];
        if (violations.length) return abort({ ...context, phase: 'lockfile', violations });

        cleared(`${pinned.length} package(s) pinned in package-lock.json`);
    } else if (isInstall) {
        Logger.info('asking npm what it would install (dry run, nothing is written)…');
        const preview = await previewResolution({ manager, argv, cwd });

        if (!preview.ok) {
            return abort({
                ...context,
                phase: 'resolution-preview',
                violations: [
                    {
                        rule: 'preview-failed',
                        subject: context.command,
                        reason: preview.reason,
                        hint: 'the real install would fail the same way — fix the resolution error first',
                    },
                ],
            });
        }

        if (preview.packages.length === 0) {
            Logger.info('nothing new to resolve');
            // package.json still went past the list, and the lockfile sweep
            // below reads the rest of the tree once npm is done.
            if (summary) Logger.checked(`package.json cleared the malicious-package list (${summary})`);
        } else {
            // Whitelisted git sources cleared the argv and manifest guards
            // above; the age check must not then judge them by the registry.
            const gitSourced = new Set([
                ...gitSourcedManifestNames(cwd),
                ...targets.map(target => target.gitName).filter(Boolean),
            ]);

            const packageViolations = await inspectPackages(policy, preview.packages, { gitSourced, compromised });
            if (packageViolations.length) {
                return abort({ ...context, phase: 'resolution', violations: packageViolations });
            }
            cleared(`${preview.packages.length} resolved package(s)`);
        }
    }

    const effectiveArgv =
        policy.forceIgnoreScripts && (isInstall || isExec) && !argv.includes('--ignore-scripts')
            ? [...argv, '--ignore-scripts']
            : argv;

    if (effectiveArgv !== argv) Logger.info('lifecycle scripts disabled for this run (--ignore-scripts)');

    Logger.audit({ event: 'run', command, argv: effectiveArgv, cwd });
    const code = await delegate({ manager, argv: effectiveArgv, cwd });

    // Post-install sweep: the dry-run report carries no resolution URLs, so a
    // git or tarball dependency further down the tree is only visible now.
    if (isInstall && code === 0) {
        const lockViolations = inspectLockfile(policy, cwd, compromised);
        if (lockViolations.length) {
            Logger.warn('the install finished before these were found — no scripts ran, but review node_modules');
            return abort({ ...context, phase: 'lockfile', violations: lockViolations });
        }
    }

    return code;
}
