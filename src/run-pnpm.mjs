/**
 * The pnpm path.
 *
 * pnpm enforces release age, trust downgrades, lifecycle scripts and exotic
 * sub-dependencies itself, from the global config this tool installs. The
 * wrapper's job is therefore narrower than for npm:
 *
 *   - make the active policy visible on every run,
 *   - refuse command-line flags that would switch that policy off,
 *   - check the manifest for block-listed and known-malicious packages, which is
 *     the one rule pnpm has no setting for (the hook covers the rest of the tree),
 *   - check the lockfile for the same, because an install that has nothing to
 *     resolve never reaches the hook,
 *   - shout if the global config has gone missing, because pnpm would then run
 *     with no policy at all and say nothing.
 */

import fs from 'node:fs';
import { audit, banner, checked, info, warn } from './logger.mjs';
import { loadPolicy } from './policy.mjs';
import { abort, delegate } from './execute.mjs';
import { classify, inspectArgv, unknownCommandReason } from './guard-argv.mjs';
import { inspectManifest } from './guard-manifest.mjs';
import { inspectPnpmLockfile } from './guard-pnpm.mjs';
import { compromisedListSummary, compromisedListViolation, loadCompromisedList } from './compromised.mjs';
import { PNPM_LOCK_FILE } from './lockfile.mjs';
import { findManager } from './which.mjs';
import { localPolicyFile, pnpmConfigFile, pnpmHookFile, policyFile } from './paths.mjs';

/** The hook only enforces anything if pnpm has been told to load it. */
function verifyHookWiring() {
    const configFile = pnpmConfigFile();
    if (!fs.existsSync(configFile)) return `pnpm global config is missing: ${configFile}`;

    const config = fs.readFileSync(configFile, 'utf8');
    if (!config.includes(pnpmHookFile)) return `pnpm global config does not point at ${pnpmHookFile}`;
    if (!/^\s*minimumReleaseAge\s*:/m.test(config)) return `pnpm global config sets no minimumReleaseAge`;

    return null;
}

export async function runPnpm({ command, argv, cwd }) {
    const policy = loadPolicy();
    const manager = findManager(command === 'pnpx' ? 'pnpx' : 'pnpm');

    banner({
        command: `${command} ${argv.join(' ')}`.trim(),
        policyFiles: fs.existsSync(localPolicyFile) ? [policyFile, localPolicyFile] : [policyFile],
        hookFile: pnpmHookFile,
        extras: manager ? { binary: manager.file } : {},
    });

    if (!manager) {
        warn(`no real ${command} found on PATH — is pnpm installed outside the shim directory?`);
        return 127;
    }

    const wiringProblem = verifyHookWiring();
    if (wiringProblem) {
        warn(`${wiringProblem} — run "node install.mjs" from the secure-npm repository`);
        audit({ event: 'warn', rule: 'hook-not-wired', command, cwd, reason: wiringProblem });
    }

    const { isInstall } = classify(command, argv);
    const context = { command: `${command} ${argv.join(' ')}`.trim(), cwd };

    const unknown = unknownCommandReason(command, argv, cwd);
    if (unknown) {
        warn(unknown.reason);
        info(unknown.hint);
        audit({ event: 'warn', rule: 'unknown-command', command, argv, cwd, reason: unknown.reason });
    }

    const argvViolations = inspectArgv(policy, command, argv);
    if (argvViolations.length) return abort({ ...context, phase: 'argv', violations: argvViolations });

    if (isInstall) {
        const list = await loadCompromisedList(policy);
        const listViolation = compromisedListViolation(list);
        if (listViolation) return abort({ ...context, phase: 'compromised-list', violations: [listViolation] });

        const manifestViolations = inspectManifest(policy, cwd, list.index);
        if (manifestViolations.length) return abort({ ...context, phase: 'manifest', violations: manifestViolations });

        const { violations: lockViolations, count } = inspectPnpmLockfile(policy, cwd, list.index);
        if (lockViolations.length) return abort({ ...context, phase: 'lockfile', violations: lockViolations });

        // Said out loud even when nothing was refused: a guard that only speaks
        // to refuse is, on every run that passes, indistinguishable from one
        // that was never wired up. With no lockfile there is nothing pinned yet
        // and the hook checks the tree instead, as pnpm resolves it.
        const summary = compromisedListSummary(list);
        const subject = count ? `${count} package(s) in ${PNPM_LOCK_FILE}` : 'package.json';
        if (summary) checked(`${subject} cleared the malicious-package list (${summary})`);
    }

    audit({ event: 'run', command, argv, cwd });

    // Passed to the hook so it reads the same policy files as the wrapper,
    // even if the repository has been moved since pnpm's config was written.
    return delegate({ manager, argv, cwd, env: { SECURE_NPM_POLICY: policyFile } });
}
