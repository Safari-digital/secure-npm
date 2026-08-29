import fs from 'node:fs';
import Logger from '../logs/Logger.mjs';
import Policy from '../policy/Policy.mjs';
import Rules from '../policy/Rules.mjs';
import System from '../system/System.mjs';
import Registry from '../registry/Registry.mjs';
import ArgvGuard from '../guards/ArgvGuard.mjs';
import ManifestGuard from '../guards/ManifestGuard.mjs';
import NpmGuard from '../guards/NpmGuard.mjs';
import Compromised from '../compromised/Compromised.mjs';
import { LOCAL_POLICY_FILE, POLICY_FILE } from '../paths.mjs';

/**
 * npm ships no release-age check, no trust policy and no resolution hook, so
 * every rule is enforced here, before the real command starts.
 */
export default class NpmRunner {
    /** npx targets are usually unpinned; resolve the tag so the age check has a version. **/
    static async #resolveExecTargets(policy, targets) {
        const resolved = [];
        const violations = [];

        for (const target of targets) {
            if (!target.name || target.exotic) continue;

            const registry = Rules.registryFor(policy, target.name);
            if (registry === null) continue; // Already reported by the argv guard.

            if (target.version && /^\d/.test(target.version)) {
                resolved.push({ name: target.name, version: target.version });
                continue;
            }

            const { version, reason } = await Registry.resolveDistTag(registry, target.name, target.version ?? 'latest');
            if (version === null) {
                violations.push({ rule: 'unresolvable-target', subject: target.raw, reason });
                continue;
            }

            resolved.push({ name: target.name, version });
        }

        return { resolved, violations };
    }

    /** @returns {Promise<number>} **/
    static async run({ command, argv, cwd }) {
        const policy = Policy.load();
        const manager = System.findManager(command === 'npx' ? 'npx' : 'npm');

        Logger.banner({
            command: `${command} ${argv.join(' ')}`.trim(),
            policyFiles: fs.existsSync(LOCAL_POLICY_FILE) ? [POLICY_FILE, LOCAL_POLICY_FILE] : [POLICY_FILE],
            extras: manager ? { binary: manager.file } : {},
        });

        if (!manager) {
            Logger.warn(`no real ${command} found on PATH - is Node installed outside the shim directory?`);
            return 127;
        }

        const { command: subCommand, isInstall, isExec, targets } = ArgvGuard.classify(command, argv);
        const context = { command: `${command} ${argv.join(' ')}`.trim(), cwd };

        const unknown = ArgvGuard.unknownCommandReason(command, argv, cwd);
        if (unknown) {
            Logger.warn(unknown.reason);
            Logger.info(unknown.hint);
            Logger.audit({ event: 'warn', rule: 'unknown-command', command, argv, cwd, reason: unknown.reason });
        }

        const argvViolations = ArgvGuard.inspect(policy, command, argv);
        if (argvViolations.length) return System.abort({ ...context, phase: 'argv', violations: argvViolations });

        // Only fetched for the commands that bring code in.
        const list = isInstall || isExec ? await Compromised.load(policy) : { index: null, reason: null };
        const listViolation = Compromised.listViolation(list);
        if (listViolation) return System.abort({ ...context, phase: 'compromised-list', violations: [listViolation] });

        const compromised = list.index;

        // "It passed" is only worth reading next to what it passed against.
        const summary = Compromised.summary(list);
        const cleared = subject =>
            Logger.checked(
                summary
                    ? `${subject} cleared the policy and the malicious-package list (${summary})`
                    : `${subject} cleared the policy`
            );

        if (isInstall) {
            const manifestViolations = ManifestGuard.inspect(policy, cwd, compromised);
            if (manifestViolations.length) {
                return System.abort({ ...context, phase: 'manifest', violations: manifestViolations });
            }
        }

        if (isExec && targets.length) {
            const { resolved, violations } = await this.#resolveExecTargets(policy, targets);
            const packageViolations = [
                ...violations,
                ...(await NpmGuard.inspectPackages(policy, resolved, { compromised })),
            ];
            if (packageViolations.length) {
                return System.abort({ ...context, phase: 'exec-target', violations: packageViolations });
            }
            if (resolved.length) cleared(resolved.map(p => `${p.name}@${p.version}`).join(', '));
        }

        // `npm ci` reinstalls the whole lockfile, and its dry-run report says
        // nothing when node_modules is populated - check the lockfile directly.
        if (subCommand === 'ci' || subCommand === 'clean-install') {
            const { packages: pinned, gitSourced } = NpmGuard.lockfilePackages(cwd);
            Logger.info(`checking the ${pinned.length} package(s) pinned in package-lock.json…`);

            // The list is checked by the lockfile pass alone - it knows the
            // install path; a package it refused stays out of the age check.
            const lockViolations = NpmGuard.inspectLockfile(policy, cwd, compromised);
            const candidates = pinned.filter(({ name, version }) => !Compromised.reason(compromised, name, version));

            const violations = [...lockViolations, ...(await NpmGuard.inspectPackages(policy, candidates, { gitSourced }))];
            if (violations.length) return System.abort({ ...context, phase: 'lockfile', violations });

            cleared(`${pinned.length} package(s) pinned in package-lock.json`);
        } else if (isInstall) {
            Logger.info('asking npm what it would install (dry run, nothing is written)…');
            const preview = await NpmGuard.preview({ manager, argv, cwd });

            if (!preview.ok) {
                return System.abort({
                    ...context,
                    phase: 'resolution-preview',
                    violations: [
                        {
                            rule: 'preview-failed',
                            subject: context.command,
                            reason: preview.reason,
                            hint: 'the real install would fail the same way - fix the resolution error first',
                        },
                    ],
                });
            }

            if (preview.packages.length === 0) {
                Logger.info('nothing new to resolve');
                if (summary) Logger.checked(`package.json cleared the malicious-package list (${summary})`);
            } else {
                // Whitelisted git sources cleared the guards above; the age
                // check must not then judge them by the registry.
                const gitSourced = new Set([
                    ...ManifestGuard.gitSourcedNames(cwd),
                    ...targets.map(target => target.gitName).filter(Boolean),
                ]);

                const packageViolations = await NpmGuard.inspectPackages(policy, preview.packages, {
                    gitSourced,
                    compromised,
                });
                if (packageViolations.length) {
                    return System.abort({ ...context, phase: 'resolution', violations: packageViolations });
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
        const code = await System.delegate({ manager, argv: effectiveArgv, cwd });

        // Post-install sweep: exotic resolutions deeper in the tree are only visible now.
        if (isInstall && code === 0) {
            const lockViolations = NpmGuard.inspectLockfile(policy, cwd, compromised);
            if (lockViolations.length) {
                Logger.warn('the install finished before these were found - no scripts ran, but review node_modules');
                return System.abort({ ...context, phase: 'lockfile', violations: lockViolations });
            }
        }

        return code;
    }
}
