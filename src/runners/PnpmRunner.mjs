import fs from 'node:fs';
import Logger from '../logs/Logger.mjs';
import Policy from '../policy/Policy.mjs';
import System from '../system/System.mjs';
import ArgvGuard from '../guards/ArgvGuard.mjs';
import ManifestGuard from '../guards/ManifestGuard.mjs';
import PnpmGuard from '../guards/PnpmGuard.mjs';
import PnpmChecksum from '../guards/PnpmChecksum.mjs';
import LockFiles from '../guards/LockFiles.mjs';
import Compromised from '../compromised/Compromised.mjs';
import { LOCAL_POLICY_FILE, PNPM_CONFIG_FILE, PNPM_HOOK_FILE, POLICY_FILE } from '../paths.mjs';

/**
 * pnpm enforces release age, trust and lifecycle scripts itself, from the
 * global config the installer writes. The wrapper's job is narrower than for
 * npm: refuse flags that switch that off, check what pnpm has no setting for,
 * and shout when the global config has gone missing.
 */
export default class PnpmRunner {
    /** The hook only enforces anything if pnpm has been told to load it. **/
    static #verifyHookWiring() {
        if (!fs.existsSync(PNPM_CONFIG_FILE)) return `pnpm global config is missing: ${PNPM_CONFIG_FILE}`;

        const config = fs.readFileSync(PNPM_CONFIG_FILE, 'utf8');
        if (!config.includes(PNPM_HOOK_FILE)) return `pnpm global config does not point at ${PNPM_HOOK_FILE}`;
        if (!/^\s*minimumReleaseAge\s*:/m.test(config)) return `pnpm global config sets no minimumReleaseAge`;

        return null;
    }

    /** @returns {Promise<number>} **/
    static async run({ command, argv, cwd }) {
        const policy = Policy.load();
        const manager = System.findManager(command === 'pnpx' ? 'pnpx' : 'pnpm');

        Logger.banner({
            command: `${command} ${argv.join(' ')}`.trim(),
            policyFiles: fs.existsSync(LOCAL_POLICY_FILE) ? [POLICY_FILE, LOCAL_POLICY_FILE] : [POLICY_FILE],
            hookFile: PNPM_HOOK_FILE,
            extras: manager ? { binary: manager.file } : {},
        });

        if (!manager) {
            Logger.warn(`no real ${command} found on PATH - is pnpm installed outside the shim directory?`);
            return 127;
        }

        const wiringProblem = this.#verifyHookWiring();
        if (wiringProblem) {
            Logger.warn(`${wiringProblem} - run "node installer.mjs" from the secure-npm repository`);
            Logger.audit({ event: 'warn', rule: 'hook-not-wired', command, cwd, reason: wiringProblem });
        }

        const { isInstall, command: commandWord, ownArgv } = ArgvGuard.classify(command, argv);
        const context = { command: `${command} ${argv.join(' ')}`.trim(), cwd };

        const unknown = ArgvGuard.unknownCommandReason(command, argv, cwd);
        if (unknown) {
            Logger.warn(unknown.reason);
            Logger.info(unknown.hint);
            Logger.audit({ event: 'warn', rule: 'unknown-command', command, argv, cwd, reason: unknown.reason });
        }

        const argvViolations = ArgvGuard.inspect(policy, command, argv);
        if (argvViolations.length) return System.abort({ ...context, phase: 'argv', violations: argvViolations });

        if (isInstall) {
            const list = await Compromised.load(policy);
            const listViolation = Compromised.listViolation(list);
            if (listViolation) return System.abort({ ...context, phase: 'compromised-list', violations: [listViolation] });

            const manifestViolations = ManifestGuard.inspect(policy, cwd, list.index);
            if (manifestViolations.length) {
                return System.abort({ ...context, phase: 'manifest', violations: manifestViolations });
            }

            const { violations: lockViolations, count } = PnpmGuard.inspectLockfile(policy, cwd, list.index);
            if (lockViolations.length) return System.abort({ ...context, phase: 'lockfile', violations: lockViolations });

            // Said out loud even when nothing was refused: a guard that only
            // speaks to refuse is indistinguishable from one never wired up.
            const summary = Compromised.summary(list);
            const subject = count ? `${count} package(s) in ${LockFiles.PNPM_LOCK_FILE}` : 'package.json';
            if (summary) Logger.checked(`${subject} cleared the malicious-package list (${summary})`);
        }

        const frozen = PnpmChecksum.frozenLockfileInstall(commandWord, ownArgv);
        Logger.audit({ event: 'run', command, argv, cwd, frozen });

        // A frozen install never calls the hook, yet the wired-up global
        // pnpmfile still makes pnpm compute a checksum it then refuses to
        // match. The lockfile pass above is the check that matters here.
        const delivered = frozen ? PnpmChecksum.withGlobalPnpmfileDisabled(argv) : argv;
        if (frozen) {
            Logger.info(`frozen install - the resolution hook is inert here and is left out, so pnpm's pnpmfileChecksum cannot block it`);
        }

        // SECURE_NPM_POLICY points the hook at the same policy files as the wrapper.
        const code = await System.delegate({ manager, argv: delivered, cwd, env: { SECURE_NPM_POLICY: POLICY_FILE } });

        // Mirror image: a resolving install runs the hook and pnpm writes the
        // empty checksum; committed, it breaks frozen installs elsewhere.
        if (isInstall && !frozen && code === 0) {
            const lockFile = PnpmGuard.findLockfile(cwd);
            if (lockFile && PnpmChecksum.stripPhantom(lockFile)) {
                Logger.info(`cleared the empty pnpmfileChecksum pnpm stamped into ${LockFiles.PNPM_LOCK_FILE} - it pins nothing and would fail frozen installs elsewhere`);
            }
        }

        return code;
    }
}
