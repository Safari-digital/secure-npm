import Logger from '../logs/Logger.mjs';
import Policy from '../policy/Policy.mjs';
import Rules from '../policy/Rules.mjs';

/**
 * Refusal shim for every manager that is not npm or pnpm - `bun install`
 * fails with a reason instead of "command not found", and the attempt lands
 * in the audit log.
 */
export default class BlockedRunner {
    /** @returns {Promise<number>} **/
    static async run({ command, argv, cwd }) {
        const policy = Policy.load();
        const reason =
            Rules.blockedManagerReason(policy, command) ?? 'this package manager is not approved on this machine';

        Logger.reportBlock({
            rule: 'blocked-manager',
            subject: `${command} ${argv.join(' ')}`.trim(),
            reason,
            hint: 'use npm or pnpm; edit "blockedManagers" in policy.json to change this',
        });

        Logger.audit({ event: 'block', phase: 'invocation', rule: 'blocked-manager', command, argv, cwd, reason });

        return 127;
    }
}
