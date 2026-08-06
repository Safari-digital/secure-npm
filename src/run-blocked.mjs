/**
 * Refusal shim for every package manager that is not npm or pnpm.
 *
 * The shim exists so that `bun install` fails with a reason instead of a
 * "command not found", and so that an attempt shows up in the audit log — a
 * build script or a README that reaches for bun is worth knowing about.
 *
 * This only covers invocation. Installation is blocked separately, by the
 * package block list that both the npm wrapper and the pnpm hook enforce.
 */

import { audit, reportBlock } from './logger.mjs';
import { loadPolicy } from './policy.mjs';
import { blockedManagerReason } from './rules.mjs';

export async function runBlocked({ command, argv, cwd }) {
    const policy = loadPolicy();
    const reason = blockedManagerReason(policy, command) ?? 'this package manager is not approved on this machine';

    reportBlock({
        rule: 'blocked-manager',
        subject: `${command} ${argv.join(' ')}`.trim(),
        reason,
        hint: 'use npm or pnpm; edit "blockedManagers" in policy.json to change this',
    });

    audit({ event: 'block', phase: 'invocation', rule: 'blocked-manager', command, argv, cwd, reason });

    return 127;
}
