#!/usr/bin/env node
/**
 * Single entry point for every shim.
 *
 * Shims call `node bin/secure-npm.mjs <manager> <original arguments…>`, so the
 * name that was typed decides the route: npm and pnpm are wrapped, everything
 * else on the block list is refused.
 */

import { loadPolicy } from '../src/policy.mjs';
import { maybePruneAuditLog } from '../src/logger.mjs';
import { blockedManagerReason } from '../src/rules.mjs';
import { runNpm } from '../src/run-npm.mjs';
import { runPnpm } from '../src/run-pnpm.mjs';
import { runBlocked } from '../src/run-blocked.mjs';
import { runSelfCommand } from '../src/self.mjs';

const NPM_FAMILY = new Set(['npm', 'npx']);
const PNPM_FAMILY = new Set(['pnpm', 'pnpx']);

const SELF_COMMANDS = ['doctor', 'log', 'policy', 'version'];

const USAGE = `secure-npm — supply-chain guard rails for npm and pnpm

  secure-npm doctor            check that the guard rails are actually wired up
  secure-npm log [count]       show the most recent audit entries
  secure-npm policy            print the effective policy
  secure-npm version           print the version and the install root

npm, npx, pnpm and pnpx are shimmed onto PATH by install.mjs and route through
the guard rails on their own — there is nothing to prefix with this command.
`;

const HELP_FLAGS = new Set(['--help', '-h', undefined]);

async function main() {
    const [invoked, ...argv] = process.argv.slice(2);
    const cwd = process.cwd();

    if (HELP_FLAGS.has(invoked)) {
        process.stdout.write(USAGE);
        return 0;
    }

    // `--self doctor` is how the secure-npm shim reaches these without a
    // package manager one day called "doctor" being able to shadow them.
    if (invoked === '--self') {
        const [selfCommand, ...rest] = argv;
        if (SELF_COMMANDS.includes(selfCommand)) return runSelfCommand(selfCommand, rest);

        if (!HELP_FLAGS.has(selfCommand)) process.stderr.write(`secure-npm: unknown command "${selfCommand}"\n\n`);
        process.stdout.write(USAGE);
        return HELP_FLAGS.has(selfCommand) ? 0 : 2;
    }

    if (SELF_COMMANDS.includes(invoked)) return runSelfCommand(invoked, argv);

    const policy = loadPolicy();
    maybePruneAuditLog(policy.logRetentionDays);

    if (NPM_FAMILY.has(invoked)) return runNpm({ command: invoked, argv, cwd });
    if (PNPM_FAMILY.has(invoked)) return runPnpm({ command: invoked, argv, cwd });
    if (blockedManagerReason(policy, invoked)) return runBlocked({ command: invoked, argv, cwd });

    process.stderr.write(`secure-npm: no route for "${invoked}"\n\n${USAGE}`);
    return 2;
}

main()
    .then(code => process.exit(code ?? 0))
    .catch(error => {
        process.stderr.write(`secure-npm: ${error?.stack ?? error}\n`);
        process.exit(1);
    });
