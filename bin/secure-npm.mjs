#!/usr/bin/env node
/**
 * Single entry point for every shim: the name that was typed decides the
 * route - npm and pnpm are wrapped, everything on the block list is refused.
 */

import Logger from '../src/logs/Logger.mjs';
import Policy from '../src/policy/Policy.mjs';
import Rules from '../src/policy/Rules.mjs';
import NpmRunner from '../src/runners/NpmRunner.mjs';
import PnpmRunner from '../src/runners/PnpmRunner.mjs';
import BlockedRunner from '../src/runners/BlockedRunner.mjs';
import Self from '../src/self/Self.mjs';

const NPM_FAMILY = new Set(['npm', 'npx']);
const PNPM_FAMILY = new Set(['pnpm', 'pnpx']);

const SELF_COMMANDS = ['doctor', 'edit-policy', 'log', 'policy', 'validate', 'version'];
const UPDATE_FLAGS = new Set(['--update', '-upd']);
const UNINSTALL_FLAGS = new Set(['--uninstall', '-u']);

const USAGE = `secure-npm - supply-chain guard rails for npm and pnpm

  secure-npm validate [path]   audit an existing tree against the malicious-package list
  secure-npm doctor            check that the guard rails are actually wired up
  secure-npm edit-policy       open this machine's policy overlay, creating it if needed
  secure-npm log [count]       show the most recent audit entries
  secure-npm policy            print the effective policy
  secure-npm version           print the version and the install root
  secure-npm --update, -upd    check the repository for a newer version and offer to install it
  secure-npm --uninstall, -u   remove everything the installer put in place

npm, npx, pnpm and pnpx are shimmed onto PATH by installer.mjs and route through
the guard rails on their own - there is nothing to prefix with this command.
`;

const HELP_FLAGS = new Set(['--help', '-h', undefined]);

async function runMaintenance(word) {
    if (UPDATE_FLAGS.has(word)) {
        const { default: Updater } = await import('../src/install/Updater.mjs');
        return Updater.run();
    }

    const { default: Installer } = await import('../src/install/Installer.mjs');
    await Installer.uninstall();
    return process.exitCode ?? 0;
}

async function main() {
    const [invoked, ...argv] = process.argv.slice(2);
    const cwd = process.cwd();

    if (HELP_FLAGS.has(invoked)) {
        Logger.write(USAGE);
        return 0;
    }

    // `--self doctor` is how the shim reaches these without a package manager
    // one day called "doctor" being able to shadow them.
    if (invoked === '--self') {
        const [selfCommand, ...rest] = argv;
        if (SELF_COMMANDS.includes(selfCommand)) return Self.run(selfCommand, rest);
        if (UPDATE_FLAGS.has(selfCommand) || UNINSTALL_FLAGS.has(selfCommand)) return runMaintenance(selfCommand);

        if (!HELP_FLAGS.has(selfCommand)) Logger.writeErr(`secure-npm: unknown command "${selfCommand}"\n\n`);
        Logger.write(USAGE);
        return HELP_FLAGS.has(selfCommand) ? 0 : 2;
    }

    if (SELF_COMMANDS.includes(invoked)) return Self.run(invoked, argv);
    if (UPDATE_FLAGS.has(invoked) || UNINSTALL_FLAGS.has(invoked)) return runMaintenance(invoked);

    const policy = Policy.load();
    Logger.maybePruneAuditLog(policy.logRetentionDays);

    if (NPM_FAMILY.has(invoked)) return NpmRunner.run({ command: invoked, argv, cwd });
    if (PNPM_FAMILY.has(invoked)) return PnpmRunner.run({ command: invoked, argv, cwd });
    if (Rules.blockedManagerReason(policy, invoked)) return BlockedRunner.run({ command: invoked, argv, cwd });

    Logger.writeErr(`secure-npm: no route for "${invoked}"\n\n${USAGE}`);
    return 2;
}

main()
    .then(code => process.exit(code ?? 0))
    .catch(error => {
        Logger.writeErr(`secure-npm: ${error?.stack ?? error}\n`);
        process.exit(1);
    });
