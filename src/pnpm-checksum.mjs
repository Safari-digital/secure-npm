/**
 * Working around pnpm's `pnpmfileChecksum` for a global-only hook.
 *
 * pnpm stamps a `pnpmfileChecksum` into the lockfile whenever any loaded
 * pnpmfile exports hooks, and refuses a frozen install whose stored checksum
 * differs from the one it recomputes. That is meant to catch a *local*
 * `.pnpmfile.cjs` changing under a pinned tree. But secure-npm's hook is wired
 * as pnpm's `globalPnpmfile`, and pnpm deliberately excludes the global file
 * from the digest (`includeInChecksum: false`). With no local pnpmfile the set
 * of files it hashes is therefore empty — and pnpm hashes the empty string
 * rather than recording nothing:
 *
 *     createHashFromMultipleFiles([])  ->  createHash("")  ->  EMPTY_PNPMFILE_CHECKSUM
 *
 * So every machine running secure-npm computes this one constant, while a
 * machine with no pnpmfile at all computes `undefined`. A lockfile written
 * without secure-npm (CI, a colleague, the repo before install) carries no
 * checksum, and `pnpm ci` here aborts on `ERR_PNPM_LOCKFILE_CONFIG_MISMATCH`
 * over a value that pins nothing and hashes no file.
 *
 * Two halves, mirror images of each other:
 *
 *   - a frozen install links straight from the lockfile and never calls the
 *     hook, so it is handed the command with the global pnpmfile switched off
 *     (`frozenLockfileInstall` + `withGlobalPnpmfileDisabled`); the wrapper's
 *     own lockfile pass is the check that matters there,
 *   - a resolving install *does* run the hook, and pnpm then writes the empty
 *     checksum into the lockfile; left there and committed it breaks frozen
 *     installs for everyone without secure-npm, so it is stripped back out
 *     (`stripPhantomPnpmfileChecksum`).
 *
 * All of this can be deleted the day pnpm records `undefined` for an empty file
 * set, or offers a global hook that stays out of the checksum entirely.
 */

import crypto from 'node:crypto';
import fs from 'node:fs';

/**
 * The checksum pnpm stamps when a hook is loaded but no file feeds the digest:
 * `sha256-` + base64(sha256("")). Computed rather than pasted so it tracks the
 * algorithm pnpm uses, and only ever compared for exact equality.
 */
export const EMPTY_PNPMFILE_CHECKSUM = `sha256-${crypto.createHash('sha256').update('').digest('base64')}`;

/** `pnpm ci` and its aliases: they wipe node_modules and link strictly from the lockfile. */
const FROZEN_INSTALL_COMMANDS = new Set(['ci', 'clean-install', 'ic', 'install-clean']);

/** Plain installs pnpm freezes only on request, or on its own when CI is set. */
const FREEZABLE_INSTALL_COMMANDS = new Set(['install', 'i', 'import', 'install-test', 'it']);

/** pnpm treats a plain install as frozen when this is set; mirror that, loosely. */
function ciEnvironment() {
    const value = process.env.CI;
    return value != null && value !== '' && value !== '0' && value !== 'false';
}

/**
 * Whether pnpm will run this command as a frozen (headless) install, linked
 * straight from the lockfile with the resolution hook never called.
 *
 * Only an install can be frozen — `add`, `update`, `run` and the rest resolve,
 * and the hook is not inert there. Among installs the precedence follows
 * pnpm's own: `ci` and its aliases are frozen by definition, a plain install
 * freezes on an explicit `--frozen-lockfile` or, failing that, under CI; an
 * explicit opt-out always wins.
 *
 * @param {string} commandWord The resolved command, e.g. `ci` or `install`.
 * @param {string[]} ownArgv The manager's own arguments (everything before `--`).
 */
export function frozenLockfileInstall(commandWord, ownArgv, ci = ciEnvironment()) {
    const has = (...flags) => ownArgv.some(argument => flags.includes(argument));
    const optedOut = has('--no-frozen-lockfile', '--frozen-lockfile=false');

    if (FROZEN_INSTALL_COMMANDS.has(commandWord)) return !optedOut;
    if (FREEZABLE_INSTALL_COMMANDS.has(commandWord)) {
        if (optedOut) return false;
        if (has('--frozen-lockfile', '--frozen-lockfile=true')) return true;
        return ci;
    }
    return false;
}

/**
 * The command line with pnpm's global pnpmfile turned off for one invocation.
 * The flag goes before any `--`, so pnpm reads it rather than the script being
 * run. The user is forbidden this flag (it would disable the policy hook); the
 * wrapper adds it only where the hook is inert anyway.
 */
export function withGlobalPnpmfileDisabled(argv) {
    const flag = '--config.global-pnpmfile=';
    const separator = argv.indexOf('--');
    return separator === -1
        ? [...argv, flag]
        : [...argv.slice(0, separator), flag, ...argv.slice(separator)];
}

/** Line equality that tolerates a trailing CR, so CRLF lockfiles match too. */
const sameLine = (line, text) => line === text || line.replace(/\r$/, '') === text;

/**
 * Removes the empty-string `pnpmfileChecksum` pnpm writes under a global-only
 * hook, if the lockfile carries exactly that. A real local pnpmfile produces a
 * different digest and is left untouched; a lockfile without the field, or one
 * that cannot be read, is a no-op.
 *
 * Done as a line edit rather than a YAML round-trip so nothing else in the
 * machine-written file is reformatted.
 *
 * @returns {boolean} Whether the file was rewritten.
 */
export function stripPhantomPnpmfileChecksum(lockFile) {
    let content;
    try {
        content = fs.readFileSync(lockFile, 'utf8');
    } catch {
        return false;
    }

    const target = `pnpmfileChecksum: ${EMPTY_PNPMFILE_CHECKSUM}`;
    const lines = content.split('\n');
    const index = lines.findIndex(line => sameLine(line, target));
    if (index === -1) return false;

    // Drop the field and one blank line beside it, so the header keeps a single
    // gap instead of the double it would otherwise leave behind.
    const blankAfter = index + 1 < lines.length && sameLine(lines[index + 1], '') ? 1 : 0;
    lines.splice(index, 1 + blankAfter);

    fs.writeFileSync(lockFile, lines.join('\n'), 'utf8');
    return true;
}
