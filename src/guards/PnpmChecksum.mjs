import crypto from 'node:crypto';
import fs from 'node:fs';

/**
 * Working around pnpm's `pnpmfileChecksum` for a global-only hook.
 *
 * pnpm stamps the field whenever a loaded pnpmfile exports hooks, but excludes
 * the global file from the digest - so with no local pnpmfile it hashes the
 * empty string instead of recording nothing. Machines running secure-npm then
 * disagree with machines that do not, and frozen installs die on
 * ERR_PNPM_LOCKFILE_CONFIG_MISMATCH over a value that pins nothing. The drop
 * lives in the hook (the only code every pnpm invocation loads), the strip
 * cleans lockfiles that already carry it, and frozen installs are delegated
 * with the inert hook switched off. Deletable the day pnpm records undefined
 * for an empty file set.
 */
export default class PnpmChecksum {
    /** `sha256-` + base64(sha256("")): the digest of an empty file set. **/
    static EMPTY = `sha256-${crypto.createHash('sha256').update('').digest('base64')}`;

    /** `pnpm ci` and its aliases: they link strictly from the lockfile. **/
    static #FROZEN_INSTALL_COMMANDS = new Set(['ci', 'clean-install', 'ic', 'install-clean']);
    /** Plain installs pnpm freezes on request, or on its own under CI. **/
    static #FREEZABLE_INSTALL_COMMANDS = new Set(['install', 'i', 'import', 'install-test', 'it']);

    static #ciEnvironment() {
        const value = process.env.CI;
        return value != null && value !== '' && value !== '0' && value !== 'false';
    }

    /**
     * Whether pnpm will run this command as a frozen (headless) install, with
     * the resolution hook never called. Only installs can freeze; an explicit
     * opt-out always wins.
     *
     * @param {string} commandWord
     * @param {string[]} ownArgv The manager's own arguments, before any `--`.
     * @param {boolean} [ci]
     */
    static frozenLockfileInstall(commandWord, ownArgv, ci = this.#ciEnvironment()) {
        const has = (...flags) => ownArgv.some(argument => flags.includes(argument));
        const optedOut = has('--no-frozen-lockfile', '--frozen-lockfile=false');

        if (this.#FROZEN_INSTALL_COMMANDS.has(commandWord)) return !optedOut;
        if (this.#FREEZABLE_INSTALL_COMMANDS.has(commandWord)) {
            if (optedOut) return false;
            if (has('--frozen-lockfile', '--frozen-lockfile=true')) return true;
            return ci;
        }
        return false;
    }

    /**
     * The command line with pnpm's global pnpmfile off for one invocation. The
     * flag goes before any `--`, so pnpm reads it rather than the script run.
     */
    static withGlobalPnpmfileDisabled(argv) {
        const flag = '--config.global-pnpmfile=';
        const separator = argv.indexOf('--');
        return separator === -1
            ? [...argv, flag]
            : [...argv.slice(0, separator), flag, ...argv.slice(separator)];
    }

    /**
     * Drops the phantom checksum from the lockfile object pnpm is about to
     * write, from the hook's `afterAllResolved`. Only ever that exact digest -
     * a real local pnpmfile's is left alone.
     *
     * @param {Object} lockfile Mutated in place.
     * @returns {boolean} Whether the field was dropped.
     */
    static dropPhantom(lockfile) {
        if (!lockfile || lockfile.pnpmfileChecksum !== this.EMPTY) return false;

        delete lockfile.pnpmfileChecksum;
        return true;
    }

    /** Line equality tolerating a trailing CR, so CRLF lockfiles match too. **/
    static #sameLine = (line, text) => line === text || line.replace(/\r$/, '') === text;

    /**
     * Removes the phantom checksum from a lockfile already carrying it. A line
     * edit rather than a YAML round-trip, so nothing else is reformatted.
     *
     * @returns {boolean} Whether the file was rewritten.
     */
    static stripPhantom(lockFile) {
        let content;
        try {
            content = fs.readFileSync(lockFile, 'utf8');
        } catch {
            return false;
        }

        const target = `pnpmfileChecksum: ${this.EMPTY}`;
        const lines = content.split('\n');
        const index = lines.findIndex(line => this.#sameLine(line, target));
        if (index === -1) return false;

        // One blank line goes with it, so the header keeps a single gap.
        const blankAfter = index + 1 < lines.length && this.#sameLine(lines[index + 1], '') ? 1 : 0;
        lines.splice(index, 1 + blankAfter);

        fs.writeFileSync(lockFile, lines.join('\n'), 'utf8');
        return true;
    }
}
