import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import { APP_SHIM_MARKER_FILE, IS_WINDOWS } from '../paths.mjs';
import Logger from '../logs/Logger.mjs';

/**
 * @typedef {{ kind: 'node-script' | 'executable', file: string, launcher: string }} Manager
 * @typedef {{ rule: string, subject: string, reason: string, hint?: string }} Violation
 */

/** Finding the real package managers, handing control to them, and refusing to. */
export default class System {
    static #WINDOWS_EXTENSIONS = ['.cmd', '.exe', '.bat', ''];
    static #SCRIPT_EXTENSIONS = new Set(['.js', '.cjs', '.mjs']);
    static #MARKER_NAME = path.basename(APP_SHIM_MARKER_FILE);

    /** JS entry point shipped alongside each manager's launcher script. **/
    static #NODE_ENTRY_POINTS = {
        npm: ['node_modules/npm/bin/npm-cli.js'],
        npx: ['node_modules/npm/bin/npx-cli.js'],
        pnpm: ['node_modules/pnpm/bin/pnpm.cjs'],
        pnpx: ['node_modules/pnpm/bin/pnpx.cjs'],
    };

    static #isShimDirectory = (directory) => fs.existsSync(path.join(directory, this.#MARKER_NAME));

    static #candidatesIn(directory, name) {
        const extensions = IS_WINDOWS ? this.#WINDOWS_EXTENSIONS : [''];
        return extensions.map(extension => path.join(directory, `${name}${extension}`));
    }

    static #isExecutableFile(file) {
        try {
            return fs.statSync(file).isFile();
        } catch {
            return false;
        }
    }

    /**
     * Resolves to a JS file whenever possible: `node <script>` sidesteps
     * Windows' rule that `.cmd` files require a shell, and the quoting bugs
     * that come with one.
     */
    static #toNodeScript(launcher, name) {
        const real = (() => {
            try {
                return fs.realpathSync(launcher);
            } catch {
                return launcher;
            }
        })();

        if (this.#SCRIPT_EXTENSIONS.has(path.extname(real))) return real;

        for (const base of [path.dirname(launcher), path.dirname(real), path.join(path.dirname(real), '..')]) {
            for (const relative of this.#NODE_ENTRY_POINTS[name] ?? []) {
                const entry = path.join(base, ...relative.split('/'));
                if (this.#isExecutableFile(entry)) return entry;
            }
        }

        return null;
    }

    /**
     * The real binary on PATH, skipping every directory that holds the shim
     * marker - which is what stops a shim from resolving to itself.
     *
     * @param {string} name
     * @returns {Manager | null}
     */
    static findManager(name) {
        const pathEntries = (process.env.PATH ?? '').split(path.delimiter).filter(Boolean);

        for (const entry of pathEntries) {
            const directory = entry.replace(/^"|"$/g, '');
            if (directory === '' || this.#isShimDirectory(directory)) continue;

            for (const candidate of this.#candidatesIn(directory, name)) {
                if (!this.#isExecutableFile(candidate)) continue;

                const script = this.#toNodeScript(candidate, name);
                return script
                    ? { kind: 'node-script', file: script, launcher: candidate }
                    : { kind: 'executable', file: candidate, launcher: candidate };
            }
        }

        return null;
    }

    /** True when `command` resolves to something outside our own shim directory. **/
    static isInstalled(command) {
        return this.findManager(command) !== null;
    }

    /**
     * Runs the genuine binary with the caller's stdio, so the wrapper stays
     * invisible once the checks have passed.
     *
     * @param {{ manager: Manager, argv: string[], cwd: string, env?: Object }} _
     * @returns {Promise<number>} The child's exit code.
     */
    static delegate({ manager, argv, cwd, env = {} }) {
        const [file, args] =
            manager.kind === 'node-script'
                ? [process.execPath, [manager.file, ...argv]]
                : [manager.file, [...argv]];

        return new Promise(resolve => {
            const child = spawn(file, args, {
                cwd,
                stdio: 'inherit',
                shell: manager.kind !== 'node-script' && IS_WINDOWS,
                env: { ...process.env, ...env },
            });

            child.on('error', error => {
                Logger.writeErr(`secure-npm: could not start ${manager.file}: ${error.message}\n`);
                resolve(1);
            });

            child.on('close', (code, signal) => resolve(signal ? 1 : (code ?? 0)));
        });
    }

    /**
     * Reports every violation, records them, and stops. Never partially applied.
     *
     * @param {{ violations: Violation[], command: string, cwd: string, phase: string }} _
     * @returns {1}
     */
    static abort({ violations, command, cwd, phase }) {
        const grouped = new Map();
        for (const violation of violations) {
            if (!grouped.has(violation.rule)) grouped.set(violation.rule, []);
            grouped.get(violation.rule).push(violation);
        }

        for (const [rule, entries] of grouped) {
            Logger.reportBlocks({
                rule,
                title: `${entries.length} ${entries.length === 1 ? 'violation' : 'violations'} in ${command}`,
                entries: entries.map(entry => `${entry.subject} - ${entry.reason}`),
                hint: entries.find(entry => entry.hint)?.hint,
            });
        }

        Logger.audit({
            event: 'block',
            phase,
            command,
            cwd,
            violations: violations.map(({ rule, subject, reason }) => ({ rule, subject, reason })),
        });

        return 1;
    }
}
