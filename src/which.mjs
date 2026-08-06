/**
 * Locating the *real* npm and pnpm.
 *
 * The shims are named `npm` and `pnpm` and sit first on PATH, so a naive
 * lookup finds them again and recurses. Every PATH entry holding the shim
 * marker file is skipped, which makes the search terminate on the genuine
 * binary regardless of how the machine installs Node.
 */

import fs from 'node:fs';
import path from 'node:path';
import { shimMarkerFile } from './paths.mjs';

const IS_WINDOWS = process.platform === 'win32';

const WINDOWS_EXTENSIONS = ['.cmd', '.exe', '.bat', ''];
const SCRIPT_EXTENSIONS = new Set(['.js', '.cjs', '.mjs']);

/** JS entry point shipped alongside each manager's launcher script. */
const NODE_ENTRY_POINTS = {
    npm: ['node_modules/npm/bin/npm-cli.js'],
    npx: ['node_modules/npm/bin/npx-cli.js'],
    pnpm: ['node_modules/pnpm/bin/pnpm.cjs'],
    pnpx: ['node_modules/pnpm/bin/pnpx.cjs'],
};

const MARKER_NAME = path.basename(shimMarkerFile);

function isShimDirectory(directory) {
    return fs.existsSync(path.join(directory, MARKER_NAME));
}

function candidatesIn(directory, name) {
    const extensions = IS_WINDOWS ? WINDOWS_EXTENSIONS : [''];
    return extensions.map(extension => path.join(directory, `${name}${extension}`));
}

function isExecutableFile(file) {
    try {
        return fs.statSync(file).isFile();
    } catch {
        return false;
    }
}

/**
 * Resolves to a JS file whenever possible: spawning `node <script>` sidesteps
 * Windows' rule that `.cmd` files require a shell, and with it the quoting
 * problems that come from passing user arguments through one.
 */
function toNodeScript(launcher, name) {
    const real = (() => {
        try {
            return fs.realpathSync(launcher);
        } catch {
            return launcher;
        }
    })();

    if (SCRIPT_EXTENSIONS.has(path.extname(real))) return real;

    for (const base of [path.dirname(launcher), path.dirname(real), path.join(path.dirname(real), '..')]) {
        for (const relative of NODE_ENTRY_POINTS[name] ?? []) {
            const entry = path.join(base, ...relative.split('/'));
            if (isExecutableFile(entry)) return entry;
        }
    }

    return null;
}

/**
 * @returns {{ kind: 'node-script' | 'executable', file: string, launcher: string } | null}
 */
export function findManager(name) {
    const pathEntries = (process.env.PATH ?? '').split(path.delimiter).filter(Boolean);

    for (const entry of pathEntries) {
        const directory = entry.replace(/^"|"$/g, '');
        if (directory === '' || isShimDirectory(directory)) continue;

        for (const candidate of candidatesIn(directory, name)) {
            if (!isExecutableFile(candidate)) continue;

            const script = toNodeScript(candidate, name);
            return script
                ? { kind: 'node-script', file: script, launcher: candidate }
                : { kind: 'executable', file: candidate, launcher: candidate };
        }
    }

    return null;
}

/** True when `command` resolves to something outside our own shim directory. */
export function isInstalled(command) {
    return findManager(command) !== null;
}
