/**
 * Reading a dependency tree back out of the files that pin it.
 *
 * Parser only — no policy, no network, no reporting. Three files answer the same
 * question, which exact versions of which packages does this project hold, and
 * each of them answers it somewhere else:
 *
 *   package-lock.json  `packages`, keyed by install path (lockfileVersion 2 & 3),
 *                      and the legacy `dependencies` tree (lockfileVersion 1)
 *   pnpm-lock.yaml     the top-level `packages:` section, pnpm v5 through v9
 *   package.json       declared ranges, which are not versions at all
 *
 * A name maps to a list rather than to a single entry: the same package is
 * routinely pinned at several versions in one tree, and checking only the first
 * one is how a compromised copy two levels down goes unnoticed.
 *
 * Ported from Safari Digital's node-packages-validator, which is where the
 * shapes below were worked out.
 */

import fs from 'node:fs';
import path from 'node:path';

export const NPM_LOCK_FILE = 'package-lock.json';
export const PNPM_LOCK_FILE = 'pnpm-lock.yaml';
export const MANIFEST_FILE = 'package.json';

/** The three names `indexFile` knows how to read, and `findIndexableFiles` looks for. */
export const INDEXABLE_FILES = [NPM_LOCK_FILE, PNPM_LOCK_FILE, MANIFEST_FILE];

const NODE_MODULES = 'node_modules/';
const IGNORED_DIRECTORIES = new Set(['node_modules', '.git']);

/**
 * Records one resolved package in an index, keeping every version seen.
 *
 * @param {Object} index Index to mutate
 * @param {string} name Package name
 * @param {string} version Exact version
 * @param {string} resolved Tarball URL, when the file records one
 * @returns {{ version: string, resolved: string } | null} The stored entry
 */
export function addEntry(index, name, version, resolved = '') {
    if (!name || !version) return null;

    const entries = (index[name] ??= []);
    const existing = entries.find(entry => entry.version === version);

    if (existing) {
        if (!existing.resolved && resolved) existing.resolved = resolved;
        return existing;
    }

    const entry = { version: String(version), resolved: resolved ?? '' };
    entries.push(entry);
    return entry;
}

/**
 * Package name behind an npm lockfile location.
 * `node_modules/a/node_modules/@scope/b` is `@scope/b`; the root project and
 * workspace sources hold no `node_modules/` segment and are not installed
 * packages at all.
 */
function nameFromLocation(location) {
    const index = location.lastIndexOf(NODE_MODULES);
    return index === -1 ? null : location.slice(index + NODE_MODULES.length);
}

/** @returns {Object} name → [{ version, resolved }] */
export function indexNpmLock(file) {
    const lock = JSON.parse(fs.readFileSync(file, 'utf8'));
    const index = {};

    for (const [location, data] of Object.entries(lock.packages ?? {})) {
        if (!data || data.link) continue;

        const installed = nameFromLocation(location);
        if (!installed) continue;

        // `name` is set when the folder differs from the package, i.e. aliases.
        addEntry(index, data.name ?? installed, data.version, data.resolved ?? '');
    }

    const scan = dependencies => {
        for (const [name, data] of Object.entries(dependencies ?? {})) {
            if (!data) continue;
            addEntry(index, name, data.version, data.resolved ?? '');
            if (data.dependencies) scan(data.dependencies);
        }
    };

    scan(lock.dependencies);
    return index;
}

/**
 * Name and version out of a pnpm `packages` key: `name@version(peers)` from
 * pnpm 6.1 onwards, `/name/version_peers` before that.
 */
export function parsePnpmKey(key) {
    // Tested first: a legacy key holds an `@` too, so the modern pattern would match it wrong.
    if (key.startsWith('/')) {
        const legacy = key.match(/^\/((?:@[^/]+\/)?[^/]+)\/([^_\s]+)(?:_.*)?$/);
        return legacy ? { name: legacy[1], version: legacy[2] } : null;
    }

    const modern = key.match(/^((?:@[^/]+\/)?[^@\s]+)@([^(\s]+)(?:\(.*\))?$/);
    return modern ? { name: modern[1], version: modern[2] } : null;
}

/**
 * A YAML reader tailored to one section of one file, rather than a YAML parser.
 * pnpm's `packages:` block is two levels deep and machine-written, and pulling a
 * dependency in to read a lockfile is exactly the kind of trade this tool exists
 * to avoid.
 *
 * @returns {Object} name → [{ version, resolved }]
 */
export function indexPnpmLock(file) {
    const content = fs.readFileSync(file, 'utf8');
    const index = {};

    let inPackages = false;
    let current = null;

    for (const line of content.split('\n')) {
        const topLevel = line.match(/^([a-zA-Z][\w-]*):/);
        if (topLevel) {
            // `snapshots:` repeats the same packages with their peers resolved;
            // ending here keeps one entry per package instead of one per peer set.
            inPackages = topLevel[1] === 'packages';
            current = null;
            continue;
        }

        if (!inPackages) continue;

        const entry = line.match(/^ {2}'?(.+?)'?:\s*$/);
        if (entry) {
            const parsed = parsePnpmKey(entry[1]);
            current = parsed ? addEntry(index, parsed.name, parsed.version) : null;
            continue;
        }

        if (current && /^ {4}resolution:/.test(line)) {
            const tarball = line.match(/tarball:\s*([^\s,}]+)/);
            if (tarball) current.resolved = tarball[1];
        }
    }

    return index;
}

/**
 * Declared dependencies of a package.json.
 *
 * These are ranges, so the leading operators are stripped to leave something an
 * exact-version comparison can be run against. That guess is deliberately only
 * trusted by `secure-npm validate`, which reports; the install guards treat a
 * manifest as names alone, because `>=1.0.0` reduced to `1.0.0` would otherwise
 * refuse an install over a version that was never going to be resolved.
 *
 * @returns {Object} name → [{ version, resolved }]
 */
export function indexManifest(file) {
    const manifest = JSON.parse(fs.readFileSync(file, 'utf8'));
    const index = {};

    const groups = [
        manifest.dependencies,
        manifest.devDependencies,
        manifest.optionalDependencies,
        manifest.peerDependencies,
    ];

    for (const group of groups) {
        if (!group) continue;
        for (const [name, range] of Object.entries(group)) {
            addEntry(
                index,
                name,
                String(range)
                    .replace(/^[\s^~>=<]+/, '')
                    .trim()
            );
        }
    }

    return index;
}

/** Picks the parser from the file name. Unknown names index to nothing. */
export function indexFile(file) {
    switch (path.basename(file)) {
        case NPM_LOCK_FILE:
            return indexNpmLock(file);
        case PNPM_LOCK_FILE:
            return indexPnpmLock(file);
        case MANIFEST_FILE:
            return indexManifest(file);
        default:
            return {};
    }
}

/** Nearest ancestor holding a `.git` entry, or `startDir` when there is none. */
export function findRepositoryRoot(startDir = process.cwd()) {
    let directory = path.resolve(startDir);

    for (;;) {
        if (fs.existsSync(path.join(directory, '.git'))) return directory;
        const parent = path.dirname(directory);
        if (parent === directory) return path.resolve(startDir);
        directory = parent;
    }
}

/**
 * Every manifest and lockfile under a directory. `node_modules`, `.git` and
 * hidden directories are skipped: the first is the installed tree rather than a
 * declaration of it, and the other two hold nothing anyone authored.
 *
 * @returns {string[]} File paths, in walk order
 */
export function findIndexableFiles(directory) {
    const found = [];

    const walk = dir => {
        for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
            const fullPath = path.join(dir, entry.name);

            if (entry.isDirectory()) {
                if (IGNORED_DIRECTORIES.has(entry.name) || entry.name.startsWith('.')) continue;
                walk(fullPath);
            } else if (entry.isFile() && INDEXABLE_FILES.includes(entry.name)) {
                found.push(fullPath);
            }
        }
    };

    walk(directory);
    return found;
}
