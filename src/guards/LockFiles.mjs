import fs from 'node:fs';
import path from 'node:path';

/** @typedef {Object<string, { version: string, resolved: string }[]>} PackageIndex **/

export default class LockFiles {
    static NPM_LOCK_FILE = 'package-lock.json';
    static PNPM_LOCK_FILE = 'pnpm-lock.yaml';
    static MANIFEST_FILE = 'package.json';
    static INDEXABLE_FILES = [this.NPM_LOCK_FILE, this.PNPM_LOCK_FILE, this.MANIFEST_FILE];

    static #NODE_MODULES = 'node_modules/';
    static #IGNORED_DIRECTORIES = new Set(['node_modules', '.git']);

    /**
     * @param {PackageIndex} index
     * @returns {{ version: string, resolved: string } | null} The stored entry.
     */
    static addEntry(index, name, version, resolved = '') {
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

    /** `node_modules/a/node_modules/@scope/b` → `@scope/b`; no segment → not an installed package. **/
    static #nameFromLocation(location) {
        const index = location.lastIndexOf(this.#NODE_MODULES);
        return index === -1 ? null : location.slice(index + this.#NODE_MODULES.length);
    }

    /** @returns {PackageIndex} **/
    static indexNpmLock(file) {
        const lock = JSON.parse(fs.readFileSync(file, 'utf8'));
        const index = {};

        for (const [location, data] of Object.entries(lock.packages ?? {})) {
            if (!data || data.link) continue;

            const installed = this.#nameFromLocation(location);
            if (!installed) continue;

            // `name` is set when the folder differs from the package, i.e. aliases.
            this.addEntry(index, data.name ?? installed, data.version, data.resolved ?? '');
        }

        const scan = dependencies => {
            for (const [name, data] of Object.entries(dependencies ?? {})) {
                if (!data) continue;
                this.addEntry(index, name, data.version, data.resolved ?? '');
                if (data.dependencies) scan(data.dependencies);
            }
        };

        scan(lock.dependencies);
        return index;
    }

    /** `name@version(peers)` from pnpm 6.1 onwards, `/name/version_peers` before. **/
    static parsePnpmKey(key) {
        // Legacy first: a legacy key holds an `@` too, and the modern pattern would match it wrong.
        if (key.startsWith('/')) {
            const legacy = key.match(/^\/((?:@[^/]+\/)?[^/]+)\/([^_\s]+)(?:_.*)?$/);
            return legacy ? { name: legacy[1], version: legacy[2] } : null;
        }

        const modern = key.match(/^((?:@[^/]+\/)?[^@\s]+)@([^(\s]+)(?:\(.*\))?$/);
        return modern ? { name: modern[1], version: modern[2] } : null;
    }

    /**
     * A reader tailored to pnpm's machine-written `packages:` block, rather
     * than a YAML dependency - which is the kind of trade this tool refuses.
     *
     * @returns {PackageIndex}
     */
    static indexPnpmLock(file) {
        const content = fs.readFileSync(file, 'utf8');
        const index = {};

        let inPackages = false;
        let current = null;

        for (const line of content.split('\n')) {
            const topLevel = line.match(/^([a-zA-Z][\w-]*):/);
            if (topLevel) {
                // `snapshots:` repeats the same packages once per peer set.
                inPackages = topLevel[1] === 'packages';
                current = null;
                continue;
            }

            if (!inPackages) continue;

            const entry = line.match(/^ {2}'?(.+?)'?:\s*$/);
            if (entry) {
                const parsed = this.parsePnpmKey(entry[1]);
                current = parsed ? this.addEntry(index, parsed.name, parsed.version) : null;
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
     * Declared ranges with their operators stripped. Only `secure-npm validate`
     * trusts that guess - the install guards treat a manifest as names alone.
     *
     * @returns {PackageIndex}
     */
    static indexManifest(file) {
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
                this.addEntry(
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

    /** Picks the parser from the file name. Unknown names index to nothing. **/
    static indexFile(file) {
        switch (path.basename(file)) {
            case this.NPM_LOCK_FILE:
                return this.indexNpmLock(file);
            case this.PNPM_LOCK_FILE:
                return this.indexPnpmLock(file);
            case this.MANIFEST_FILE:
                return this.indexManifest(file);
            default:
                return {};
        }
    }

    /** Nearest ancestor holding a `.git` entry, or `startDir` when there is none. **/
    static findRepositoryRoot(startDir = process.cwd()) {
        let directory = path.resolve(startDir);

        for (;;) {
            if (fs.existsSync(path.join(directory, '.git'))) return directory;
            const parent = path.dirname(directory);
            if (parent === directory) return path.resolve(startDir);
            directory = parent;
        }
    }

    /**
     * Every manifest and lockfile under a directory, skipping node_modules,
     * .git and hidden directories.
     *
     * @returns {string[]}
     */
    static findIndexableFiles(directory) {
        const found = [];

        const walk = dir => {
            for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
                const fullPath = path.join(dir, entry.name);

                if (entry.isDirectory()) {
                    if (this.#IGNORED_DIRECTORIES.has(entry.name) || entry.name.startsWith('.')) continue;
                    walk(fullPath);
                } else if (entry.isFile() && this.INDEXABLE_FILES.includes(entry.name)) {
                    found.push(fullPath);
                }
            }
        };

        walk(directory);
        return found;
    }
}
