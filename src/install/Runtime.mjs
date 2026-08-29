import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { APP_RUNTIME_DIR, APP_RUNTIME_STAMP_FILE } from '../paths.mjs';

/**
 * The deployed copy of the runtime: what the shims start and what pnpm loads.
 * Deployed by the Installer, compared to its source by `doctor` - a stale copy
 * silently enforcing last month's rules is the failure this exists to catch.
 */
export default class Runtime {
    /** What a working runtime needs; `installer.mjs` stays behind on purpose. **/
    static DEPLOYED = ['bin', 'src', 'hooks', 'policy.json', 'package.json'];

    /** Files under `entries`, as { absolute, relative }, in a stable order. **/
    static #filesUnder(root, entries) {
        const found = [];

        const visit = (absolute, relative) => {
            const stat = fs.statSync(absolute);
            if (stat.isDirectory()) {
                for (const name of fs.readdirSync(absolute)) visit(path.join(absolute, name), `${relative}/${name}`);
            } else if (stat.isFile()) {
                found.push({ absolute, relative });
            }
        };

        for (const entry of entries) {
            const absolute = path.join(root, entry);
            if (fs.existsSync(absolute)) visit(absolute, entry);
        }

        return found.sort((a, b) => (a.relative < b.relative ? -1 : 1));
    }

    /** Content hash of the deployable files; names are digested too, so a rename changes it. **/
    static fingerprint(root) {
        const hash = createHash('sha256');

        for (const { absolute, relative } of this.#filesUnder(root, this.DEPLOYED)) {
            hash.update(`${relative}\0`);
            hash.update(fs.readFileSync(absolute));
            hash.update('\0');
        }

        return hash.digest('hex');
    }

    static readStamp() {
        try {
            return JSON.parse(fs.readFileSync(APP_RUNTIME_STAMP_FILE, 'utf8'));
        } catch {
            return null;
        }
    }

    /**
     * Is what is deployed still what the source says it should be? Compared by
     * content rather than by trusting the stamp, which also catches a deployed
     * copy edited in place. `source-gone` is a note, not a problem: the runtime
     * is self-contained.
     *
     * @returns {{ state: 'missing' | 'unstamped' | 'source-gone' | 'stale' | 'current', stamp?: Object }}
     */
    static status() {
        if (!fs.existsSync(APP_RUNTIME_STAMP_FILE)) {
            return { state: fs.existsSync(APP_RUNTIME_DIR) ? 'unstamped' : 'missing' };
        }

        const stamp = this.readStamp();
        if (!stamp?.source) return { state: 'unstamped' };
        if (!fs.existsSync(path.join(stamp.source, 'package.json'))) return { state: 'source-gone', stamp };

        return { state: this.fingerprint(stamp.source) === this.fingerprint(APP_RUNTIME_DIR) ? 'current' : 'stale', stamp };
    }
}
