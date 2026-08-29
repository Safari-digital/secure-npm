/**
 * Deploying the runtime out of the repository.
 *
 * The clone is the source; the copy under `runtimeRoot` is what the shims start
 * and what pnpm loads as its global hook. Keeping those two apart is the whole
 * point: a machine that has been installed keeps enforcing the policy whether or
 * not the clone is still on disk, still on that path, or halfway through a
 * rebase.
 *
 * The cost is that `git pull` no longer changes anything by itself, and a stale
 * copy silently enforcing last month's rules is exactly the failure this tool
 * exists to prevent. Hence the stamp: it records what was deployed and from
 * where, so `doctor` can compare the two trees and say so out loud.
 */

import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { APP_RUNTIME_DIR, APP_RUNTIME_STAMP_FILE } from './paths.mjs';

/**
 * What a working runtime needs. `installer.mjs` stays behind on purpose — it
 * operates on the source tree and is run from it.
 */
export const DEPLOYED = ['bin', 'src', 'hooks', 'policy.json', 'package.json'];

/** Files under `entries`, as `{ absolute, relative }`, in a stable order. */
function filesUnder(root, entries) {
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

    // Sorted here rather than per directory: one comparison, and the result no
    // longer depends on the order the filesystem happens to hand back.
    return found.sort((a, b) => (a.relative < b.relative ? -1 : 1));
}

/**
 * Content hash of the deployable files under `root`. Names go into the digest
 * alongside the bytes, so a renamed or deleted file changes it too.
 */
export function fingerprint(root) {
    const hash = createHash('sha256');

    for (const { absolute, relative } of filesUnder(root, DEPLOYED)) {
        hash.update(`${relative}\0`);
        hash.update(fs.readFileSync(absolute));
        hash.update('\0');
    }

    return hash.digest('hex');
}

export function readStamp() {
    try {
        return JSON.parse(fs.readFileSync(APP_RUNTIME_STAMP_FILE, 'utf8'));
    } catch {
        return null;
    }
}

/**
 * Is what is deployed still what the source says it should be?
 *
 * `source-gone` is a note rather than a problem: the runtime is self-contained,
 * so a clone that has been moved or deleted costs nothing but the ability to
 * check for updates. Comparing the two trees by content, rather than trusting
 * the stamp, also catches a deployed copy that was edited in place.
 *
 * @returns {{ state: 'missing' | 'unstamped' | 'source-gone' | 'stale' | 'current', stamp?: object }}
 */
export function runtimeStatus() {
    if (!fs.existsSync(APP_RUNTIME_STAMP_FILE)) {
        return { state: fs.existsSync(APP_RUNTIME_DIR) ? 'unstamped' : 'missing' };
    }

    const stamp = readStamp();
    if (!stamp?.source) return { state: 'unstamped' };
    if (!fs.existsSync(path.join(stamp.source, 'package.json'))) return { state: 'source-gone', stamp };

    return { state: fingerprint(stamp.source) === fingerprint(APP_RUNTIME_DIR) ? 'current' : 'stale', stamp };
}
