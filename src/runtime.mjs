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
import { runtimeRoot, runtimeStampFile } from './paths.mjs';

/**
 * What a working runtime needs. `install.mjs` and `uninstall.mjs` stay behind
 * on purpose — they operate on the source tree and are run from it.
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
        return JSON.parse(fs.readFileSync(runtimeStampFile, 'utf8'));
    } catch {
        return null;
    }
}

/**
 * Replaces the deployed runtime with a copy of `sourceRoot`.
 *
 * Removed first rather than copied over: a file dropped from a later version
 * would otherwise linger for good, and a stale `src/` module is indistinguishable
 * from a current one once it is sitting in the tree.
 */
export function deployRuntime(sourceRoot) {
    for (const entry of DEPLOYED) {
        const from = path.join(sourceRoot, entry);
        if (!fs.existsSync(from)) throw new Error(`cannot deploy the runtime: ${from} is missing`);
    }

    fs.rmSync(runtimeRoot, { recursive: true, force: true });
    fs.mkdirSync(runtimeRoot, { recursive: true });

    for (const entry of DEPLOYED) {
        fs.cpSync(path.join(sourceRoot, entry), path.join(runtimeRoot, entry), { recursive: true });
    }

    const { version } = JSON.parse(fs.readFileSync(path.join(sourceRoot, 'package.json'), 'utf8'));
    const stamp = {
        source: sourceRoot,
        version,
        deployedAt: new Date().toISOString(),
        fingerprint: fingerprint(runtimeRoot),
    };

    fs.writeFileSync(runtimeStampFile, `${JSON.stringify(stamp, null, 4)}\n`);
    return stamp;
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
    if (!fs.existsSync(runtimeStampFile)) {
        return { state: fs.existsSync(runtimeRoot) ? 'unstamped' : 'missing' };
    }

    const stamp = readStamp();
    if (!stamp?.source) return { state: 'unstamped' };
    if (!fs.existsSync(path.join(stamp.source, 'package.json'))) return { state: 'source-gone', stamp };

    return { state: fingerprint(stamp.source) === fingerprint(runtimeRoot) ? 'current' : 'stale', stamp };
}
