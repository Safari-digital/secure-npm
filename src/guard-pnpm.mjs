/**
 * The pnpm lockfile, read before pnpm starts.
 *
 * The resolution hook sees every package pnpm resolves — but a `pnpm install`
 * whose lockfile is already up to date resolves nothing at all: pnpm goes
 * headless, reads the lockfile and links straight out of the store. The hook is
 * never called, and neither is anything that depends on it. That is the common
 * case in CI and on a fresh clone, which is to say the case that matters.
 *
 * So the lockfile is checked directly, and the two passes cover each other:
 * the lockfile is what a headless install is about to link, and the hook is what
 * catches everything a resolving install adds to it afterwards.
 *
 * Only name-based rules are applied here. pnpm records an integrity hash rather
 * than a registry URL for ordinary packages, so `resolved` is empty for all but
 * tarball and git dependencies — judging a source by its absence would refuse
 * the entire tree.
 */

import fs from 'node:fs';
import path from 'node:path';
import { blockedPackageReason } from './rules.mjs';
import { compromisedReason } from './compromised.mjs';
import { PNPM_LOCK_FILE, indexPnpmLock } from './lockfile.mjs';

/**
 * The lockfile that governs `cwd`.
 *
 * pnpm keeps one lockfile per workspace, at its root, so a command run inside a
 * package resolves against a file that is not in the current directory. The
 * walk stops at the repository boundary: above it, a lockfile belongs to
 * something else entirely.
 */
export function findPnpmLockfile(cwd) {
    let directory = path.resolve(cwd);

    for (;;) {
        const candidate = path.join(directory, PNPM_LOCK_FILE);
        if (fs.existsSync(candidate)) return candidate;
        if (fs.existsSync(path.join(directory, '.git'))) return null;

        const parent = path.dirname(directory);
        if (parent === directory) return null;
        directory = parent;
    }
}

/**
 * @param {Object|null} compromised The malicious-package list, or null when the
 *   policy configures none.
 * @returns {{ violations: {rule: string, subject: string, reason: string, hint?: string}[], count: number }}
 *   `count` is how many pinned packages were read, which is what the wrapper
 *   reports back: "nothing was refused" and "nothing was looked at" have to be
 *   distinguishable.
 */
export function inspectPnpmLockfile(policy, cwd, compromised = null) {
    const lockFile = findPnpmLockfile(cwd);
    if (!lockFile) return { violations: [], count: 0 };

    let index;
    try {
        index = indexPnpmLock(lockFile);
    } catch (error) {
        return {
            violations: [{ rule: 'unreadable-lockfile', subject: lockFile, reason: error.message }],
            count: 0,
        };
    }

    const violations = [];
    let count = 0;

    for (const [name, entries] of Object.entries(index)) {
        count += entries.length;

        const blocked = blockedPackageReason(policy, name);
        if (blocked) {
            violations.push({
                rule: 'blocked-package',
                subject: `${name} — ${PNPM_LOCK_FILE}`,
                reason: blocked,
                hint: 'the lockfile already pins it; remove it there as well as from package.json',
            });
            continue;
        }

        for (const { version, resolved } of entries) {
            const malicious = compromisedReason(compromised, name, version, resolved);
            if (malicious) {
                violations.push({
                    rule: 'compromised-package',
                    subject: `${name}@${version} — ${PNPM_LOCK_FILE}`,
                    reason: malicious,
                    hint: 'this package is on the malicious-package list — remove it, do not pin around it',
                });
            }
        }
    }

    return { violations, count };
}
