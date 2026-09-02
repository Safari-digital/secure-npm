import fs from 'node:fs';
import path from 'node:path';
import Rules from '../policy/Rules.mjs';
import Compromised from '../compromised/Compromised.mjs';
import LockFiles from './LockFiles.mjs';

/**
 * The pnpm lockfile, read before pnpm starts: an install whose lockfile is up
 * to date goes headless and never calls the resolution hook, so the two passes
 * cover each other. Name-based rules only - pnpm records an integrity hash
 * rather than a URL for ordinary packages.
 */
export default class PnpmGuard {
    /**
     * The lockfile that governs `cwd` - pnpm keeps one per workspace, at its
     * root. The walk stops at the repository boundary.
     *
     * @returns {string | null}
     */
    static findLockfile(cwd) {
        let directory = path.resolve(cwd);

        for (;;) {
            const candidate = path.join(directory, LockFiles.PNPM_LOCK_FILE);
            if (fs.existsSync(candidate)) return candidate;
            if (fs.existsSync(path.join(directory, '.git'))) return null;

            const parent = path.dirname(directory);
            if (parent === directory) return null;
            directory = parent;
        }
    }

    /**
     * @param {Object | null} compromised
     * @returns {{ violations: import('../system/System.mjs').Violation[], count: number }}
     *   `count` distinguishes "nothing was refused" from "nothing was looked at".
     */
    static inspectLockfile(policy, cwd, compromised = null) {
        const lockFile = this.findLockfile(cwd);
        if (!lockFile) return { violations: [], count: 0 };

        let index;
        try {
            index = LockFiles.indexPnpmLock(lockFile);
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

            for (const { version, resolved } of entries) {
                const blocked = Rules.dependencyBlockReason(policy, name, version);
                if (blocked) {
                    violations.push({
                        rule: 'blocked-package',
                        subject: `${name}@${version} - ${LockFiles.PNPM_LOCK_FILE}`,
                        reason: blocked,
                        hint: `the lockfile already pins it; remove it there as well as from package.json, or ${Rules.blockedPackageHint(name, version)}`,
                    });
                    continue;
                }

                const malicious = Compromised.reason(compromised, name, version, resolved);
                if (malicious) {
                    violations.push({
                        rule: 'compromised-package',
                        subject: `${name}@${version} - ${LockFiles.PNPM_LOCK_FILE}`,
                        reason: malicious,
                        hint: 'this package is on the malicious-package list - remove it, do not pin around it',
                    });
                }
            }
        }

        return { violations, count };
    }
}
