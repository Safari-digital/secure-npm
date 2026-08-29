/**
 * pnpm resolution hook - wired up by `globalPnpmfile` in pnpm's global config.
 *
 * pnpm calls `readPackage` on every manifest it resolves, before anything is
 * downloaded, so throwing here aborts the install. It runs inside pnpm's own
 * process, whether pnpm was started through the shim or called directly, which
 * makes it the backstop for both. The list is loaded on the first package
 * rather than at import time: pnpm loads this file for commands that resolve
 * nothing at all.
 *
 * `afterAllResolved` enforces no policy - it undoes a side effect of this very
 * file. See guards/PnpmChecksum.mjs.
 */

import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import Logger from '../src/logs/Logger.mjs';
import Policy from '../src/policy/Policy.mjs';
import Rules from '../src/policy/Rules.mjs';
import Compromised from '../src/compromised/Compromised.mjs';
import PnpmChecksum from '../src/guards/PnpmChecksum.mjs';
import { LOCAL_POLICY_FILE, POLICY_FILE } from '../src/paths.mjs';

const policy = Policy.load();

// The wrapper sets this and prints its own banner; absent, pnpm was started
// outside the shim and this is the only chance to say what is enforced.
if (!process.env.SECURE_NPM_POLICY) {
    Logger.banner({
        command: 'pnpm (called directly)',
        policyFiles: fs.existsSync(LOCAL_POLICY_FILE) ? [POLICY_FILE, LOCAL_POLICY_FILE] : [POLICY_FILE],
        hookFile: fileURLToPath(import.meta.url),
    });
}

function refuse({ rule, subject, reason, hint, origin }) {
    Logger.reportBlock({ rule, subject, reason, hint });
    Logger.audit({
        event: 'block',
        phase: 'pnpm-hook',
        command: 'pnpm (resolution hook)',
        rule,
        subject,
        reason,
        origin,
        cwd: process.cwd(),
    });

    const error = new Error(`[secure-npm/${rule}] ${subject} - ${reason}`);
    error.code = rule;
    throw error;
}

async function readPackage(pkg) {
    const origin = pkg.name ? `${pkg.name}@${pkg.version ?? '?'}` : 'the local project';

    const list = await Compromised.load(policy);
    const unavailable = Compromised.listViolation(list);
    if (unavailable) refuse({ ...unavailable, origin });

    // The only place a sub-dependency's exact version is ever seen: the
    // wrapper's lockfile pass reads what is pinned, this reads what is about to be.
    const selfMalicious = Compromised.reason(list.index, pkg.name, pkg.version);
    if (selfMalicious) {
        refuse({
            rule: 'compromised-package',
            subject: origin,
            reason: selfMalicious,
            hint: 'this package is on the malicious-package list - remove it, do not pin around it',
            origin,
        });
    }

    // Catches the package itself whatever field pulled it in, including
    // devDependencies of the local project, which is what `pnpm add -D` writes.
    const selfReason = pkg.name && Rules.blockedPackageReason(policy, pkg.name);
    if (selfReason) {
        refuse({ rule: 'blocked-package', subject: pkg.name, reason: selfReason, origin });
    }

    // Only the fields pnpm installs for a third-party manifest - its
    // devDependencies are never fetched, and rejecting them would break installs.
    for (const field of Rules.INSTALLED_FIELDS) {
        for (const [key, specifier] of Object.entries(pkg[field] ?? {})) {
            const name = Rules.resolveName(key, specifier);
            const alias = name === key ? '' : ` (aliased as "${key}")`;

            // By name only - a dependency declares a range; the exact version
            // is checked above once pnpm resolves it.
            const malicious = Compromised.reason(list.index, name);
            if (malicious) {
                refuse({
                    rule: 'compromised-package',
                    subject: `${name}${alias}, required by ${origin} ▸ ${field}`,
                    reason: malicious,
                    hint: 'this package is on the malicious-package list - remove it, do not pin around it',
                    origin,
                });
            }

            const reason = Rules.blockedPackageReason(policy, name);
            if (reason) {
                refuse({
                    rule: 'blocked-package',
                    subject: `${name}${alias}, required by ${origin} ▸ ${field}`,
                    reason,
                    origin,
                });
            }

            // With the whitelist in use this is the only enforcement point left
            // for sub-dependencies: pnpm's blockExoticSubdeps is a boolean.
            if (Rules.isExoticSpecifier(specifier)) {
                const { allowed, identity } = Rules.exoticSourceVerdict(policy, specifier);
                if (!allowed) {
                    refuse({
                        rule: 'exotic-source',
                        subject: `"${key}": "${specifier}", required by ${origin} ▸ ${field}`,
                        reason: 'git and tarball sources carry no publish date and no provenance attestation',
                        hint: Rules.exoticSourceHint(identity),
                        origin,
                    });
                }
            }
        }
    }

    return pkg;
}

/**
 * Takes the wrapper's own footprint back out of the lockfile pnpm is about to
 * write. Never refuses: a checksum left in place is a nuisance, not a danger.
 */
function afterAllResolved(lockfile) {
    try {
        if (PnpmChecksum.dropPhantom(lockfile)) {
            Logger.audit({
                event: 'fix',
                phase: 'pnpm-hook',
                rule: 'phantom-pnpmfile-checksum',
                command: 'pnpm (resolution hook)',
                reason: 'dropped the empty pnpmfileChecksum pnpm stamps for a global-only hook',
                cwd: process.cwd(),
            });
        }
    } catch {
        // Not worth failing an install over.
    }

    return lockfile;
}

export const hooks = { readPackage, afterAllResolved };
