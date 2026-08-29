/**
 * pnpm resolution hook — wired up by `globalPnpmfile` in pnpm's global config.
 *
 * pnpm calls `readPackage` on every manifest it resolves, before anything is
 * downloaded, so throwing here aborts the install. This covers the two rules
 * pnpm has no setting for: rejecting a package by name, and rejecting a release
 * that is known to be malicious — both at any depth.
 *
 * It runs inside pnpm's own process, whether pnpm was started through the
 * shim or called directly, which makes it the backstop for both. pnpm awaits
 * the hook, so the malicious-package list can be fetched from here; it is
 * loaded on the first package rather than at import time, because pnpm loads
 * this file for commands that resolve nothing at all.
 *
 * `afterAllResolved` enforces no policy. It undoes a side effect of this very
 * file: pnpm stamps a `pnpmfileChecksum` into the lockfile because a pnpmfile
 * exports hooks, and with only a global one the value hashes no file at all.
 * Being loaded by every pnpm there is — including the ones the wrapper never
 * sees — this is where that stamp can be taken back off. See pnpm-checksum.mjs.
 */

import Logger from '../src/logs/Logger.mjs';
import { loadPolicy } from '../src/policy.mjs';
import { LOCAL_POLICY_FILE, POLICY_FILE } from '../src/paths.mjs';
import { compromisedListViolation, compromisedReason, loadCompromisedList } from '../src/compromised.mjs';
import { dropPhantomPnpmfileChecksum } from '../src/pnpm-checksum.mjs';
import {
    INSTALLED_FIELDS,
    blockedPackageReason,
    exoticSourceHint,
    exoticSourceVerdict,
    isExoticSpecifier,
    resolveName,
} from '../src/rules.mjs';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const policy = loadPolicy();

// The wrapper sets this and prints its own banner. When it is absent, pnpm was
// started outside the shim and this is the only chance to say what is enforced.
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

    const error = new Error(`[secure-npm/${rule}] ${subject} — ${reason}`);
    error.code = rule;
    throw error;
}

async function readPackage(pkg) {
    const origin = pkg.name ? `${pkg.name}@${pkg.version ?? '?'}` : 'the local project';

    const list = await loadCompromisedList(policy);
    const unavailable = compromisedListViolation(list);
    if (unavailable) refuse({ ...unavailable, origin });

    // The only place a sub-dependency's exact version is ever seen: the lockfile
    // check in the wrapper reads what is already pinned, this reads what is
    // about to be.
    const selfMalicious = compromisedReason(list.index, pkg.name, pkg.version);
    if (selfMalicious) {
        refuse({
            rule: 'compromised-package',
            subject: origin,
            reason: selfMalicious,
            hint: 'this package is on the malicious-package list — remove it, do not pin around it',
            origin,
        });
    }

    // Catches the package itself whatever field pulled it in, including
    // devDependencies of the local project, which is what `pnpm add -D` writes.
    const selfReason = pkg.name && blockedPackageReason(policy, pkg.name);
    if (selfReason) {
        refuse({ rule: 'blocked-package', subject: pkg.name, reason: selfReason, origin });
    }

    // Only the fields pnpm actually installs for a third-party manifest.
    // Its devDependencies are never fetched, and rejecting them would break
    // installs over dependencies that are not downloaded at all.
    for (const field of INSTALLED_FIELDS) {
        for (const [key, specifier] of Object.entries(pkg[field] ?? {})) {
            const name = resolveName(key, specifier);
            const alias = name === key ? '' : ` (aliased as "${key}")`;

            // By name only — a dependency declares a range, not a version. The
            // exact one is checked above, once pnpm resolves it. Refusing here
            // as well is what names the package that asked for it.
            const malicious = compromisedReason(list.index, name);
            if (malicious) {
                refuse({
                    rule: 'compromised-package',
                    subject: `${name}${alias}, required by ${origin} ▸ ${field}`,
                    reason: malicious,
                    hint: 'this package is on the malicious-package list — remove it, do not pin around it',
                    origin,
                });
            }

            const reason = blockedPackageReason(policy, name);
            if (reason) {
                refuse({
                    rule: 'blocked-package',
                    subject: `${name}${alias}, required by ${origin} ▸ ${field}`,
                    reason,
                    origin,
                });
            }

            // When the whitelist is in use this is the only enforcement point
            // left for sub-dependencies: pnpm's own blockExoticSubdeps is a
            // boolean and cannot tell an allowed repository from the rest, so
            // the installer hands the decision here.
            if (isExoticSpecifier(specifier)) {
                const { allowed, identity } = exoticSourceVerdict(policy, specifier);
                if (!allowed) {
                    refuse({
                        rule: 'exotic-source',
                        subject: `"${key}": "${specifier}", required by ${origin} ▸ ${field}`,
                        reason: 'git and tarball sources carry no publish date and no provenance attestation',
                        hint: exoticSourceHint(identity),
                        origin,
                    });
                }
            }
        }
    }

    return pkg;
}

/**
 * The last thing pnpm hands over before writing the lockfile. Nothing here
 * judges anything: it takes the wrapper's own footprint back out of a file the
 * repository has committed, so an install run here leaves the lockfile exactly
 * as an install run without secure-npm would.
 *
 * A throw would abort the install, and a checksum left in place is a nuisance
 * and not a danger — so this never refuses, whatever it is given.
 */
function afterAllResolved(lockfile) {
    try {
        if (dropPhantomPnpmfileChecksum(lockfile)) {
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
        // Nothing to do about it, and not worth failing an install over.
    }

    return lockfile;
}

export const hooks = { readPackage, afterAllResolved };
