/**
 * pnpm resolution hook — wired up by `globalPnpmfile` in pnpm's global config.
 *
 * pnpm calls `readPackage` on every manifest it resolves, before anything is
 * downloaded, so throwing here aborts the install. This covers the one rule
 * pnpm has no setting for: rejecting a package by name, at any depth.
 *
 * It runs inside pnpm's own process, whether pnpm was started through the
 * shim or called directly, which makes it the backstop for both.
 */

import { audit, banner, reportBlock } from '../src/logger.mjs';
import { loadPolicy } from '../src/policy.mjs';
import { localPolicyFile, policyFile } from '../src/paths.mjs';
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
    banner({
        command: 'pnpm (called directly)',
        policyFiles: fs.existsSync(localPolicyFile) ? [policyFile, localPolicyFile] : [policyFile],
        hookFile: fileURLToPath(import.meta.url),
    });
}

function refuse({ rule, subject, reason, hint, origin }) {
    reportBlock({ rule, subject, reason, hint });
    audit({
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

function readPackage(pkg) {
    const origin = pkg.name ? `${pkg.name}@${pkg.version ?? '?'}` : 'the local project';

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

            const reason = blockedPackageReason(policy, name);
            if (reason) {
                const alias = name === key ? '' : ` (aliased as "${key}")`;
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

export const hooks = { readPackage };
