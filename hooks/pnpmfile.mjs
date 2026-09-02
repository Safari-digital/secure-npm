import fs from 'node:fs';
import { fileURLToPath } from 'node:url';
import Logger from '../src/logs/Logger.mjs';
import Policy from '../src/policy/Policy.mjs';
import Rules from '../src/policy/Rules.mjs';
import Compromised from '../src/compromised/Compromised.mjs';
import PnpmChecksum from '../src/guards/PnpmChecksum.mjs';
import { LOCAL_POLICY_FILE, POLICY_FILE } from '../src/paths.mjs';

const policy = Policy.load();

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

    const selfReason = pkg.name && Rules.dependencyBlockReason(policy, pkg.name, pkg.version);
    if (selfReason) {
        refuse({
            rule: 'blocked-package',
            subject: origin,
            reason: selfReason,
            hint: Rules.blockedPackageHint(pkg.name, pkg.version ?? null),
            origin,
        });
    }

    for (const field of Rules.INSTALLED_FIELDS) {
        for (const [key, specifier] of Object.entries(pkg[field] ?? {})) {
            const name = Rules.resolveName(key, specifier);
            const alias = name === key ? '' : ` (aliased as "${key}")`;

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

            const reason = Rules.dependencyBlockReason(policy, name);
            if (reason) {
                refuse({
                    rule: 'blocked-package',
                    subject: `${name}${alias}, required by ${origin} ▸ ${field}`,
                    reason,
                    hint: Rules.blockedPackageHint(name),
                    origin,
                });
            }

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
