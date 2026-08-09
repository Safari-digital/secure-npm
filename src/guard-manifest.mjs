/**
 * The project's own package.json.
 *
 * `npm install` with no arguments installs whatever is already written there,
 * so the command line being clean says nothing. Every dependency field is
 * inspected here, devDependencies included: this manifest is authored locally,
 * unlike a third-party one whose devDependencies are never installed.
 */

import fs from 'node:fs';
import path from 'node:path';
import {
    blockedPackageReason,
    exoticSourceHint,
    exoticSourceVerdict,
    gitSourceIdentity,
    isExoticSpecifier,
    resolveName,
} from './rules.mjs';
import { compromisedReason } from './compromised.mjs';

const FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies'];

function readManifest(cwd) {
    const manifestFile = path.join(cwd, 'package.json');
    if (!fs.existsSync(manifestFile)) return { manifestFile, manifest: null, error: null };

    try {
        return { manifestFile, manifest: JSON.parse(fs.readFileSync(manifestFile, 'utf8')), error: null };
    } catch (error) {
        return { manifestFile, manifest: null, error };
    }
}

/**
 * Dependency keys whose specifier resolves from git.
 *
 * npm installs those under the key, not under the repository's own package
 * name, and reports them that way in its dry-run output — so the key is
 * exactly what the release-age check has to skip. See `inspectPackages`.
 */
export function gitSourcedManifestNames(cwd) {
    const { manifest } = readManifest(cwd);
    const names = new Set();
    if (!manifest) return names;

    for (const field of FIELDS) {
        for (const [key, specifier] of Object.entries(manifest[field] ?? {})) {
            if (gitSourceIdentity(specifier) !== null) names.add(key);
        }
    }

    return names;
}

/**
 * @param {Object|null} compromised The malicious-package list. Checked by name
 *   alone here: a manifest declares ranges, and only an entry covering every
 *   published version of a package says anything certain about a range. The
 *   exact versions get checked once they have been resolved.
 */
export function inspectManifest(policy, cwd, compromised = null) {
    const { manifestFile, manifest, error } = readManifest(cwd);
    if (error) {
        return [
            {
                rule: 'unreadable-manifest',
                subject: manifestFile,
                reason: `package.json could not be parsed: ${error.message}`,
            },
        ];
    }
    if (!manifest) return [];

    const violations = [];

    for (const field of FIELDS) {
        for (const [key, specifier] of Object.entries(manifest[field] ?? {})) {
            const name = resolveName(key, specifier);
            const alias = name === key ? '' : ` (aliased as "${key}")`;

            const malicious = compromisedReason(compromised, name);
            if (malicious) {
                violations.push({
                    rule: 'compromised-package',
                    subject: `${name}${alias} — package.json ▸ ${field}`,
                    reason: malicious,
                    hint: 'this package is on the malicious-package list — remove it from package.json',
                });
                continue;
            }

            const reason = blockedPackageReason(policy, name);
            if (reason) {
                violations.push({
                    rule: 'blocked-package',
                    subject: `${name}${alias} — package.json ▸ ${field}`,
                    reason,
                });
                continue;
            }

            if (isExoticSpecifier(specifier)) {
                const { allowed, identity } = exoticSourceVerdict(policy, specifier);
                if (!allowed) {
                    violations.push({
                        rule: 'exotic-source',
                        subject: `"${key}": "${specifier}" — package.json ▸ ${field}`,
                        reason: 'git and tarball sources carry no publish date and no provenance',
                        hint: exoticSourceHint(identity),
                    });
                }
            }
        }
    }

    return violations;
}
