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
import { blockedPackageReason, isExoticSpecifier, resolveName } from './rules.mjs';

const FIELDS = ['dependencies', 'devDependencies', 'optionalDependencies'];

export function inspectManifest(policy, cwd) {
    const manifestFile = path.join(cwd, 'package.json');
    if (!fs.existsSync(manifestFile)) return [];

    let manifest;
    try {
        manifest = JSON.parse(fs.readFileSync(manifestFile, 'utf8'));
    } catch (error) {
        return [
            {
                rule: 'unreadable-manifest',
                subject: manifestFile,
                reason: `package.json could not be parsed: ${error.message}`,
            },
        ];
    }

    const violations = [];

    for (const field of FIELDS) {
        for (const [key, specifier] of Object.entries(manifest[field] ?? {})) {
            const name = resolveName(key, specifier);

            const reason = blockedPackageReason(policy, name);
            if (reason) {
                const alias = name === key ? '' : ` (aliased as "${key}")`;
                violations.push({
                    rule: 'blocked-package',
                    subject: `${name}${alias} — package.json ▸ ${field}`,
                    reason,
                });
                continue;
            }

            if (!policy.allowExoticSources && isExoticSpecifier(specifier)) {
                violations.push({
                    rule: 'exotic-source',
                    subject: `"${key}": "${specifier}" — package.json ▸ ${field}`,
                    reason: 'git and tarball sources carry no publish date and no provenance',
                    hint: 'install from a registry, or set "allowExoticSources" in policy.json',
                });
            }
        }
    }

    return violations;
}
