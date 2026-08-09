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
import { MANIFEST_FILE, findIndexableFiles, findRepositoryRoot } from './lockfile.mjs';

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
function scriptNamesIn(file, names) {
    try {
        const { scripts } = JSON.parse(fs.readFileSync(file, 'utf8'));
        for (const name of Object.keys(scripts ?? {})) names.add(name);
    } catch {
        // A manifest that cannot be read declares nothing, which is the safe answer:
        // the caller only uses this to stay quiet, never to let something through.
    }
    return names;
}

/** Script names declared by the manifest in this directory. */
export function manifestScriptNames(cwd) {
    return scriptNamesIn(path.join(cwd, 'package.json'), new Set());
}

/**
 * Script names declared anywhere in the repository.
 *
 * The fallback behind `manifestScriptNames`, for `pnpm --filter web build`,
 * where the script belongs to another package entirely. Walking the tree is not
 * free, so it is only ever reached once the local manifest has come up empty on
 * a word we already failed to recognise as a command.
 */
export function workspaceScriptNames(cwd) {
    const names = new Set();

    for (const file of findIndexableFiles(findRepositoryRoot(cwd))) {
        if (path.basename(file) === MANIFEST_FILE) scriptNamesIn(file, names);
    }

    return names;
}

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
