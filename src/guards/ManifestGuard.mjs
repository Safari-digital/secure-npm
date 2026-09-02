import fs from 'node:fs';
import path from 'node:path';
import Rules from '../policy/Rules.mjs';
import Compromised from '../compromised/Compromised.mjs';
import LockFiles from './LockFiles.mjs';

/**
 * The project's own package.json. Every dependency field is inspected,
 * devDependencies included: this manifest is authored locally, unlike a
 * third-party one whose devDependencies are never installed.
 */
export default class ManifestGuard {
    static #readManifest(cwd) {
        const manifestFile = path.join(cwd, 'package.json');
        if (!fs.existsSync(manifestFile)) return { manifestFile, manifest: null, error: null };

        try {
            return { manifestFile, manifest: JSON.parse(fs.readFileSync(manifestFile, 'utf8')), error: null };
        } catch (error) {
            return { manifestFile, manifest: null, error };
        }
    }

    static #scriptNamesIn(file, names) {
        try {
            const { scripts } = JSON.parse(fs.readFileSync(file, 'utf8'));
            for (const name of Object.keys(scripts ?? {})) names.add(name);
        } catch {
            // An unreadable manifest declares nothing - only ever used to stay quiet.
        }
        return names;
    }

    /** Script names declared by the manifest in this directory. **/
    static scriptNames(cwd) {
        return this.#scriptNamesIn(path.join(cwd, 'package.json'), new Set());
    }

    /**
     * Script names declared anywhere in the repository - for
     * `pnpm --filter web build`, where the script belongs to another package.
     * Only reached once the local manifest has come up empty.
     */
    static workspaceScriptNames(cwd) {
        const names = new Set();

        for (const file of LockFiles.findIndexableFiles(LockFiles.findRepositoryRoot(cwd))) {
            if (path.basename(file) === LockFiles.MANIFEST_FILE) this.#scriptNamesIn(file, names);
        }

        return names;
    }

    /**
     * Dependency keys whose specifier resolves from git - npm installs those
     * under the key, which is what the release-age check has to skip.
     *
     * @returns {Set<string>}
     */
    static gitSourcedNames(cwd) {
        const { manifest } = this.#readManifest(cwd);
        const names = new Set();
        if (!manifest) return names;

        for (const field of Rules.AUTHORED_FIELDS) {
            for (const [key, specifier] of Object.entries(manifest[field] ?? {})) {
                if (Rules.gitSourceIdentity(specifier) !== null) names.add(key);
            }
        }

        return names;
    }

    /**
     * Checked by name alone against the malicious-package list: a manifest
     * declares ranges, and exact versions get checked once resolved.
     *
     * @param {Object | null} compromised
     * @returns {import('../system/System.mjs').Violation[]}
     */
    static inspect(policy, cwd, compromised = null) {
        const { manifestFile, manifest, error } = this.#readManifest(cwd);
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

        for (const field of Rules.AUTHORED_FIELDS) {
            for (const [key, specifier] of Object.entries(manifest[field] ?? {})) {
                const name = Rules.resolveName(key, specifier);
                const alias = name === key ? '' : ` (aliased as "${key}")`;

                const malicious = Compromised.reason(compromised, name);
                if (malicious) {
                    violations.push({
                        rule: 'compromised-package',
                        subject: `${name}${alias} - package.json ▸ ${field}`,
                        reason: malicious,
                        hint: 'this package is on the malicious-package list - remove it from package.json',
                    });
                    continue;
                }

                const reason = Rules.blockedPackageReason(policy, name);
                if (reason) {
                    violations.push({
                        rule: 'blocked-package',
                        subject: `${name}${alias} - package.json ▸ ${field}`,
                        reason,
                        hint: Rules.BLOCKED_BY_NAME_HINT,
                    });
                    continue;
                }

                if (Rules.isExoticSpecifier(specifier)) {
                    const { allowed, identity } = Rules.exoticSourceVerdict(policy, specifier);
                    if (!allowed) {
                        violations.push({
                            rule: 'exotic-source',
                            subject: `"${key}": "${specifier}" - package.json ▸ ${field}`,
                            reason: 'git and tarball sources carry no publish date and no provenance',
                            hint: Rules.exoticSourceHint(identity),
                        });
                    }
                }
            }
        }

        return violations;
    }
}
