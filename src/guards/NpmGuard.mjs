import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import Rules from '../policy/Rules.mjs';
import Compromised from '../compromised/Compromised.mjs';
import Registry from '../registry/Registry.mjs';

/**
 * The checks npm cannot perform on its own - pnpm enforces release age, trust
 * and exotic sources natively, npm has none of them. The wrapper asks npm what
 * it would install (dry run), checks that set, and only then runs the command:
 * checking after the fact would mean the code is already on disk.
 */
export default class NpmGuard {
    static #PREVIEW_TIMEOUT_MS = 180_000;
    static #REGISTRY_CONCURRENCY = 8;

    /**
     * Runs the command as a dry run and returns what npm reports it would add
     * or change - touching neither node_modules nor the lockfile.
     *
     * @returns {Promise<{ ok: true, packages: { name: string, version: string }[] } | { ok: false, reason: string }>}
     */
    static preview({ manager, argv, cwd }) {
        const previewArgv = [...argv, '--dry-run', '--json', '--ignore-scripts'];

        return new Promise(resolve => {
            const child = spawn(process.execPath, [manager.file, ...previewArgv], {
                cwd,
                stdio: ['ignore', 'pipe', 'pipe'],
                env: { ...process.env, npm_config_update_notifier: 'false' },
            });

            let stdout = '';
            let stderr = '';
            const timer = setTimeout(() => child.kill(), this.#PREVIEW_TIMEOUT_MS);

            child.stdout.on('data', chunk => (stdout += chunk));
            child.stderr.on('data', chunk => (stderr += chunk));

            child.on('error', error => {
                clearTimeout(timer);
                resolve({ ok: false, reason: error.message });
            });

            child.on('close', code => {
                clearTimeout(timer);

                if (code !== 0) {
                    const detail = stderr.trim().split('\n').slice(-6).join('\n') || `npm exited with code ${code}`;
                    return resolve({ ok: false, reason: detail });
                }

                const start = stdout.indexOf('{');
                if (start === -1) return resolve({ ok: true, packages: [] });

                try {
                    const report = JSON.parse(stdout.slice(start));
                    const entries = [...(report.add ?? []), ...(report.change ?? [])];
                    const packages = entries
                        .filter(entry => entry?.name && entry?.version)
                        .map(({ name, version }) => ({ name, version }));
                    return resolve({ ok: true, packages });
                } catch (error) {
                    return resolve({ ok: false, reason: `could not read npm's dry-run report: ${error.message}` });
                }
            });
        });
    }

    /**
     * Known-malicious releases, blocked names and immature releases across a
     * resolved package set. `gitSourced` names are exempt from the age check
     * alone: their version belongs to a commit, and looking it up would read
     * whatever unrelated package sits under that name on the registry.
     *
     * @param {{ name: string, version: string }[]} packages
     * @param {{ gitSourced?: Set<string>, compromised?: Object | null }} [options]
     * @returns {Promise<import('../system/System.mjs').Violation[]>}
     */
    static async inspectPackages(policy, packages, { gitSourced = new Set(), compromised = null } = {}) {
        const violations = [];
        const cutoffMs = Date.now() - policy.minimumReleaseAgeMinutes * 60 * 1000;

        const needAgeCheck = [];

        for (const { name, version } of packages) {
            // First, and with no exemption: this rule names a release rather than weighing a risk.
            const malicious = Compromised.reason(compromised, name, version);
            if (malicious) {
                violations.push({
                    rule: 'compromised-package',
                    subject: `${name}@${version}`,
                    reason: malicious,
                    hint: 'this package is on the malicious-package list - remove it, do not pin around it',
                });
                continue;
            }

            const reason = Rules.dependencyBlockReason(policy, name, version);
            if (reason) {
                violations.push({
                    rule: 'blocked-package',
                    subject: `${name}@${version}`,
                    reason,
                    hint: Rules.blockedPackageHint(name, version),
                });
                continue;
            }

            if (policy.minimumReleaseAgeMinutes <= 0 || Rules.isAgeExempt(policy, name, version)) continue;
            if (gitSourced.has(name)) continue;

            const registry = Rules.registryFor(policy, name);
            if (registry === null) {
                violations.push({
                    rule: 'unknown-scope-registry',
                    subject: `${name}@${version}`,
                    reason: 'no registry configured for this scope, so its release date cannot be verified',
                    hint: 'add the scope under "registries" in policy.json',
                });
                continue;
            }

            needAgeCheck.push({ name, version, registry });
        }

        const dates = await Registry.mapWithConcurrency(
            needAgeCheck,
            this.#REGISTRY_CONCURRENCY,
            ({ registry, name, version }) => Registry.resolvePublishDate(registry, name, version, cutoffMs)
        );

        needAgeCheck.forEach(({ name, version }, index) => {
            const { publishedAt, reason } = dates[index];

            if (publishedAt === null) {
                violations.push({
                    rule: 'unverifiable-release-date',
                    subject: `${name}@${version}`,
                    reason,
                    hint: 'add it to "minimumReleaseAgeExclude" in policy.json if this is expected',
                });
                return;
            }

            if (publishedAt.getTime() >= cutoffMs) {
                const ageHours = Math.round((Date.now() - publishedAt.getTime()) / 3_600_000);
                violations.push({
                    rule: 'release-too-recent',
                    subject: `${name}@${version}`,
                    reason: `published ${publishedAt.toISOString()} - ${ageHours}h old, minimum is ${
                        policy.minimumReleaseAgeMinutes / 60
                    }h`,
                    hint: 'wait for the version to mature, or pin an older one',
                });
            }
        });

        return violations;
    }

    /** Package name behind a lockfile key such as `node_modules/@scope/name`. **/
    static #nameFromLockKey(key, entry) {
        if (entry?.name) return entry.name;
        const marker = key.lastIndexOf('node_modules/');
        return marker === -1 ? null : key.slice(marker + 'node_modules/'.length);
    }

    static #readLockfile(cwd) {
        const lockFile = path.join(cwd, 'package-lock.json');
        if (!fs.existsSync(lockFile)) return { lockFile, lock: null, error: null };

        try {
            return { lockFile, lock: JSON.parse(fs.readFileSync(lockFile, 'utf8')), error: null };
        } catch (error) {
            return { lockFile, lock: null, error };
        }
    }

    /**
     * Every package the lockfile pins, and which of them came from git.
     * `npm ci` reinstalls the whole lockfile while its dry-run reports only
     * what is missing from the current tree - so the lockfile is the only
     * honest answer to "what is about to be fetched".
     *
     * @returns {{ packages: { name: string, version: string }[], gitSourced: Set<string> }}
     */
    static lockfilePackages(cwd) {
        const { lock } = this.#readLockfile(cwd);
        if (!lock) return { packages: [], gitSourced: new Set() };

        const packages = [];
        const gitSourced = new Set();

        for (const [key, entry] of Object.entries(lock.packages ?? {})) {
            if (key === '' || entry?.link === true || !entry?.version) continue;

            const name = this.#nameFromLockKey(key, entry);
            if (!name) continue;

            packages.push({ name, version: entry.version });
            if (Rules.gitSourceIdentity(entry?.resolved) !== null) gitSourced.add(name);
        }

        // The same package can be pinned at several depths.
        const seen = new Set();
        const deduped = packages.filter(({ name, version }) => {
            const id = `${name}@${version}`;
            if (seen.has(id)) return false;
            seen.add(id);
            return true;
        });

        return { packages: deduped, gitSourced };
    }

    /**
     * Second pass over the lockfile npm just wrote: the dry-run report carries
     * no resolution URLs, so exotic resolutions are only visible here.
     *
     * @returns {import('../system/System.mjs').Violation[]}
     */
    static inspectLockfile(policy, cwd, compromised = null) {
        const { lockFile, lock, error } = this.#readLockfile(cwd);
        if (error) return [{ rule: 'unreadable-lockfile', subject: lockFile, reason: error.message }];
        if (!lock) return [];

        const violations = [];

        for (const [key, entry] of Object.entries(lock.packages ?? {})) {
            if (key === '' || entry?.link === true) continue;

            const name = this.#nameFromLockKey(key, entry);
            if (!name) continue;

            const malicious = Compromised.reason(compromised, name, entry?.version, entry?.resolved ?? '');
            if (malicious) {
                violations.push({
                    rule: 'compromised-package',
                    subject: `${name}@${entry?.version ?? '?'} - ${key}`,
                    reason: malicious,
                    hint: 'this package is on the malicious-package list - remove it, do not pin around it',
                });
                continue;
            }

            const reason = Rules.dependencyBlockReason(policy, name, entry?.version);
            if (reason) {
                violations.push({
                    rule: 'blocked-package',
                    subject: `${name} - ${key}`,
                    reason,
                    hint: Rules.blockedPackageHint(name, entry?.version ?? null),
                });
                continue;
            }

            if (Rules.isExoticResolution(policy, entry?.resolved)) {
                const { allowed, identity } = Rules.exoticSourceVerdict(policy, entry.resolved);
                if (!allowed) {
                    violations.push({
                        rule: 'exotic-source',
                        subject: `${name} - ${entry.resolved}`,
                        reason: 'resolved outside every registry listed in the policy',
                        hint: identity
                            ? Rules.exoticSourceHint(identity)
                            : 'add the registry to policy.json, or replace the dependency',
                    });
                }
            }
        }

        return violations;
    }
}
