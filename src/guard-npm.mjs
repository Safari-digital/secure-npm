/**
 * The checks npm cannot perform on its own.
 *
 * pnpm enforces release age, trust downgrades and exotic sources natively, so
 * for pnpm the wrapper only has to keep those settings from being switched off.
 * npm has none of them, so the wrapper reproduces them:
 *
 *   1. ask npm what it *would* install (`--dry-run --json`, which touches
 *      neither node_modules nor the lockfile),
 *   2. check that set against the policy,
 *   3. only then run the real command.
 *
 * The order matters. Checking after the fact would mean the code is already on
 * disk by the time the verdict arrives.
 */

import fs from 'node:fs';
import path from 'node:path';
import { spawn } from 'node:child_process';
import {
    blockedPackageReason,
    exoticSourceHint,
    exoticSourceVerdict,
    gitSourceIdentity,
    isAgeExempt,
    isExoticResolution,
    registryFor,
} from './rules.mjs';
import { mapWithConcurrency, resolvePublishDate } from './registry.mjs';

const PREVIEW_TIMEOUT_MS = 180_000;
const REGISTRY_CONCURRENCY = 8;

/**
 * Runs the command as a dry run and returns the packages npm reports it would
 * add or change.
 *
 * @returns {Promise<{ ok: true, packages: {name: string, version: string}[] } | { ok: false, reason: string }>}
 */
export function previewResolution({ manager, argv, cwd }) {
    const previewArgv = [...argv, '--dry-run', '--json', '--ignore-scripts'];

    return new Promise(resolve => {
        const child = spawn(process.execPath, [manager.file, ...previewArgv], {
            cwd,
            stdio: ['ignore', 'pipe', 'pipe'],
            env: { ...process.env, npm_config_update_notifier: 'false' },
        });

        let stdout = '';
        let stderr = '';
        const timer = setTimeout(() => child.kill(), PREVIEW_TIMEOUT_MS);

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
 * Blocked names and immature releases across a resolved package set.
 *
 * `gitSourced` names are exempt from the age check and from it alone. A package
 * taken from a whitelisted repository has no registry publish date, and the
 * version it reports belongs to a commit — looking it up would read the date of
 * whatever unrelated package happens to sit under that name on the registry,
 * which is worse than not checking. The name is the unit here rather than
 * name@version, because npm's dry-run report is all the wrapper has to go on
 * before anything is written.
 */
export async function inspectPackages(policy, packages, gitSourced = new Set()) {
    const violations = [];
    const cutoffMs = Date.now() - policy.minimumReleaseAgeMinutes * 60 * 1000;

    const needAgeCheck = [];

    for (const { name, version } of packages) {
        const reason = blockedPackageReason(policy, name);
        if (reason) {
            violations.push({ rule: 'blocked-package', subject: `${name}@${version}`, reason });
            continue;
        }

        if (policy.minimumReleaseAgeMinutes <= 0 || isAgeExempt(policy, name, version)) continue;
        if (gitSourced.has(name)) continue;

        const registry = registryFor(policy, name);
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

    const dates = await mapWithConcurrency(needAgeCheck, REGISTRY_CONCURRENCY, ({ registry, name, version }) =>
        resolvePublishDate(registry, name, version, cutoffMs)
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
                reason: `published ${publishedAt.toISOString()} — ${ageHours}h old, minimum is ${
                    policy.minimumReleaseAgeMinutes / 60
                }h`,
                hint: 'wait for the version to mature, or pin an older one',
            });
        }
    });

    return violations;
}

/** Package name behind a lockfile entry key such as `node_modules/@scope/name`. */
function nameFromLockKey(key, entry) {
    if (entry?.name) return entry.name;
    const marker = key.lastIndexOf('node_modules/');
    return marker === -1 ? null : key.slice(marker + 'node_modules/'.length);
}

function readLockfile(cwd) {
    const lockFile = path.join(cwd, 'package-lock.json');
    if (!fs.existsSync(lockFile)) return { lockFile, lock: null, error: null };

    try {
        return { lockFile, lock: JSON.parse(fs.readFileSync(lockFile, 'utf8')), error: null };
    } catch (error) {
        return { lockFile, lock: null, error };
    }
}

/**
 * Every package a lockfile pins, and which of them came from git.
 *
 * `npm ci` deletes node_modules and reinstalls the whole lockfile, but its
 * `--dry-run` report only lists what is missing from the *current* tree — with
 * node_modules in place it reports nothing at all. The lockfile is therefore
 * the only honest answer to "what is about to be fetched", and the one place
 * where each entry says where it resolved from.
 *
 * @returns {{ packages: {name: string, version: string}[], gitSourced: Set<string> }}
 */
export function lockfilePackages(cwd) {
    const { lock } = readLockfile(cwd);
    if (!lock) return { packages: [], gitSourced: new Set() };

    const packages = [];
    const gitSourced = new Set();

    for (const [key, entry] of Object.entries(lock.packages ?? {})) {
        if (key === '' || entry?.link === true || !entry?.version) continue;

        const name = nameFromLockKey(key, entry);
        if (!name) continue;

        packages.push({ name, version: entry.version });
        if (gitSourceIdentity(entry?.resolved) !== null) gitSourced.add(name);
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
 * Second pass over the lockfile npm just wrote. The dry-run report gives names
 * and versions but not where each one came from, so exotic resolutions are only
 * visible here.
 */
export function inspectLockfile(policy, cwd) {
    const { lockFile, lock, error } = readLockfile(cwd);
    if (error) return [{ rule: 'unreadable-lockfile', subject: lockFile, reason: error.message }];
    if (!lock) return [];

    const violations = [];

    for (const [key, entry] of Object.entries(lock.packages ?? {})) {
        if (key === '' || entry?.link === true) continue;

        const name = nameFromLockKey(key, entry);
        if (!name) continue;

        const reason = blockedPackageReason(policy, name);
        if (reason) {
            violations.push({ rule: 'blocked-package', subject: `${name} — ${key}`, reason });
            continue;
        }

        if (isExoticResolution(policy, entry?.resolved)) {
            const { allowed, identity } = exoticSourceVerdict(policy, entry.resolved);
            if (!allowed) {
                violations.push({
                    rule: 'exotic-source',
                    subject: `${name} — ${entry.resolved}`,
                    reason: 'resolved outside every registry listed in the policy',
                    hint: identity
                        ? exoticSourceHint(identity)
                        : 'add the registry to policy.json, or replace the dependency',
                });
            }
        }
    }

    return violations;
}
