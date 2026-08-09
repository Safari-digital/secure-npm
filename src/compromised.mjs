/**
 * The packages that are already known to be malicious.
 *
 * Every other rule here is a heuristic about when and where code came from — an
 * age, a provenance attestation, a repository whitelist. This one names actual
 * compromised releases: DataDog publish a curated manifest of malicious npm
 * packages, and a name on it is not a risk to be weighed against convenience,
 * it is a package that must not reach the machine.
 *
 *   https://github.com/DataDog/malicious-software-packages-dataset
 *
 * The manifest maps a package name to the versions that are compromised, or to
 * `null` when every version of it is. It is ~300 kB and changes at most daily,
 * so it is fetched once and cached on disk for every command to share. Three
 * states come out of that, and they are deliberately not the same thing:
 *
 *   fresh    fetched within `compromisedPackagesRefreshMinutes`
 *   stale    the fetch failed, but a cached copy is still inside
 *            `compromisedPackagesMaxStaleMinutes` — announced, then used, because
 *            a two-day-old list is worth incomparably more than no list at all
 *   missing  neither, and then nothing gets installed: an unverifiable tree is
 *            refused the same way an unverifiable publish date is.
 */

import fs from 'node:fs';
import path from 'node:path';
import { compromisedCacheFile } from './paths.mjs';
import { warn } from './logger.mjs';

const REQUEST_TIMEOUT_MS = 30_000;
const USER_AGENT = 'secure-npm (supply-chain guard)';

/** Loaded at most once per process, however many guards ask for it. */
let pending = null;

function readCache(source) {
    try {
        const cached = JSON.parse(fs.readFileSync(compromisedCacheFile, 'utf8'));
        // A cache written from another source answers a different question.
        if (cached.source !== source || !cached.index) return null;
        return { index: cached.index, fetchedAt: cached.fetchedAt, count: cached.count };
    } catch {
        return null;
    }
}

/**
 * Written through a temporary file: this one is large enough, and read often
 * enough, for a half-written copy to be a realistic way to lose the check.
 */
function writeCache(source, index, count) {
    try {
        fs.mkdirSync(path.dirname(compromisedCacheFile), { recursive: true });
        const temporary = `${compromisedCacheFile}.${process.pid}.tmp`;
        fs.writeFileSync(temporary, JSON.stringify({ source, fetchedAt: Date.now(), count, index }), 'utf8');
        fs.renameSync(temporary, compromisedCacheFile);
    } catch {
        // A cold cache only costs one more request.
    }
}

async function fetchList(source) {
    const response = await fetch(source, {
        headers: { accept: 'application/json', 'user-agent': USER_AGENT },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });

    if (!response.ok) throw new Error(`${source} answered ${response.status} ${response.statusText}`);

    const body = await response.json();
    if (!body || typeof body !== 'object' || Array.isArray(body)) {
        throw new Error(`${source} did not answer with a package manifest`);
    }

    return body;
}

const minutes = value => value * 60 * 1000;

async function resolveList(policy) {
    const source = policy.compromisedPackagesSource;
    if (!source) return { index: null, source: null, fetchedAt: null, count: 0, stale: false, reason: null };

    const cached = readCache(source);
    const age = cached ? Date.now() - cached.fetchedAt : Infinity;

    if (cached && age < minutes(policy.compromisedPackagesRefreshMinutes)) {
        const { index, fetchedAt, count } = cached;
        return { index, source, fetchedAt, count, stale: false, reason: null };
    }

    try {
        const index = await fetchList(source);
        const count = Object.keys(index).length;
        writeCache(source, index, count);
        return { index, source, fetchedAt: Date.now(), count, stale: false, reason: null };
    } catch (error) {
        if (cached && age < minutes(policy.compromisedPackagesMaxStaleMinutes)) {
            const hours = Math.round(age / 3_600_000);
            warn(
                `the malicious-package list could not be refreshed (${error.message}) — using the copy fetched ${hours}h ago`
            );
            return {
                index: cached.index,
                source,
                fetchedAt: cached.fetchedAt,
                count: cached.count,
                stale: true,
                reason: error.message,
            };
        }

        return {
            index: null,
            source,
            fetchedAt: cached?.fetchedAt ?? null,
            count: 0,
            stale: false,
            reason: cached
                ? `${error.message} — and the cached copy is older than ${policy.compromisedPackagesMaxStaleMinutes} minutes`
                : error.message,
        };
    }
}

/**
 * The list, fetched or read from the cache.
 *
 * @returns {Promise<{ index: Object|null, source: string|null, fetchedAt: number|null, count: number,
 *   stale: boolean, reason: string|null }>}
 *   `index: null` with a `reason` means the list could not be obtained and the
 *   caller must fail closed. `index: null` with no reason means the policy
 *   configures no source, and the check is switched off.
 */
export function loadCompromisedList(policy) {
    pending ??= resolveList(policy);
    return pending;
}

/** Cache state without touching the network, for `doctor`. */
export function compromisedCacheStatus(policy) {
    const source = policy.compromisedPackagesSource;
    if (!source) return { source: null, cached: null };
    return { source, cached: readCache(source) };
}

/** How old the copy in use is, in the coarsest unit that still says something. */
export function listAge(fetchedAt) {
    const minutes = Math.round((Date.now() - fetchedAt) / 60_000);
    if (minutes < 60) return `${minutes} min`;

    const hours = Math.round(minutes / 60);
    return hours < 48 ? `${hours} h` : `${Math.round(hours / 24)} d`;
}

/**
 * What the run was checked against, for the line that says so out loud.
 *
 * A guard that only speaks when it refuses something is indistinguishable, on
 * every run that passes, from a guard that was never wired up — which is the
 * failure this whole tool exists to make impossible. The age belongs in it: a
 * clean report against a list from last month is not the same answer.
 *
 * @returns {string | null} null when no list is in use, and there is nothing to claim.
 */
export function compromisedListSummary(state) {
    return state?.index ? `${state.count} names, fetched ${listAge(state.fetchedAt)} ago` : null;
}

/** Violation for a list that a policy asked for and could not be obtained. */
export function compromisedListViolation(state) {
    if (state.index || !state.reason) return null;

    return {
        rule: 'compromised-list-unavailable',
        subject: state.source,
        reason: `the malicious-package list could not be obtained: ${state.reason}`,
        hint: 'this check fails closed — restore network access, or clear "compromisedPackagesSource" in policy.json to switch it off',
    };
}

/**
 * Why `name@version` is refused, or null when it is not on the list.
 *
 * `version` is optional on purpose. A package.json declares ranges rather than
 * versions, so a manifest is checked by name alone: only an entry covering
 * every published version says anything certain about a range.
 *
 * @param {Object|null} list The manifest, or null when the check is off
 * @returns {string | null}
 */
export function compromisedReason(list, name, version = null, resolved = '') {
    // hasOwn, so that a package named `constructor` or `toString` does not match.
    if (!list || typeof name !== 'string' || !Object.hasOwn(list, name)) return null;

    const versions = list[name];
    if (versions === null) return 'every published version of this package is listed as malicious';
    if (!Array.isArray(versions)) return null;

    if (version && versions.includes(version)) return 'this exact version is listed as malicious';

    // A lockfile can pin a version the entry spells differently, or record no
    // version at all; the tarball it resolves to still names what was published.
    const match = typeof resolved === 'string' && resolved !== '' && versions.find(v => resolved.includes(`-${v}.tgz`));
    return match ? `its tarball resolves to ${match}, which is listed as malicious` : null;
}

/**
 * Every compromised entry of an index built by `lockfile.mjs`.
 *
 * @returns {{ name: string, version: string, resolved: string, reason: string }[]}
 */
export function findCompromised(list, index) {
    const found = [];
    if (!list) return found;

    for (const [name, entries] of Object.entries(index)) {
        for (const { version, resolved } of entries) {
            const reason = compromisedReason(list, name, version, resolved);
            if (reason) found.push({ name, version, resolved, reason });
        }
    }

    return found;
}
