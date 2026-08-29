import fs from 'node:fs';
import path from 'node:path';
import { COMPROMISED_CACHE_FILE } from '../paths.mjs';
import Logger from '../logs/Logger.mjs';

/**
 * The packages already known to be malicious using DataDog's curated manifest.
 */
export default class Compromised {
    static #REQUEST_TIMEOUT_MS = 30_000;
    static #USER_AGENT = 'secure-npm (supply-chain guard)';

    /** @type {Promise<Object> | null} **/
    static #pending = null;

    static #minutes = (value) => value * 60 * 1000;

    static #readCache(source) {
        try {
            const cached = JSON.parse(fs.readFileSync(COMPROMISED_CACHE_FILE, 'utf8'));
            // A cache written from another source answers a different question.
            if (cached.source !== source || !cached.index) return null;
            return { index: cached.index, fetchedAt: cached.fetchedAt, count: cached.count };
        } catch {
            return null;
        }
    }

    static #writeCache(source, index, count) {
        try {
            fs.mkdirSync(path.dirname(COMPROMISED_CACHE_FILE), { recursive: true });
            const temporary = `${COMPROMISED_CACHE_FILE}.${process.pid}.tmp`;
            fs.writeFileSync(temporary, JSON.stringify({ source, fetchedAt: Date.now(), count, index }), 'utf8');
            fs.renameSync(temporary, COMPROMISED_CACHE_FILE);
        } catch {
            // A cold cache only costs one more request.
        }
    }

    static async #fetchList(source) {
        const response = await fetch(source, {
            headers: { accept: 'application/json', 'user-agent': this.#USER_AGENT },
            signal: AbortSignal.timeout(this.#REQUEST_TIMEOUT_MS),
        });

        if (!response.ok) throw new Error(`${source} answered ${response.status} ${response.statusText}`);

        const body = await response.json();
        if (!body || typeof body !== 'object' || Array.isArray(body)) {
            throw new Error(`${source} did not answer with a package manifest`);
        }

        return body;
    }

    static async #resolveList(policy) {
        const source = policy.compromisedPackagesSource;
        if (!source) return { index: null, source: null, fetchedAt: null, count: 0, stale: false, reason: null };

        const cached = this.#readCache(source);
        const age = cached ? Date.now() - cached.fetchedAt : Infinity;

        if (cached && age < this.#minutes(policy.compromisedPackagesRefreshMinutes)) {
            const { index, fetchedAt, count } = cached;
            return { index, source, fetchedAt, count, stale: false, reason: null };
        }

        try {
            const index = await this.#fetchList(source);
            const count = Object.keys(index).length;
            this.#writeCache(source, index, count);
            return { index, source, fetchedAt: Date.now(), count, stale: false, reason: null };
        } catch (error) {
            if (cached && age < this.#minutes(policy.compromisedPackagesMaxStaleMinutes)) {
                const hours = Math.round(age / 3_600_000);
                Logger.warn(
                    `the malicious-package list could not be refreshed (${error.message}) - using the copy fetched ${hours}h ago`
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
                    ? `${error.message} - and the cached copy is older than ${policy.compromisedPackagesMaxStaleMinutes} minutes`
                    : error.message,
            };
        }
    }

    /**
     * @returns {Promise<{
     *      index: Object | null,
     *      source: string | null,
     *      fetchedAt: number | null,
     *      count: number,
     *      stale: boolean,
     *      reason: string | null
     *  }>}
     */
    static load(policy) {
        this.#pending ??= this.#resolveList(policy);
        return this.#pending;
    }

    static cacheStatus(policy) {
        const source = policy.compromisedPackagesSource;
        if (!source) return { source: null, cached: null };
        return { source, cached: this.#readCache(source) };
    }

    static age(fetchedAt) {
        const minutes = Math.round((Date.now() - fetchedAt) / 60_000);
        if (minutes < 60) return `${minutes} min`;

        const hours = Math.round(minutes / 60);
        return hours < 48 ? `${hours} h` : `${Math.round(hours / 24)} d`;
    }

    /** @returns {string | null} **/
    static summary(state) {
        return state?.index ? `${state.count} names, fetched ${this.age(state.fetchedAt)} ago` : null;
    }

    /** @returns {import('../system/System.mjs').Violation | null} **/
    static listViolation(state) {
        if (state.index || !state.reason) return null;

        return {
            rule: 'compromised-list-unavailable',
            subject: state.source,
            reason: `the malicious-package list could not be obtained: ${state.reason}`,
            hint: 'this check fails closed - restore network access, or clear "compromisedPackagesSource" in policy.json to switch it off',
        };
    }

    /**
     * @param {Object | null} list
     * @param {string} name
     * @param {string | null} [version]
     * @param {string} [resolved]
     * @returns {string | null}
     */
    static reason(list, name, version = null, resolved = '') {
        if (!list || typeof name !== 'string' || !Object.hasOwn(list, name)) return null;
        const versions = list[name];
        if (versions === null) return 'every published version of this package is listed as malicious';
        if (!Array.isArray(versions)) return null;
        if (version && versions.includes(version)) return 'this exact version is listed as malicious';

        // A lockfile can pin a spelling the entry lacks; the tarball still names what was published.
        const match =
            typeof resolved === 'string'
            && resolved !== ''
            && versions.find(v => resolved.includes(`-${v}.tgz`));

        return match ? `its tarball resolves to ${match}, which is listed as malicious` : null;
    }

    /** @returns {{ name: string, version: string, resolved: string, reason: string }[]} **/
    static find(list, index) {
        const found = [];
        if (!list) return found;

        for (const [name, entries] of Object.entries(index))
            for (const { version, resolved } of entries) {
                const reason = this.reason(list, name, version, resolved);
                if (reason) found.push({ name, version, resolved, reason });
            }

        return found;
    }
}
