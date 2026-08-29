import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { PACKUMENT_CACHE_DIR } from '../paths.mjs';

/**
 * Publish dates and dist-tags, which npm will not answer locally.
 *
 * The abbreviated packument (~6 kB) carries a package-wide `modified` stamp;
 * when that is older than the cutoff, every version is too. Only then is the
 * full packument (up to several MB) fetched for `time[version]`.
 */
export default class Registry {
    static #ABBREVIATED_ACCEPT = 'application/vnd.npm.install-v1+json';
    static #FULL_ACCEPT = 'application/json';
    static #CACHE_TTL_MS = 60 * 60 * 1000;
    static #REQUEST_TIMEOUT_MS = 20_000;
    static #USER_AGENT = 'secure-npm (supply-chain guard)';

    static #memory = new Map();

    static #cacheFile(registry, name, kind) {
        const digest = createHash('sha256').update(`${registry}\0${name}\0${kind}`).digest('hex');
        return path.join(PACKUMENT_CACHE_DIR, `${digest}.json`);
    }

    static #readCache(file) {
        try {
            const cached = JSON.parse(fs.readFileSync(file, 'utf8'));
            if (Date.now() - cached.fetchedAt > this.#CACHE_TTL_MS) return null;
            return cached.body;
        } catch {
            return null;
        }
    }

    static #writeCache(file, body) {
        try {
            fs.mkdirSync(PACKUMENT_CACHE_DIR, { recursive: true });
            fs.writeFileSync(file, JSON.stringify({ fetchedAt: Date.now(), body }), 'utf8');
        } catch {
            // A cold cache only costs time.
        }
    }

    static #packumentUrl(registry, name) {
        const base = registry.endsWith('/') ? registry : `${registry}/`;
        return `${base}${name.replace('/', '%2f')}`;
    }

    static async #fetchPackument(registry, name, kind) {
        const response = await fetch(this.#packumentUrl(registry, name), {
            headers: {
                accept: kind === 'full' ? this.#FULL_ACCEPT : this.#ABBREVIATED_ACCEPT,
                'user-agent': this.#USER_AGENT,
            },
            signal: AbortSignal.timeout(this.#REQUEST_TIMEOUT_MS),
        });

        if (!response.ok) throw new Error(`${registry} answered ${response.status} for ${name}`);
        return response.json();
    }

    static async #getPackument(registry, name, kind, { allowCache = true } = {}) {
        const key = `${registry} ${name} ${kind}`;
        if (allowCache && this.#memory.has(key)) return this.#memory.get(key);

        const file = this.#cacheFile(registry, name, kind);
        if (allowCache) {
            const cached = this.#readCache(file);
            if (cached) {
                this.#memory.set(key, cached);
                return cached;
            }
        }

        const body = await this.#fetchPackument(registry, name, kind);
        this.#writeCache(file, body);
        this.#memory.set(key, body);
        return body;
    }

    /**
     * When `name@version` was published. `publishedAt: null` means the date
     * could not be established - callers treat that as a failure, not a pass.
     *
     * @returns {Promise<{ publishedAt: Date } | { publishedAt: null, reason: string }>}
     */
    static async resolvePublishDate(registry, name, version, cutoffMs) {
        try {
            const abbreviated = await this.#getPackument(registry, name, 'abbreviated');
            const known = abbreviated?.versions && version in abbreviated.versions;

            // Re-fetch once when the version is missing: the cache may predate it.
            const fresh = known
                ? abbreviated
                : await this.#getPackument(registry, name, 'abbreviated', { allowCache: false });
            if (!fresh?.versions || !(version in fresh.versions)) {
                return { publishedAt: null, reason: `${name}@${version} is not published on ${registry}` };
            }

            const modified = Date.parse(fresh.modified ?? '');
            if (!Number.isNaN(modified) && modified < cutoffMs) {
                return { publishedAt: new Date(modified) };
            }

            const full = await this.#getPackument(registry, name, 'full', { allowCache: known });
            const stamp = Date.parse(full?.time?.[version] ?? '');
            if (Number.isNaN(stamp)) {
                return { publishedAt: null, reason: `${registry} publishes no release date for ${name}@${version}` };
            }

            return { publishedAt: new Date(stamp) };
        } catch (error) {
            return { publishedAt: null, reason: error.message };
        }
    }

    /**
     * Concrete version behind a dist-tag - `npx cowsay` names no version.
     *
     * @returns {Promise<{ version: string } | { version: null, reason: string }>}
     */
    static async resolveDistTag(registry, name, tag = 'latest') {
        try {
            const abbreviated = await this.#getPackument(registry, name, 'abbreviated', { allowCache: false });
            const version = abbreviated?.['dist-tags']?.[tag];
            if (!version) return { version: null, reason: `${name} has no "${tag}" dist-tag on ${registry}` };
            return { version };
        } catch (error) {
            return { version: null, reason: error.message };
        }
    }

    /** Bounded parallelism - registries throttle. **/
    static async mapWithConcurrency(items, limit, worker) {
        const results = new Array(items.length);
        let cursor = 0;

        const runners = Array.from({ length: Math.min(limit, items.length) }, async () => {
            while (cursor < items.length) {
                const index = cursor++;
                results[index] = await worker(items[index], index);
            }
        });

        await Promise.all(runners);
        return results;
    }
}
