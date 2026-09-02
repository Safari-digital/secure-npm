import fs from 'node:fs';
import { LOCAL_POLICY_FILE, POLICY_FILE } from '../paths.mjs';

/**
 * @typedef {Object} PolicyConfig
 * @property {number} minimumReleaseAgeMinutes
 * @property {Set<string>} minimumReleaseAgeExclude
 * @property {boolean} allowExoticSources
 * @property {{ pattern: RegExp, source: string }[]} allowedGitSources
 * @property {boolean} forceIgnoreScripts
 * @property {string} trustPolicy
 * @property {number} trustPolicyIgnoreAfterMinutes
 * @property {string | null} compromisedPackagesSource
 * @property {number} compromisedPackagesRefreshMinutes
 * @property {number} compromisedPackagesMaxStaleMinutes
 * @property {{ pattern: RegExp, source: string, reason: string }[]} blockedPackages
 * @property {Set<string>} blockedPackagesExclude
 * @property {Map<string, string>} blockedManagers
 * @property {Object<string, string>} registries
 * @property {number} logRetentionDays
 * @property {string[]} sources
 */

export default class Policy {
    /** @type {PolicyConfig | undefined} **/
    static #cached;

    static #readJson(file) {
        if (!fs.existsSync(file)) return null;
        try {
            return JSON.parse(fs.readFileSync(file, 'utf8'));
        } catch (cause) {
            throw new Error(`policy file is not valid JSON: ${file}\n  ${cause.message}`, { cause });
        }
    }

    /**
     * `host/owner/repo` glob where `*` is exactly one path segment, anchored.
     * Deliberately not a raw regex: this list grants access, and a dot-happy
     * hand-written expression would widen it past what was meant.
     */
    static #gitSourcePattern(entry) {
        const glob = String(entry)
            .trim()
            .toLowerCase()
            .replace(/^\/+|\/+$/g, '')
            .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
            .replaceAll('\\*', '[^/]+');

        return new RegExp(`^${glob}$`);
    }

    /** @returns {PolicyConfig} **/
    static #compile(raw) {
        const blockedPackages = (raw.blockedPackages ?? []).map(({ pattern, reason }) => ({
            pattern: new RegExp(pattern),
            source: pattern,
            reason,
        }));

        const allowedGitSources = (raw.allowedGitSources ?? [])
            .filter(entry => typeof entry === 'string' && entry.trim() !== '')
            .map(entry => ({ pattern: this.#gitSourcePattern(entry), source: entry }));

        const blockedManagers = new Map(
            (raw.blockedManagers ?? []).map(({ command, reason }) => [command.toLowerCase(), reason])
        );

        return {
            minimumReleaseAgeMinutes: raw.minimumReleaseAgeMinutes ?? 0,
            minimumReleaseAgeExclude: new Set(raw.minimumReleaseAgeExclude ?? []),
            allowExoticSources: raw.allowExoticSources === true,
            allowedGitSources,
            forceIgnoreScripts: raw.forceIgnoreScripts !== false,
            trustPolicy: raw.trustPolicy ?? 'no-downgrade',
            trustPolicyIgnoreAfterMinutes: raw.trustPolicyIgnoreAfterMinutes ?? 129600,
            compromisedPackagesSource: raw.compromisedPackagesSource || null,
            compromisedPackagesRefreshMinutes: raw.compromisedPackagesRefreshMinutes ?? 360,
            compromisedPackagesMaxStaleMinutes: raw.compromisedPackagesMaxStaleMinutes ?? 10080,
            blockedPackages,
            blockedPackagesExclude: new Set(raw.blockedPackagesExclude ?? []),
            blockedManagers,
            registries: raw.registries ?? { default: 'https://registry.npmjs.org/' },
            logRetentionDays: raw.logRetentionDays ?? 90,
            sources: raw.$sources,
        };
    }

    /**
     * The shared policy.json overlaid with the machine-local policy.local.json.
     *
     * @returns {PolicyConfig}
     */
    static load() {
        if (this.#cached) return this.#cached;

        const shared = this.#readJson(POLICY_FILE);
        if (!shared) throw new Error(`policy file is missing: ${POLICY_FILE}`);

        const local = this.#readJson(LOCAL_POLICY_FILE);
        const merged = { ...shared, ...(local ?? {}) };
        merged.$sources = local ? [POLICY_FILE, LOCAL_POLICY_FILE] : [POLICY_FILE];

        this.#cached = this.#compile(merged);
        return this.#cached;
    }
}
