/**
 * Policy loading. `policy.json` is the shared, versioned ruleset, read from the
 * deployed runtime; `policy.local.json` is a per-machine overlay merged on top,
 * kept outside the repository entirely and written by `secure-npm edit-policy`.
 */

import fs from 'node:fs';
import { localPolicyFile, policyFile } from './paths.mjs';

function readJson(file) {
    if (!fs.existsSync(file)) return null;
    try {
        return JSON.parse(fs.readFileSync(file, 'utf8'));
    } catch (cause) {
        throw new Error(`policy file is not valid JSON: ${file}\n  ${cause.message}`, { cause });
    }
}

/**
 * `host/owner/repo`, where `*` stands for exactly one path segment, into an
 * anchored pattern. Deliberately not a raw regex like `blockedPackages`: this
 * list *grants* access, so an unanchored or dot-happy expression written by
 * hand would widen it far past what was meant — `github.com/acme/*` must not
 * reach `github.com.evil.net/acme/x` or `github.com/acme/x/../../y`.
 */
function gitSourcePattern(entry) {
    const glob = String(entry)
        .trim()
        .toLowerCase()
        .replace(/^\/+|\/+$/g, '')
        .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
        .replaceAll('\\*', '[^/]+');

    return new RegExp(`^${glob}$`);
}

function compile(raw) {
    const blockedPackages = (raw.blockedPackages ?? []).map(({ pattern, reason }) => ({
        pattern: new RegExp(pattern),
        source: pattern,
        reason,
    }));

    const allowedGitSources = (raw.allowedGitSources ?? [])
        .filter(entry => typeof entry === 'string' && entry.trim() !== '')
        .map(entry => ({ pattern: gitSourcePattern(entry), source: entry }));

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
        // An empty source is how the check is switched off, the way a zero
        // minimumReleaseAge switches off the age check.
        compromisedPackagesSource: raw.compromisedPackagesSource || null,
        compromisedPackagesRefreshMinutes: raw.compromisedPackagesRefreshMinutes ?? 360,
        compromisedPackagesMaxStaleMinutes: raw.compromisedPackagesMaxStaleMinutes ?? 10080,
        blockedPackages,
        blockedManagers,
        registries: raw.registries ?? { default: 'https://registry.npmjs.org/' },
        logRetentionDays: raw.logRetentionDays ?? 90,
        sources: raw.$sources,
    };
}

let cached;

export function loadPolicy() {
    if (cached) return cached;

    const shared = readJson(policyFile);
    if (!shared) throw new Error(`policy file is missing: ${policyFile}`);

    const local = readJson(localPolicyFile);
    const merged = { ...shared, ...(local ?? {}) };
    merged.$sources = local ? [policyFile, localPolicyFile] : [policyFile];

    cached = compile(merged);
    return cached;
}
