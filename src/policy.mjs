/**
 * Policy loading. `policy.json` is the shared, versioned ruleset;
 * `policy.local.json` is a git-ignored per-machine overlay merged on top.
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

function compile(raw) {
    const blockedPackages = (raw.blockedPackages ?? []).map(({ pattern, reason }) => ({
        pattern: new RegExp(pattern),
        source: pattern,
        reason,
    }));

    const blockedManagers = new Map(
        (raw.blockedManagers ?? []).map(({ command, reason }) => [command.toLowerCase(), reason])
    );

    return {
        minimumReleaseAgeMinutes: raw.minimumReleaseAgeMinutes ?? 0,
        minimumReleaseAgeExclude: new Set(raw.minimumReleaseAgeExclude ?? []),
        allowExoticSources: raw.allowExoticSources === true,
        forceIgnoreScripts: raw.forceIgnoreScripts !== false,
        trustPolicy: raw.trustPolicy ?? 'no-downgrade',
        trustPolicyIgnoreAfterMinutes: raw.trustPolicyIgnoreAfterMinutes ?? 129600,
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
