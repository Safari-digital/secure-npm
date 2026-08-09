/**
 * `secure-npm validate [path]`.
 *
 * The guard rails answer "should this be allowed in". This answers the other
 * question — "is what I already have compromised" — by reading a tree that is
 * on disk and checking every package it pins against the malicious-package
 * list. Nothing is resolved, nothing is fetched, and nothing about the policy
 * beyond that list applies: a lockfile written last year gets the list as it
 * stands today.
 *
 * It is the same audit `secure-npm validate` inherited from Safari Digital's
 * node-packages-validator, including its fail-closed rule: an unreadable file
 * or an unreachable list is reported as a failure rather than passed over.
 */

import fs from 'node:fs';
import path from 'node:path';
import { abort } from './execute.mjs';
import { audit, banner, checked, info } from './logger.mjs';
import { loadPolicy } from './policy.mjs';
import { compromisedListViolation, findCompromised, listAge, loadCompromisedList } from './compromised.mjs';
import {
    INDEXABLE_FILES,
    MANIFEST_FILE,
    NPM_LOCK_FILE,
    PNPM_LOCK_FILE,
    findIndexableFiles,
    findRepositoryRoot,
    indexFile,
} from './lockfile.mjs';
import { localPolicyFile, policyFile } from './paths.mjs';

export const VALIDATE_USAGE = `secure-npm validate — audit a tree against the malicious-package list

  secure-npm validate [path] [--monorepo]

  path         directory to audit, or a lockfile to audit directly (default: the current one)
  --monorepo   walk up to the repository root, then audit every manifest and lockfile below it

Both lockfiles are audited when both are present: whichever one was meant, the
other is on disk too, and a tree it installed is a tree that exists.

Exit code 1 when a compromised package is found, when a file cannot be read, or
when the list cannot be obtained — an unverifiable tree is not a clean one.
`;

/**
 * How to get rid of what was found.
 *
 * Emptying the manager's own cache is the part that is easy to skip and the part
 * that matters: the tarball survives a deleted node_modules. A run that found
 * hits under both lockfiles therefore names both caches — one report carries one
 * hint, and half a cleanup leaves the package on the machine.
 */
function remediation(lockfiles) {
    const clean = [
        lockfiles.has(NPM_LOCK_FILE) && 'run "npm cache clean --force"',
        lockfiles.has(PNPM_LOCK_FILE) && 'run "pnpm store prune"',
    ].filter(Boolean);

    return `remove the dependency from package.json, delete ${[...lockfiles].join(' and ')} and node_modules, ${clean.join(' and ')}, then reinstall`;
}

/**
 * The files this run has to read.
 *
 * @returns {{ files: string[], scope: string } | { error: string }}
 */
function resolveTargets({ target, monorepo }) {
    if (!fs.existsSync(target)) return { error: `${target} does not exist` };

    if (fs.statSync(target).isFile()) {
        if (monorepo) return { error: '--monorepo needs a directory, not a file' };
        if (!INDEXABLE_FILES.includes(path.basename(target))) {
            return { error: `${target} is not one of ${INDEXABLE_FILES.join(', ')}` };
        }
        return { files: [target], scope: path.basename(target) };
    }

    if (monorepo) {
        const root = findRepositoryRoot(target);
        const files = findIndexableFiles(root);
        if (files.length === 0) return { error: `no manifest and no lockfile anywhere under ${root}` };
        return { files, scope: `the repository at ${root}` };
    }

    // Every lockfile that is there, rather than the one belonging to whichever
    // manager was named: a lockfile on disk describes a tree that was installed,
    // and narrowing the audit to one of them is a way to miss the other.
    //
    // Manifests are left out on purpose — their ranges are not versions, and a
    // lockfile in the same directory answers the same question exactly.
    const wanted = [NPM_LOCK_FILE, PNPM_LOCK_FILE];
    const files = wanted.map(name => path.join(target, name)).filter(file => fs.existsSync(file));

    if (files.length === 0) return { error: `no ${wanted.join(' and no ')} in ${target}` };
    return { files, scope: files.map(file => path.basename(file)).join(' + ') };
}

export async function runValidate(argv, cwd = process.cwd()) {
    if (argv.includes('--help') || argv.includes('-h')) {
        process.stdout.write(VALIDATE_USAGE);
        return 0;
    }

    const flags = new Set(argv.filter(argument => argument.startsWith('-')));
    const unknown = [...flags].filter(flag => flag !== '--monorepo');
    if (unknown.length) {
        process.stderr.write(`secure-npm validate: unknown option "${unknown[0]}"\n\n${VALIDATE_USAGE}`);
        return 2;
    }

    const positional = argv.find(argument => !argument.startsWith('-'));
    const target = path.resolve(cwd, positional ?? '.');

    const resolved = resolveTargets({ target, monorepo: flags.has('--monorepo') });

    if (resolved.error) {
        process.stderr.write(`secure-npm validate: ${resolved.error}\n\n${VALIDATE_USAGE}`);
        return 2;
    }

    const policy = loadPolicy();
    const { files, scope } = resolved;
    const context = { command: `secure-npm validate ${positional ?? '.'}`.trim(), cwd };

    banner({
        action: 'Auditing',
        command: scope,
        policyFiles: fs.existsSync(localPolicyFile) ? [policyFile, localPolicyFile] : [policyFile],
        extras: {
            list: policy.compromisedPackagesSource ?? 'none — "compromisedPackagesSource" is not set in policy.json',
            files: String(files.length),
        },
    });

    if (!policy.compromisedPackagesSource) {
        process.stderr.write(
            '\nsecure-npm validate: there is nothing to validate against.\n' +
                '  set "compromisedPackagesSource" in policy.json, then re-run "node install.mjs".\n\n'
        );
        return 2;
    }

    const list = await loadCompromisedList(policy);
    const unavailable = compromisedListViolation(list);
    if (unavailable) return abort({ ...context, phase: 'validate', violations: [unavailable] });

    info(`${list.count} known-malicious package(s), fetched ${listAge(list.fetchedAt)} ago`);

    const violations = [];
    const hitFiles = new Set();

    for (const file of files) {
        // Relative only while that stays readable — a "..\..\..\" chain out of the
        // working directory says less than the path it was built from.
        const relative = path.relative(cwd, file);
        const label = relative && !relative.startsWith('..') ? relative : file;

        let index;
        try {
            index = indexFile(file);
        } catch (error) {
            // Fails closed: a file that cannot be read has not been cleared.
            violations.push({
                rule: 'unreadable-file',
                subject: label,
                reason: error.message,
                hint: 'fix or remove the file — it cannot be audited as it stands',
            });
            continue;
        }

        for (const { name, version, reason } of findCompromised(list.index, index)) {
            // A package.json hit, in --monorepo mode, comes with a lockfile hit
            // beside it; the cleanup is named after the lockfiles either way.
            if (path.basename(file) !== MANIFEST_FILE) hitFiles.add(path.basename(file));
            violations.push({ rule: 'compromised-package', subject: `${name}@${version} — ${label}`, reason });
        }
    }

    if (hitFiles.size) {
        const hint = remediation(hitFiles);
        for (const violation of violations) {
            if (violation.rule === 'compromised-package') violation.hint = hint;
        }
    }

    if (violations.length) return abort({ ...context, phase: 'validate', violations });

    checked(`no compromised package in ${files.length} file(s)`);
    audit({ event: 'run', command: context.command, cwd, files, checked: files.length });
    return 0;
}
