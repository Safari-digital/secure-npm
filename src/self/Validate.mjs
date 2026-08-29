import fs from 'node:fs';
import path from 'node:path';
import Logger from '../logs/Logger.mjs';
import Policy from '../policy/Policy.mjs';
import System from '../system/System.mjs';
import Compromised from '../compromised/Compromised.mjs';
import LockFiles from '../guards/LockFiles.mjs';
import { LOCAL_POLICY_FILE, POLICY_FILE } from '../paths.mjs';

/**
 * `secure-npm validate [path]` - the other question: is what I already have
 * compromised. Reads the trees on disk against the malicious-package list;
 * nothing is resolved, nothing is fetched, and it fails closed.
 */
export default class Validate {
    static USAGE = `secure-npm validate - audit a tree against the malicious-package list

  secure-npm validate [path] [--monorepo]

  path         directory to audit, or a lockfile to audit directly (default: the current one)
  --monorepo   walk up to the repository root, then audit every manifest and lockfile below it

Both lockfiles are audited when both are present: whichever one was meant, the
other is on disk too, and a tree it installed is a tree that exists.

Exit code 1 when a compromised package is found, when a file cannot be read, or
when the list cannot be obtained - an unverifiable tree is not a clean one.
`;

    /**
     * Emptying the manager's own cache is the part that is easy to skip and the
     * part that matters: the tarball survives a deleted node_modules.
     */
    static #remediation(lockfiles) {
        const clean = [
            lockfiles.has(LockFiles.NPM_LOCK_FILE) && 'run "npm cache clean --force"',
            lockfiles.has(LockFiles.PNPM_LOCK_FILE) && 'run "pnpm store prune"',
        ].filter(Boolean);

        return `remove the dependency from package.json, delete ${[...lockfiles].join(' and ')} and node_modules, ${clean.join(' and ')}, then reinstall`;
    }

    /** @returns {{ files: string[], scope: string } | { error: string }} **/
    static #resolveTargets({ target, monorepo }) {
        if (!fs.existsSync(target)) return { error: `${target} does not exist` };

        if (fs.statSync(target).isFile()) {
            if (monorepo) return { error: '--monorepo needs a directory, not a file' };
            if (!LockFiles.INDEXABLE_FILES.includes(path.basename(target))) {
                return { error: `${target} is not one of ${LockFiles.INDEXABLE_FILES.join(', ')}` };
            }
            return { files: [target], scope: path.basename(target) };
        }

        if (monorepo) {
            const root = LockFiles.findRepositoryRoot(target);
            const files = LockFiles.findIndexableFiles(root);
            if (files.length === 0) return { error: `no manifest and no lockfile anywhere under ${root}` };
            return { files, scope: `the repository at ${root}` };
        }

        // Every lockfile that is there - narrowing to one manager's is a way to
        // miss the other. Manifests are left out: their ranges are not versions.
        const wanted = [LockFiles.NPM_LOCK_FILE, LockFiles.PNPM_LOCK_FILE];
        const files = wanted.map(name => path.join(target, name)).filter(file => fs.existsSync(file));

        if (files.length === 0) return { error: `no ${wanted.join(' and no ')} in ${target}` };
        return { files, scope: files.map(file => path.basename(file)).join(' + ') };
    }

    /** @returns {Promise<number>} **/
    static async run(argv, cwd = process.cwd()) {
        if (argv.includes('--help') || argv.includes('-h')) {
            Logger.write(this.USAGE);
            return 0;
        }

        const flags = new Set(argv.filter(argument => argument.startsWith('-')));
        const unknown = [...flags].filter(flag => flag !== '--monorepo');
        if (unknown.length) {
            Logger.writeErr(`secure-npm validate: unknown option "${unknown[0]}"\n\n${this.USAGE}`);
            return 2;
        }

        const positional = argv.find(argument => !argument.startsWith('-'));
        const target = path.resolve(cwd, positional ?? '.');

        const resolved = this.#resolveTargets({ target, monorepo: flags.has('--monorepo') });

        if (resolved.error) {
            Logger.writeErr(`secure-npm validate: ${resolved.error}\n\n${this.USAGE}`);
            return 2;
        }

        const policy = Policy.load();
        const { files, scope } = resolved;
        const context = { command: `secure-npm validate ${positional ?? '.'}`.trim(), cwd };

        Logger.banner({
            action: 'Auditing',
            command: scope,
            policyFiles: fs.existsSync(LOCAL_POLICY_FILE) ? [POLICY_FILE, LOCAL_POLICY_FILE] : [POLICY_FILE],
            extras: {
                list: policy.compromisedPackagesSource ?? 'none - "compromisedPackagesSource" is not set in policy.json',
                files: String(files.length),
            },
        });

        if (!policy.compromisedPackagesSource) {
            Logger.writeErr(
                '\nsecure-npm validate: there is nothing to validate against.\n' +
                    '  set "compromisedPackagesSource" in policy.json, then re-run "node installer.mjs".\n\n'
            );
            return 2;
        }

        const list = await Compromised.load(policy);
        const unavailable = Compromised.listViolation(list);
        if (unavailable) return System.abort({ ...context, phase: 'validate', violations: [unavailable] });

        Logger.info(`${list.count} known-malicious package(s), fetched ${Compromised.age(list.fetchedAt)} ago`);

        const violations = [];
        const hitFiles = new Set();

        for (const file of files) {
            const relative = path.relative(cwd, file);
            const label = relative && !relative.startsWith('..') ? relative : file;

            let index;
            try {
                index = LockFiles.indexFile(file);
            } catch (error) {
                // Fails closed: a file that cannot be read has not been cleared.
                violations.push({
                    rule: 'unreadable-file',
                    subject: label,
                    reason: error.message,
                    hint: 'fix or remove the file - it cannot be audited as it stands',
                });
                continue;
            }

            for (const { name, version, reason } of Compromised.find(list.index, index)) {
                if (path.basename(file) !== LockFiles.MANIFEST_FILE) hitFiles.add(path.basename(file));
                violations.push({ rule: 'compromised-package', subject: `${name}@${version} - ${label}`, reason });
            }
        }

        if (hitFiles.size) {
            const hint = this.#remediation(hitFiles);
            for (const violation of violations) {
                if (violation.rule === 'compromised-package') violation.hint = hint;
            }
        }

        if (violations.length) return System.abort({ ...context, phase: 'validate', violations });

        Logger.checked(`no compromised package in ${files.length} file(s)`);
        Logger.audit({ event: 'run', command: context.command, cwd, files, checked: files.length });
        return 0;
    }
}
