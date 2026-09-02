import Rules from '../policy/Rules.mjs';
import ManifestGuard from './ManifestGuard.mjs';

export default class ArgvGuard {
    // Aliases included: a command word we fail to recognize is a command that skips the checks
    static #INSTALL_COMMANDS = {
        npm: new Set([
            'install', 'i', 'in', 'ins', 'inst', 'insta', 'instal', 'isntall',
            'add', 'ci', 'clean-install', 'install-clean', 'install-test', 'it',
            'install-ci-test', 'cit', 'update', 'up', 'upgrade', 'udpate',
            'dedupe', 'ddp', 'link', 'ln', 'rebuild', 'rb',
        ]),
        pnpm: new Set([
            'install', 'i', 'add', 'update', 'up', 'upgrade', 'import',
            'ci', 'clean-install', 'ic', 'install-clean', 'install-test', 'it',
            'link', 'ln', 'fetch', 'dedupe', 'rebuild', 'rb',
        ]),
    };

    static #EXEC_COMMANDS = {
        npm: new Set(['exec', 'x', 'create', 'init']),
        pnpm: new Set(['dlx', 'exec', 'create']),
    };

    static #INERT_COMMANDS = new Set([
        'run', 'run-script', 'test', 't', 'start', 'stop', 'restart', 'publish', 'pack',
        'version', 'view', 'v', 'info', 'show', 'ls', 'list', 'll', 'la', 'outdated',
        'audit', 'why', 'config', 'c', 'set', 'get', 'login', 'logout', 'whoami', 'ping',
        'help', 'root', 'bin', 'prefix', 'store', 'licenses', 'env', 'deploy', 'patch',
        'uninstall', 'remove', 'rm', 'un', 'unlink', 'r',
        'clean', 'prune', 'approve-builds', 'ignored-builds', 'patch-commit', 'patch-remove',
        'cat-file', 'cat-index', 'find-hash', 'runtime', 'rt', 'self-update', 'cache', 'doctor', 'init',
    ]);

    static #FORBIDDEN_FLAGS = {
        npm: [
            { match: /^--no-ignore-scripts$/, reason: 're-enables lifecycle scripts' },
            { match: /^--ignore-scripts=false$/, reason: 're-enables lifecycle scripts' },
            { match: /^--foreground-scripts(=true)?$/, reason: 'runs lifecycle scripts in the foreground' },
            { match: /^--script-shell(=.*)?$/, reason: 'redirects lifecycle scripts to another shell' },
            { match: /^--unsafe-perm(=true)?$/, reason: 'drops the install-time privilege guard' },
        ],
        pnpm: [
            { match: /^--config\.(minimum-release-age|minimumReleaseAge)/i, reason: 'overrides the release-age policy' },
            { match: /^--config\.(trust-policy|trustPolicy)/i, reason: 'overrides the trust policy' },
            { match: /^--config\.(ignore-scripts|ignoreScripts)/i, reason: 'overrides the lifecycle-script policy' },
            { match: /^--config\.(block-exotic-subdeps|blockExoticSubdeps)/i, reason: 'overrides the exotic-source policy' },
            { match: /^--config\.(global-pnpmfile|globalPnpmfile)/i, reason: 'replaces the policy hook' },
            { match: /^--ignore-pnpmfile$/, reason: 'disables the policy hook' },
            { match: /^--pnpmfile(=.*)?$/, reason: 'replaces the policy hook' },
            { match: /^--(dangerously-allow-all-builds|allow-build)(=.*)?$/, reason: 'allows arbitrary install-time builds' },
            { match: /^--no-verify-store-integrity$/, reason: 'disables store integrity verification' },
            { match: /^--no-strict-dep-builds$/, reason: 'silences skipped-build errors' },
        ],
    };

    /**
     * @param {string} family
     * @param {string[]} positional
     */
    static #findCommand(family, positional) {
        const known = name =>
            this.#INSTALL_COMMANDS[family].has(name) ||
            this.#EXEC_COMMANDS[family].has(name) ||
            this.#INERT_COMMANDS.has(name);

        const index = positional.findIndex(known);
        return index === -1 ? { command: '', index: -1 } : { command: positional[index], index };
    }

    static #registryOverride(argv) {
        for (let index = 0; index < argv.length; index += 1) {
            const argument = argv[index];
            if (argument === '--registry') return argv[index + 1];
            if (argument.startsWith('--registry=')) return argument.slice('--registry='.length);
        }
        return null;
    }

    static #splitTarget(raw) {
        if (Rules.isExoticSpecifier(raw)) {
            const identity = Rules.gitSourceIdentity(raw);

            // npm installs a bare git target under the repository's last path
            // segment; only used to exempt it from the age check.
            const gitName = identity ? identity.slice(identity.lastIndexOf('/') + 1) : null;
            return { raw, name: null, version: null, exotic: true, gitIdentity: identity, gitName };
        }

        const separator = raw.lastIndexOf('@');
        if (separator <= 0) return { raw, name: raw, version: null, exotic: false };

        return { raw, name: raw.slice(0, separator), version: raw.slice(separator + 1), exotic: false };
    }

    /**
     * @param {'npm' | 'npx' | 'pnpm' | 'pnpx'} manager
     * @param {string[]} argv
     * @returns {{
     *      family: 'npm' | 'pnpm',
     *      command: string,
     *      isInstall: boolean,
     *      isExec: boolean,
     *      targets: Object[],
     *      ownArgv: string[],
     *      positional: string[]
     *  }}
     */
    static classify(manager, argv) {
        const ownArgv = argv.slice(0, argv.indexOf('--') === -1 ? argv.length : argv.indexOf('--'));
        const positional = ownArgv.filter(argument => !argument.startsWith('-'));

        const isNpx = manager === 'npx' || manager === 'pnpx';
        const family = manager === 'npm' || manager === 'npx' ? 'npm' : 'pnpm';

        const found = isNpx ? { command: 'exec', index: -1 } : this.#findCommand(family, positional);
        const command = found.command;

        const isInstall = !isNpx && this.#INSTALL_COMMANDS[family].has(command);
        const isExec = isNpx || this.#EXEC_COMMANDS[family].has(command);

        // `npx pkg` takes its target first; `npm install pkg` after the command.
        const targets = (isNpx ? positional.slice(0, 1) : positional.slice(found.index + 1)).map(target =>
            this.#splitTarget(target)
        );

        return { family, command, isInstall, isExec, targets, ownArgv, positional };
    }

    /** @returns {{ reason: string, hint: string } | null} **/
    static unknownCommandReason(manager, argv, cwd) {
        const { command, positional } = this.classify(manager, argv);
        if (command !== '' || positional.length === 0) return null;

        const local = ManifestGuard.scriptNames(cwd);
        if (positional.some(word => local.has(word))) return null;

        const workspace = ManifestGuard.workspaceScriptNames(cwd);
        if (positional.some(word => workspace.has(word))) return null;

        return {
            reason: `"${positional.join(' ')}" is neither a command this wrapper knows nor a script in this project`,
            hint: 'no install checks ran - if that command installs anything, this tool is blind to it',
        };
    }

    /** @returns {import('../system/System.mjs').Violation[]} **/
    static inspect(policy, manager, argv) {
        const { family, targets } = this.classify(manager, argv);
        const violations = [];

        for (const { match, reason } of this.#FORBIDDEN_FLAGS[family]) {
            const offender = argv.find(argument => match.test(argument));
            if (offender) {
                violations.push({
                    rule: 'policy-override-flag',
                    subject: offender,
                    reason: `the flag ${reason}`,
                    hint: 'change policy.json if the rule itself is wrong; do not bypass it per command',
                });
            }
        }

        const registry = this.#registryOverride(argv);
        if (registry) {
            const approved = Object.values(policy.registries).some(
                allowed => allowed && registry.replace(/\/$/, '') === allowed.replace(/\/$/, '')
            );
            if (!approved) {
                violations.push({
                    rule: 'unapproved-registry',
                    subject: `--registry ${registry}`,
                    reason: 'this registry is not listed in the policy',
                    hint: 'add it under "registries" in policy.json if it is legitimate',
                });
            }
        }

        for (const target of targets) {
            if (target.exotic) {
                const { allowed, identity } = Rules.exoticSourceVerdict(policy, target.raw);
                if (!allowed) {
                    violations.push({
                        rule: 'exotic-source',
                        subject: identity ? `${target.raw} - ${identity}` : target.raw,
                        reason: 'git and tarball sources carry no publish date and no provenance',
                        hint: Rules.exoticSourceHint(identity),
                    });
                }
                continue;
            }

            const manager = family === 'pnpm' && target.name && Rules.blockedManagerReason(policy, target.name);
            if (manager) {
                violations.push({
                    rule: 'blocked-manager',
                    subject: target.raw,
                    reason: manager,
                    hint: `pnpm would record "${target.name}" as the project's "packageManager" instead of installing it - edit "blockedManagers" in policy.json if it should be allowed`,
                });
                continue;
            }

            const reason = target.name && Rules.blockedPackageReason(policy, target.name);
            if (reason) {
                violations.push({
                    rule: 'blocked-package',
                    subject: target.raw,
                    reason,
                    hint: Rules.BLOCKED_BY_NAME_HINT,
                });
            }
        }

        return violations;
    }
}
