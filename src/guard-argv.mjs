/**
 * The first gate: what the user typed.
 *
 * Two things are decided here. Whether the command is one that resolves new
 * code (and therefore needs the expensive checks), and whether the command
 * line itself tries to switch the policy off — pnpm accepts
 * `--config.minimumReleaseAge=0`, npm accepts `--no-ignore-scripts`, and both
 * accept `--registry`. A policy that any caller can disable is documentation,
 * not enforcement.
 */

import {
    blockedPackageReason,
    exoticSourceHint,
    exoticSourceVerdict,
    gitSourceIdentity,
    isExoticSpecifier,
} from './rules.mjs';

// Aliases included: npm accepts a generous set of them, and a command word we
// fail to recognise is a command that skips the checks.
const INSTALL_COMMANDS = {
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

const EXEC_COMMANDS = {
    npm: new Set(['exec', 'x', 'create', 'init']),
    pnpm: new Set(['dlx', 'exec', 'create']),
};

/** Commands that neither resolve nor fetch anything, listed so they classify cleanly. */
const INERT_COMMANDS = new Set([
    'run', 'run-script', 'test', 't', 'start', 'stop', 'restart', 'publish', 'pack',
    'version', 'view', 'v', 'info', 'show', 'ls', 'list', 'll', 'la', 'outdated',
    'audit', 'why', 'config', 'c', 'set', 'get', 'login', 'logout', 'whoami', 'ping',
    'help', 'root', 'bin', 'prefix', 'store', 'licenses', 'env', 'deploy', 'patch',
    'uninstall', 'remove', 'rm', 'un', 'unlink', 'r',
    'clean', 'prune', 'approve-builds', 'ignored-builds', 'patch-commit', 'patch-remove',
    'cat-file', 'cat-index', 'find-hash', 'runtime', 'rt', 'self-update', 'cache', 'doctor', 'init',
]);

/**
 * First argument that is a real command word.
 *
 * Scanning rather than taking `positionals[0]` is what makes
 * `pnpm --filter web add vite` classify as `add` instead of `web`: the value of
 * a flag such as `--filter` is a bare token too, and taking the first one would
 * hand the checks a package manager command they do not recognise, which is the
 * same as skipping them.
 */
function findCommand(family, positionals) {
    const known = name =>
        INSTALL_COMMANDS[family].has(name) || EXEC_COMMANDS[family].has(name) || INERT_COMMANDS.has(name);

    const index = positionals.findIndex(known);
    return index === -1 ? { command: '', index: -1 } : { command: positionals[index], index };
}

/** Flags that would relax or bypass the policy for this one invocation. */
const FORBIDDEN_FLAGS = {
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

/** Both managers accept `--registry`, which is the shortest path to a rogue mirror. */
function registryOverride(argv) {
    for (let index = 0; index < argv.length; index += 1) {
        const argument = argv[index];
        if (argument === '--registry') return argv[index + 1];
        if (argument.startsWith('--registry=')) return argument.slice('--registry='.length);
    }
    return null;
}

function splitTarget(raw) {
    if (isExoticSpecifier(raw)) {
        const identity = gitSourceIdentity(raw);

        // npm installs a bare git target under the repository's own package
        // name, which is the last path segment in every ordinary case. Only
        // used to exempt it from the release-age check, never to grant access.
        const gitName = identity ? identity.slice(identity.lastIndexOf('/') + 1) : null;

        return { raw, name: null, version: null, exotic: true, gitIdentity: identity, gitName };
    }

    const separator = raw.lastIndexOf('@');
    if (separator <= 0) return { raw, name: raw, version: null, exotic: false };

    return { raw, name: raw.slice(0, separator), version: raw.slice(separator + 1), exotic: false };
}

/**
 * Splits the command line into the pieces the guards need. Everything after a
 * bare `--` belongs to the script being run, not to the package manager.
 */
export function classify(manager, argv) {
    const ownArgv = argv.slice(0, argv.indexOf('--') === -1 ? argv.length : argv.indexOf('--'));
    const positionals = ownArgv.filter(argument => !argument.startsWith('-'));

    const isNpx = manager === 'npx' || manager === 'pnpx';
    const family = manager === 'npm' || manager === 'npx' ? 'npm' : 'pnpm';

    const found = isNpx ? { command: 'exec', index: -1 } : findCommand(family, positionals);
    const command = found.command;

    const isInstall = !isNpx && INSTALL_COMMANDS[family].has(command);
    const isExec = isNpx || EXEC_COMMANDS[family].has(command);

    // `npx pkg` takes its target first; `npm install pkg` takes it after the command.
    const targets = (isNpx ? positionals.slice(0, 1) : positionals.slice(found.index + 1)).map(splitTarget);

    return { family, command, isInstall, isExec, targets, ownArgv };
}

/**
 * @returns {{ rule: string, subject: string, reason: string, hint?: string }[]}
 */
export function inspectArgv(policy, manager, argv) {
    const { family, targets } = classify(manager, argv);
    const violations = [];

    for (const { match, reason } of FORBIDDEN_FLAGS[family]) {
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

    const registry = registryOverride(argv);
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
            const { allowed, identity } = exoticSourceVerdict(policy, target.raw);
            if (!allowed) {
                violations.push({
                    rule: 'exotic-source',
                    subject: identity ? `${target.raw} — ${identity}` : target.raw,
                    reason: 'git and tarball sources carry no publish date and no provenance',
                    hint: exoticSourceHint(identity),
                });
            }
            continue;
        }

        // Only name-based rules here. Whether a scope has a configured registry
        // is decided later, against packages that actually resolved: a bare
        // token on the command line may well be the value of `--filter` or
        // `--workspace` rather than something about to be installed.
        const reason = target.name && blockedPackageReason(policy, target.name);
        if (reason) violations.push({ rule: 'blocked-package', subject: target.raw, reason });
    }

    return violations;
}
