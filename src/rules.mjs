/**
 * The predicates every guard shares. Kept free of I/O so the pnpm hook, the
 * npm wrapper and the lockfile auditor all decide the same way.
 */

/**
 * Dependency ranges that resolve outside a registry. These carry no publish
 * date and no provenance attestation, so neither the release-age check nor
 * pnpm's trust policy can see them — they are the standard way around both.
 */
const EXOTIC_SPECIFIER = /^(git(\+[a-z]+)?:|git@|https?:|github:|gitlab:|bitbucket:)/;

/** `workspace:`, `catalog:`, `file:` and `link:` stay local — never fetched. */
const LOCAL_SPECIFIER = /^(workspace:|catalog:|file:|link:|portal:)/;

export function isExoticSpecifier(specifier) {
    if (typeof specifier !== 'string') return false;
    if (LOCAL_SPECIFIER.test(specifier)) return false;
    return EXOTIC_SPECIFIER.test(specifier);
}

/** Hosts whose plain https URLs npm resolves as git rather than as a tarball. */
const HOSTED_PROVIDERS = { github: 'github.com', gitlab: 'gitlab.com', bitbucket: 'bitbucket.org' };
const HOSTED_HOSTS = new Set(Object.values(HOSTED_PROVIDERS));

function repositoryIdentity(host, pathname) {
    if (!host || !pathname) return null;

    const cleaned = pathname
        .split(/[#?]/)[0] // the ref and the query say nothing about which repository this is
        .replace(/\.git$/i, '')
        .replace(/^\/+|\/+$/g, '');

    // No traversal: the whitelist matches one path segment at a time, and a
    // ".." segment is the one thing that could make two identities collide.
    if (!cleaned || cleaned.split('/').includes('..')) return null;

    return `${host.toLowerCase()}/${cleaned.toLowerCase()}`;
}

/**
 * The repository a git specifier or a lockfile resolution points at, reduced to
 * `host/owner/repo` — no protocol, no credentials, no `.git`, no ref. Every
 * form npm and pnpm accept collapses onto the same string, so the whitelist is
 * matched on the repository itself rather than on however it happened to be
 * spelled:
 *
 *   github:owner/repo#semver:^1.0.0
 *   git+ssh://git@github.com/owner/repo.git#a1b2c3d
 *   git@github.com:owner/repo.git
 *   https://github.com/owner/repo
 *                                     → github.com/owner/repo
 *
 * Returns null for anything that is not a git source — a raw tarball URL, an
 * unexpected host — which keeps those under `allowExoticSources` alone.
 */
export function gitSourceIdentity(specifier) {
    if (typeof specifier !== 'string' || specifier === '') return null;

    const shorthand = /^(github|gitlab|bitbucket):(.+)$/i.exec(specifier);
    if (shorthand) return repositoryIdentity(HOSTED_PROVIDERS[shorthand[1].toLowerCase()], shorthand[2]);

    // scp-like: git@host:owner/repo.git — a colon, not a protocol separator.
    if (!specifier.includes('://')) {
        const scp = /^[^@\s/]+@([^:/\s]+):(.+)$/.exec(specifier);
        return scp ? repositoryIdentity(scp[1], scp[2]) : null;
    }

    const url = /^(git\+[a-z0-9.+-]+|git|ssh|https?):\/\/([^/]+)\/(.+)$/i.exec(specifier);
    if (!url) return null;

    const [, scheme, authority, pathname] = url;
    const host = authority.slice(authority.lastIndexOf('@') + 1); // drop any embedded credentials

    // A plain http(s) URL is a tarball unless it says otherwise, or unless the
    // host is one npm always resolves as git.
    const isGit =
        /^(git|ssh)/i.test(scheme) || /\.git($|[#?])/i.test(specifier) || HOSTED_HOSTS.has(host.toLowerCase());
    if (!isGit) return null;

    return repositoryIdentity(host, pathname);
}

/**
 * Verdict for one exotic specifier or resolution.
 *
 * `identity` is returned even when the answer is no, so the block message can
 * name the exact string to whitelist instead of leaving the caller to guess it.
 *
 * @returns {{ allowed: boolean, identity: string | null }}
 */
export function exoticSourceVerdict(policy, specifier) {
    if (policy.allowExoticSources) return { allowed: true, identity: null };

    const identity = gitSourceIdentity(specifier);
    if (identity === null) return { allowed: false, identity: null };

    return { allowed: policy.allowedGitSources.some(({ pattern }) => pattern.test(identity)), identity };
}

/** Shared hint for a refused exotic source, copy-pasteable when we could name the repository. */
export function exoticSourceHint(identity) {
    return identity
        ? `add "${identity}" to "allowedGitSources" in policy.json if this repository is trusted`
        : 'install it from a registry, or add the repository to "allowedGitSources" in policy.json';
}

/**
 * `alias@npm:target@range` hides the real package name behind the key, which
 * would otherwise walk straight past a name-based block list.
 */
export function aliasTarget(specifier) {
    if (typeof specifier !== 'string' || !specifier.startsWith('npm:')) return null;
    const target = specifier.slice(4);
    const separator = target.lastIndexOf('@');
    return separator > 0 ? target.slice(0, separator) : target;
}

/** Real package name behind a (key, range) pair, following any alias. */
export function resolveName(key, specifier) {
    return aliasTarget(specifier) ?? key;
}

/** Returns the reason string when the package is blocked, otherwise null. */
export function blockedPackageReason(policy, name) {
    if (typeof name !== 'string') return null;
    return policy.blockedPackages.find(({ pattern }) => pattern.test(name))?.reason ?? null;
}

/** Returns the reason string when the command is a rejected manager. */
export function blockedManagerReason(policy, command) {
    return policy.blockedManagers.get(String(command).toLowerCase()) ?? null;
}

export function isAgeExempt(policy, name, version) {
    return policy.minimumReleaseAgeExclude.has(name) || policy.minimumReleaseAgeExclude.has(`${name}@${version}`);
}

/**
 * Registry a package should be fetched from, honouring per-scope overrides.
 * Returns null when the scope has no configured registry: the age check then
 * fails closed rather than silently querying the wrong host.
 */
export function registryFor(policy, name) {
    const scope = name.startsWith('@') ? name.slice(0, name.indexOf('/')) : null;
    if (scope) return policy.registries[scope] ?? null;
    return policy.registries.default ?? null;
}

/**
 * True when a lockfile `resolved` URL points somewhere other than a configured
 * registry — a git dependency, a raw tarball, or an unexpected host.
 */
export function isExoticResolution(policy, resolved) {
    if (typeof resolved !== 'string' || resolved === '') return false;
    if (resolved.startsWith('file:')) return false;
    if (/^(git(\+[a-z]+)?:|git@)/.test(resolved)) return true;

    const allowed = Object.values(policy.registries).filter(Boolean);
    return !allowed.some(registry => resolved.startsWith(registry.endsWith('/') ? registry : `${registry}/`));
}

/** Dependency fields pnpm and npm actually install for third-party packages. */
export const INSTALLED_FIELDS = ['dependencies', 'optionalDependencies'];

/** Adds the fields that only matter for manifests we author ourselves. */
export const AUTHORED_FIELDS = [...INSTALLED_FIELDS, 'devDependencies'];
