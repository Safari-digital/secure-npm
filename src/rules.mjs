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
