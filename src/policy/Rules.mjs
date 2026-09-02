/** @typedef {import('./Policy.mjs').PolicyConfig} PolicyConfig **/

const EXOTIC_SPECIFIER = /^(git(\+[a-z]+)?:|git@|https?:|github:|gitlab:|bitbucket:)/;
const LOCAL_SPECIFIER = /^(workspace:|catalog:|file:|link:|portal:)/;

const HOSTED_PROVIDERS = { github: 'github.com', gitlab: 'gitlab.com', bitbucket: 'bitbucket.org' };
const HOSTED_HOSTS = new Set(Object.values(HOSTED_PROVIDERS));

export default class Rules {
    static INSTALLED_FIELDS = ['dependencies', 'optionalDependencies'];
    static AUTHORED_FIELDS = [...this.INSTALLED_FIELDS, 'devDependencies'];

    static isExoticSpecifier(specifier) {
        if (typeof specifier !== 'string') return false;
        if (LOCAL_SPECIFIER.test(specifier)) return false;
        return EXOTIC_SPECIFIER.test(specifier);
    }

    static #repositoryIdentity(host, pathname) {
        if (!host || !pathname) return null;

        const cleaned = pathname
            .split(/[#?]/)[0]
            .replace(/\.git$/i, '')
            .replace(/^\/+|\/+$/g, '');

        if (!cleaned || cleaned.split('/').includes('..')) return null;

        return `${host.toLowerCase()}/${cleaned.toLowerCase()}`;
    }

    /**
     * Git specifier or lockfile resolution reduced to `host/owner/repo`, so the
     * whitelist matches the repository rather than how it was spelled.
     * Null for anything that is not a git source.
     *
     * @param {string} specifier
     * @returns {string | null}
     */
    static gitSourceIdentity(specifier) {
        if (typeof specifier !== 'string' || specifier === '') return null;

        const shorthand = /^(github|gitlab|bitbucket):(.+)$/i.exec(specifier);
        if (shorthand) return this.#repositoryIdentity(HOSTED_PROVIDERS[shorthand[1].toLowerCase()], shorthand[2]);

        if (!specifier.includes('://')) {
            const scp = /^[^@\s/]+@([^:/\s]+):(.+)$/.exec(specifier);
            return scp ? this.#repositoryIdentity(scp[1], scp[2]) : null;
        }

        const url = /^(git\+[a-z0-9.+-]+|git|ssh|https?):\/\/([^/]+)\/(.+)$/i.exec(specifier);
        if (!url) return null;

        const [, scheme, authority, pathname] = url;
        const host = authority.slice(authority.lastIndexOf('@') + 1);

        const isGit =
            /^(git|ssh)/i.test(scheme) || /\.git($|[#?])/i.test(specifier) || HOSTED_HOSTS.has(host.toLowerCase());
        if (!isGit) return null;

        return this.#repositoryIdentity(host, pathname);
    }

    /**
     * `identity` is returned even on a no, so the block message can name the
     * exact string to whitelist.
     *
     * @param {PolicyConfig} policy
     * @param {string} specifier
     * @returns {{ allowed: boolean, identity: string | null }}
     */
    static exoticSourceVerdict(policy, specifier) {
        if (policy.allowExoticSources) return { allowed: true, identity: null };

        const identity = this.gitSourceIdentity(specifier);
        if (identity === null) return { allowed: false, identity: null };

        return { allowed: policy.allowedGitSources.some(({ pattern }) => pattern.test(identity)), identity };
    }

    /** @param {string | null} identity **/
    static exoticSourceHint(identity) {
        return identity
            ? `add "${identity}" to "allowedGitSources" in policy.json if this repository is trusted`
            : 'install it from a registry, or add the repository to "allowedGitSources" in policy.json';
    }

    static aliasTarget(specifier) {
        if (typeof specifier !== 'string' || !specifier.startsWith('npm:')) return null;
        const target = specifier.slice(4);
        const separator = target.lastIndexOf('@');
        return separator > 0 ? target.slice(0, separator) : target;
    }

    static resolveName(key, specifier) {
        return this.aliasTarget(specifier) ?? key;
    }

    /**
     * @param {PolicyConfig} policy
     * @param {string} name
     * @returns {string | null} The reason when the package is blocked.
     */
    static blockedPackageReason(policy, name) {
        if (typeof name !== 'string') return null;
        return policy.blockedPackages.find(({ pattern }) => pattern.test(name))?.reason ?? null;
    }

    /**
     * @param {PolicyConfig} policy
     * @param {string} name
     * @param {string | null} [version]
     */
    static isBlockExempt(policy, name, version = null) {
        if (typeof name !== 'string') return false;
        if (policy.blockedPackagesExclude.has(name)) return true;
        if (version) return policy.blockedPackagesExclude.has(`${name}@${version}`);

        const prefix = `${name}@`;
        for (const entry of policy.blockedPackagesExclude) if (entry.startsWith(prefix)) return true;

        return false;
    }

    /**
     * `blockedPackageReason` for a package that arrived as somebody else's
     * dependency, which is the only thing `blockedPackagesExclude` waives.
     * A package asked for by name - a command-line target, or a dependency of
     * the manifest being installed - stays on `blockedPackageReason`: accepting
     * what a dependency drags in is not the same decision as choosing to
     * install the thing.
     *
     * That split is about intent rather than reach. A waived package still has
     * to get past `blockedManagers` before anything can run it, and that list
     * is untouched by this one.
     *
     * @param {PolicyConfig} policy
     * @param {string} name
     * @param {string | null} [version]
     * @returns {string | null} The reason when the package is blocked.
     */
    static dependencyBlockReason(policy, name, version = null) {
        const reason = this.blockedPackageReason(policy, name);
        if (reason === null) return null;

        return this.isBlockExempt(policy, name, version) ? null : reason;
    }

    static blockedPackageHint(name, version = null) {
        const entry = version ? `${name}@${version}` : name;
        return `add "${entry}" to "blockedPackagesExclude" in policy.json if this dependency is expected`;
    }

    static BLOCKED_BY_NAME_HINT =
        '"blockedPackagesExclude" only covers a package pulled in as a dependency, which this one is not - edit "blockedPackages" in policy.json if it should be allowed outright';

    /**
     * @param {PolicyConfig} policy
     * @param {string} command
     * @returns {string | null} The reason when the command is a rejected manager.
     */
    static blockedManagerReason(policy, command) {
        return policy.blockedManagers.get(String(command).toLowerCase()) ?? null;
    }

    static isAgeExempt(policy, name, version) {
        return (
            policy.minimumReleaseAgeExclude.has(name) || policy.minimumReleaseAgeExclude.has(`${name}@${version}`)
        );
    }

    /**
     * Registry for a package, honouring per-scope overrides. Null when the scope
     * has none configured: the age check then fails closed.
     *
     * @param {PolicyConfig} policy
     * @param {string} name
     * @returns {string | null}
     */
    static registryFor(policy, name) {
        const scope = name.startsWith('@') ? name.slice(0, name.indexOf('/')) : null;
        if (scope) return policy.registries[scope] ?? null;
        return policy.registries.default ?? null;
    }

    static isExoticResolution(policy, resolved) {
        if (typeof resolved !== 'string' || resolved === '') return false;
        if (resolved.startsWith('file:')) return false;
        if (/^(git(\+[a-z]+)?:|git@)/.test(resolved)) return true;

        const allowed = Object.values(policy.registries).filter(Boolean);
        return !allowed.some(registry => resolved.startsWith(registry.endsWith('/') ? registry : `${registry}/`));
    }
}
