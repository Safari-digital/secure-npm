# secure-npm

Supply-chain guard rails around `npm` and `pnpm`, and a hard refusal for every other JS package manager.

Zero runtime dependencies — a tool meant to protect you from npm packages should not install any.

## Why

A compromised package hurts at two moments: when its install script runs, and when a freshly published
malicious version reaches your machine before anyone has noticed. pnpm 11 can defend against both natively.
npm cannot: it has no release-age check, no provenance check, and no resolution hook.

This repository closes that gap, applies the same rules to both managers, and makes them visible on every
command instead of silently doing nothing when a config file has drifted.

## What is enforced

| Rule                    | npm                                      | pnpm                                     |
| ----------------------- | ---------------------------------------- | ---------------------------------------- |
| Minimum release age     | wrapper queries the registry             | native (`minimumReleaseAge`, strict)     |
| Trust downgrade         | —                                        | native (`trustPolicy: no-downgrade`)     |
| No install scripts      | `.npmrc` + forced `--ignore-scripts`     | native (`ignoreScripts`)                 |
| No git / tarball source | wrapper (argv, manifest, lockfile)       | native + resolution hook                 |
| Blocked package names   | wrapper (argv, manifest, lockfile)       | resolution hook                          |
| Blocked managers        | shim refuses `bun`, `yarn`, `deno`, …    | same                                     |
| Policy cannot be waived | wrapper rejects override flags           | wrapper rejects override flags           |

**Minimum release age** is the main defence: a version must have existed for three days before it may be
installed. Most publish-token compromises are caught and unpublished well inside that window.

**Trust downgrade** is the one check that catches a poisoned version on day zero: if any earlier-published
version of a package carried provenance or a trusted publisher and the new one does not, the install stops.
That is what a stolen publish token looks like from the outside.

## Install

Requires Node 20.6+. Clone once per machine, then:

```bash
git clone git@github.com:digital-net-org/secure-npm.git && cd secure-npm && node install.mjs --set-path
```

The installer writes four things and copies nothing out of the repository — every generated file points back
here, so `git pull` is the whole update procedure.

| What                      | Where                                                                    |
| ------------------------- | ------------------------------------------------------------------------ |
| Shims                     | `%LOCALAPPDATA%\secure-npm\bin` · `~/.local/share/secure-npm/bin`         |
| pnpm global config + hook | `%LOCALAPPDATA%\pnpm\config\config.yaml` · `~/.config/pnpm/config.yaml`   |
| npm config                | `~/.npmrc` (managed block only — auth tokens are never touched)           |
| Audit log                 | `%LOCALAPPDATA%\secure-npm\logs` · `~/.local/state/secure-npm/logs`       |

`--set-path` prepends the shim directory to your user PATH (the previous value is backed up next to the
shims). Drop it to have the installer print the directory and leave PATH alone. Open a new terminal
afterwards, then check the result:

```bash
secure-npm doctor
```

`doctor` is not decoration. Every layer here fails open when it is not wired up — a shim that is not on PATH,
a pnpm config someone overwrote, an `.npmrc` that lost its line. Run it after installing, and after anything
that rewrites your shell profile.

## What it looks like

Every wrapped command announces the policy it is running under:

```
▸ secure-npm  Securely running pnpm add vite
              policy   ~/.sources/digital-net-org/secure-npm/policy.json
              hook     ~/.sources/digital-net-org/secure-npm/hooks/pnpmfile.mjs
              binary   ~/.local/share/nvs/default/node_modules/pnpm/bin/pnpm.cjs
              audit    ~/.local/state/secure-npm/logs/audit.log
```

And when a rule fires, it says which one, on what, and why — then records it:

```
✖ secure-npm  BLOCKED  2 violations in npm install left-pad
              rule     release-too-recent
                       left-pad@1.3.1 — published 2026-08-05T09:12:44.001Z — 19h old, minimum is 72h
              hint     wait for the version to mature, or pin an older one
```

```bash
secure-npm log 20     # recent audit entries
secure-npm policy     # the effective policy, after the local overlay
```

## How it works

```
npm / pnpm / bun / yarn / deno          ← what you type
        │
   shim on PATH                          ← %LOCALAPPDATA%\secure-npm\bin
        │
   bin/secure-npm.mjs                    ← routes on the name that was typed
        │
        ├─ blocked manager  → refuse, log, exit
        │
        ├─ npm  → argv guard → manifest guard → resolution preview → real npm → lockfile audit
        │
        └─ pnpm → argv guard → manifest guard → real pnpm
                                                  └─ hooks/pnpmfile.mjs (loaded by pnpm itself)
```

For **npm**, the wrapper does the work npm will not. It asks npm what it *would* install
(`--dry-run --json`, which writes neither `node_modules` nor the lockfile), checks that set against the
policy, and only then runs the real command. Nothing reaches disk before the verdict. `npm ci` is checked
against `package-lock.json` instead, because its dry-run report is empty when `node_modules` already exists.

For **pnpm**, the settings written to pnpm's global config do the enforcement. The wrapper's job is narrower:
show the policy, refuse flags that would switch it off, and warn if the config has gone missing.

`hooks/pnpmfile.mjs` is loaded by pnpm itself, so it keeps enforcing the block list even when pnpm is invoked
by its absolute path and the shim never sees the call. It prints its own banner in that case.

## Configuration

`policy.json` is the shared ruleset — versioned, so every machine enforces the same thing. Machine-specific
overrides go in `policy.local.json` (git-ignored), shallow-merged on top.

| Key                             | Meaning                                                              |
| ------------------------------- | -------------------------------------------------------------------- |
| `minimumReleaseAgeMinutes`      | how long a version must have existed (default 4320 = 3 days)          |
| `minimumReleaseAgeExclude`      | `name` or `name@version` entries exempt from the age check            |
| `trustPolicy`                   | pnpm only — `no-downgrade` or `off`                                   |
| `trustPolicyIgnoreAfterMinutes` | only check versions younger than this (default 90 days, see below)    |
| `allowExoticSources`            | permit `git:` / tarball dependencies                                  |
| `forceIgnoreScripts`            | disable lifecycle scripts at install time                             |
| `blockedManagers`               | commands the shims refuse outright                                    |
| `blockedPackages`               | name patterns refused at any depth, on both managers                  |
| `registries`                    | approved registries, per scope — an unlisted scope fails closed       |

After editing, re-run `node install.mjs` so pnpm's config picks up the change, then `secure-npm doctor`.

`trustPolicyIgnoreAfterMinutes` exists because the trust check compares by *publish date*, not semver: a
backport onto an old branch is published after a newer release that carried provenance, and gets flagged.
Bounding the check to recent releases keeps it on the window where the risk actually is.

## When something is blocked

Fix the policy, not the command. Every bypass flag — `--config.minimumReleaseAge=0`, `--no-ignore-scripts`,
`--ignore-pnpmfile`, an unapproved `--registry` — is rejected on purpose, because a policy any caller can
switch off is documentation rather than enforcement.

- **`release-too-recent`** — wait, or add `name@version` to `minimumReleaseAgeExclude` once you have looked
  at what changed.
- **`blocked-package`** — if it is a false positive, narrow the pattern in `blockedPackages`.
- **`exotic-source`** — publish the dependency to a registry, or set `allowExoticSources` if you own it.
- **`unknown-scope-registry`** — add the scope under `registries`.

## Limits

Worth knowing, because none of these are covered:

- **Build time is not install time.** Blocking install scripts does not stop `vite`, `eslint` or `vitest`
  from executing dependency code the moment you run them. This narrows the window, it does not close it.
- **No filesystem sandbox.** Nothing here confines what a process can write once it runs.
- **PATH is the enforcement point for npm.** A tool calling npm by absolute path skips the wrapper, and with
  it the age check — `~/.npmrc` still blocks scripts, and for pnpm the hook still applies.
- **A cold `npm ci` on a large tree is slow.** One registry lookup per package, eight at a time, cached for
  an hour afterwards. pnpm does this natively and much faster.
- **Authenticated registries are not supported** for the age check yet; an unlisted scope fails closed.
- **Blocked managers already installed remain reachable by absolute path.** `doctor` reports any it finds.

## Uninstall

```bash
node uninstall.mjs --set-path
```

Only files carrying the `managed by secure-npm` marker are touched, so a hand-edited pnpm config or an
`.npmrc` with credentials survives.

## Layout

```
bin/secure-npm.mjs     entry point, routes on the invoked name
hooks/pnpmfile.mjs     pnpm resolution hook (loaded by pnpm, not by us)
src/policy.mjs         policy.json + policy.local.json
src/rules.mjs          the predicates every guard shares
src/guard-argv.mjs     command line: bypass flags, blocked targets
src/guard-manifest.mjs package.json
src/guard-npm.mjs      npm dry-run preview, release age, lockfile audit
src/registry.mjs       publish dates, with an on-disk cache
src/run-*.mjs          one runner per route
src/self.mjs           doctor / log / policy / version
install.mjs            shims, pnpm config, .npmrc, PATH
```
