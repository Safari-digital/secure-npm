<!-- markdownlint-disable-next-line -->
<p align="center">
    <img width="200" src="https://raw.githubusercontent.com/Safari-digital/.github/refs/heads/main/assets/logo-2025.svg" alt="Safari Digital Logo">
</p>

<p align="center">
    Supply-chain guard rails around npm and pnpm, and a hard refusal for every other JS package manager.
</p>

---

A compromised package hurts at two moments: when its install script runs, and when a freshly published
malicious version reaches your machine before anyone has noticed. 

**pnpm 11** defends against both natively; npm has no release-age check, no provenance check and no resolution hook. 

This repository closes that gap and applies the same rules to both: a version must have existed for three days before it can be installed, a
version published with weaker guarantees than an earlier one is refused, lifecycle scripts never run, `git:`
and tarball dependencies are rejected, blocked names are refused at any depth, and `bun`, `yarn` and `deno`
are refused outright.

## Install

Requires Node 20.6+. Clone once per machine, then:

```bash
git clone git@github.com:Safari-digital/secure-npm.git && cd secure-npm && node install.mjs --set-path
```

`--set-path` prepends the shim directory to your user PATH *(the previous value is backed up next to the
shims)*. Drop it to have the installer print the directory and leave PATH alone. Nothing is copied out of the
repository, every generated file points back here, so `git pull` is the whole update procedure.

| What                      | Where                                                                   |
|---------------------------|-------------------------------------------------------------------------|
| Shims                     | `%LOCALAPPDATA%\secure-npm\bin` · `~/.local/share/secure-npm/bin`       |
| pnpm global config + hook | `%LOCALAPPDATA%\pnpm\config\config.yaml` · `~/.config/pnpm/config.yaml` |
| npm config                | `~/.npmrc` (managed block only, auth tokens are never touched)          |
| Audit log                 | `%LOCALAPPDATA%\secure-npm\logs` · `~/.local/state/secure-npm/logs`     |

## Usage

There is no new command to learn. The shim directory sits ahead of Node's own on PATH, so `npm`, `npx`,
`pnpm` and `pnpx` *are* the guarded versions, **keep typing exactly what you typed before**. 

Open a new terminal
after installing, then every wrapped command announces the policy it is running under:

```
▸ secure-npm  Securely running pnpm add vite
              policy   ~/.sources/safari-digital/secure-npm/policy.json
              hook     ~/.sources/safari-digital/secure-npm/hooks/pnpmfile.mjs
              binary   ~/.local/share/nvs/default/node_modules/pnpm/bin/pnpm.cjs
              audit    ~/.local/state/secure-npm/logs/audit.log
```

And when a rule fires, it says which one, on what, and why and then records it:

```
✖ secure-npm  BLOCKED  2 violations in npm install left-pad
              rule     release-too-recent
                       left-pad@1.3.1 — published 2026-08-05T09:12:44.001Z — 19h old, minimum is 72h
              hint     wait for the version to mature, or pin an older one
```

`bun`, `yarn` and `deno` are shimmed too, and refuse to run at all.

### Additional commands
> The tool's own commands are not shimmed, run them from the clone:

```bash
node bin/secure-npm.mjs doctor      # check that the guard rails are actually wired up
node bin/secure-npm.mjs log 20      # recent audit entries
node bin/secure-npm.mjs policy      # the effective policy, after the local overlay
```

## Configuration

`policy.json` is the shared ruleset. Machine-specific overrides go in `policy.local.json` (git-ignored),
shallow-merged on top. After editing, re-run `node install.mjs` so pnpm's config picks up the change, then
`doctor`.

| Key                             | Meaning                                                       |
|---------------------------------|---------------------------------------------------------------|
| `minimumReleaseAgeMinutes`      | how long a version must have existed (default 4320 = 3 days)  |
| `minimumReleaseAgeExclude`      | `name` or `name@version` entries exempt from the age check    |
| `trustPolicy`                   | pnpm only, `no-downgrade` or `off`                            |
| `trustPolicyIgnoreAfterMinutes` | only check versions younger than this (default 90 days)       |
| `allowExoticSources`            | permit `git:` / tarball dependencies                          |
| `forceIgnoreScripts`            | disable lifecycle scripts at install time                     |
| `blockedManagers`               | commands the shims refuse outright                            |
| `blockedPackages`               | name patterns refused at any depth, on both managers          |
| `registries`                    | approved registries per scope, an unlisted scope fails closed |

## Uninstall

```bash
node uninstall.mjs --set-path
```

Only files carrying the `managed by secure-npm` marker are touched, so a hand-edited pnpm config or an
`.npmrc` with credentials survives.
