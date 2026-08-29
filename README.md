<!-- markdownlint-disable-next-line -->
<p align="center">
    <img width="200" src="https://raw.githubusercontent.com/Safari-digital/.github/refs/heads/main/assets/logo-2025.svg" alt="Safari Digital Logo">
</p>

<p align="center">
    Supply-chain guard rails around npm and pnpm, and a hard refusal for every other JS package manager.
</p>

---

secure-npm wraps npm and pnpm behind a shared supply-chain policy. Installed once per machine, it puts
shims first on PATH and registers a global pnpm hook, so every install is checked before the real package manager runs:

- a release must be at least three days old,
- lifecycle scripts never run,
- every resolved package is checked, at any depth, against a curated list of known-malicious releases,
- `git:` and tarball dependencies are refused unless their repository is whitelisted,
- blocked names are refused everywhere, and `bun`, `yarn` and `deno` are refused outright.

## Install

Requires Node 20.6+. Clone once per machine, then:

```bash
git clone git@github.com:Safari-digital/secure-npm.git && cd secure-npm && node installer.mjs
```

The installer announces everything it is about to touch - including prepending the shim directory to your
PATH *(on Windows the previous value is backed up next to the shims)* - and waits for a confirmation;
pass `-y` to answer it.

| What                  | Where                                                                                    |
|-----------------------|------------------------------------------------------------------------------------------|
| Runtime               | `%LOCALAPPDATA%\secure-npm\runtime` · `~/.local/share/secure-npm/runtime`                |
| Shims                 | `%LOCALAPPDATA%\secure-npm\bin` · `~/.local/share/secure-npm/bin`                        |
| Policy overlay        | `%LOCALAPPDATA%\secure-npm\policy.local.json` · `~/.config/secure-npm/policy.local.json` |
| pnpm config  + hook   | `%LOCALAPPDATA%\pnpm\config\config.yaml` · `~/.config/pnpm/config.yaml`                  |
| npm config            | `~/.npmrc` (managed block only, auth tokens are never touched)                           |
| Audit log             | `%LOCALAPPDATA%\secure-npm\logs` · `~/.local/state/secure-npm/logs`                      |
| Registry + list cache | `%LOCALAPPDATA%\secure-npm\cache` · `~/.cache/secure-npm`                                |

### Update

The runtime compares itself to the repository recorded at install time and offers to install anything
newer.

```bash
secure-npm --update
```

## Usage

There is no new command to learn. The shim directory sits ahead of Node's own on PATH, so `npm`, `npx`,
`pnpm` and `pnpx` *are* the guarded versions, **keep typing exactly what you typed before**. 

Open a new terminal
after installing, then every wrapped command announces the policy it is running under:

```
▸ secure-npm  Securely running pnpm add vite
              policy   ~/.local/share/secure-npm/runtime/policy.json + ~/.config/secure-npm/policy.local.json
              hook     ~/.local/share/secure-npm/runtime/hooks/pnpmfile.mjs
              binary   ~/.local/share/nvs/default/node_modules/pnpm/bin/pnpm.cjs
              audit    ~/.local/state/secure-npm/logs/audit.log
```

And when a rule fires, it says which one, on what, and why and then records it:

```
✖ secure-npm  BLOCKED  2 violations in npm install left-pad
              rule     release-too-recent
                       left-pad@1.3.1 - published 2026-08-05T09:12:44.001Z - 19h old, minimum is 72h
              hint     wait for the version to mature, or pin an older one
```

`bun`, `yarn` and `deno` are shimmed too, and refuse to run at all.

### Known-malicious packages

Every install is also checked against DataDog's
[malicious-software-packages-dataset](https://github.com/DataDog/malicious-software-packages-dataset), a curated
list of npm packages that have been caught. A name on it is refused wherever it appears on the command line,
in `package.json`, in either lockfile, and at any depth of the resolved tree:

```
✖ secure-npm  BLOCKED  1 violation in pnpm install
              rule     compromised-package
                       02-echo@0.0.7 - pnpm-lock.yaml - this exact version is listed as malicious
              hint     this package is on the malicious-package list - remove it, do not pin around it
```

The list is fetched once and cached for six hours. When a refresh fails the cached copy is used and said so out
loud; past a week without one, installs are refused rather than run unchecked. `secure-npm doctor` reports how
old the copy on this machine is.

### Auditing an existing tree

`validate` look for what is already compromised on disk by reading a lockfile and checking every version it pins against the same list. Nothing is resolved and nothing is installed, so it is safe to run anywhere, including in CI:

```bash
secure-npm validate                    # every lockfile in the current directory
secure-npm validate ./packages/web     # every lockfile in the given directory
secure-npm validate ./pnpm-lock.yaml   # that one file
secure-npm validate --monorepo         # walk up to the repository root, then audit everything below it
```

### Additional commands

```bash
secure-npm validate      # audit an existing tree against the malicious-package list
secure-npm doctor        # check that the guard rails are actually wired up
secure-npm edit-policy   # open this machine's overrides, creating them if needed
secure-npm log 20        # recent audit entries
secure-npm policy        # the effective policy, after the local overlay
secure-npm --update      # check the repository for a newer version, offer to install it
secure-npm --uninstall   # remove everything the installer put in place
```

## Configuration

| Key                                  | Meaning                                                                                                                                                          |
|--------------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `minimumReleaseAgeMinutes`           | how long a version must have existed (default 4320 = 3 days)                                                                                                     |
| `minimumReleaseAgeExclude`           | `name` or `name@version` entries exempt from the age check                                                                                                       |
| `trustPolicy`                        | pnpm only, `no-downgrade` or `off`                                                                                                                               |
| `trustPolicyIgnoreAfterMinutes`      | only check versions younger than this (default 90 days)                                                                                                          |
| `allowExoticSources`                 | permit `git:` / tarball dependencies                                                                                                                             |
| `allowedGitSources`                  | git repositories exempt from that, as `host/owner/repo`, `*` matching one path segment. Also exempt from the release-age check, which a commit has no answer for |
| `forceIgnoreScripts`                 | disable lifecycle scripts at install time                                                                                                                        |
| `compromisedPackagesSource`          | the malicious-package list every install is checked against. `""` switches the check off                                                                         |
| `compromisedPackagesRefreshMinutes`  | how long a fetched copy is used before it is refreshed (default 360 = 6 hours)                                                                                   |
| `compromisedPackagesMaxStaleMinutes` | how long a copy may still be used once a refresh has failed, after which installs are refused (default 10080 = 7 days)                                           |
| `blockedManagers`                    | commands the shims refuse outright                                                                                                                               |
| `blockedPackages`                    | name patterns refused at any depth, on both managers                                                                                                             |
| `registries`                         | approved registries per scope, an unlisted scope fails closed                                                                                                    |

## Uninstall

```bash
secure-npm --uninstall
```

Removes the deployed runtime and the shims. Beyond those, only files carrying the `managed by secure-npm`
marker are touched, so a hand-edited pnpm config or an `.npmrc` with credentials survives.
