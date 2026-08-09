/**
 * Every filesystem location the tool uses, resolved once, for Windows and POSIX.
 *
 * Three roots, deliberately distinct:
 *
 *   moduleRoot   the copy of the code that is currently running — the repository
 *                when a command is started from a clone, the deployed runtime
 *                when it is started through a shim or by pnpm,
 *   runtimeRoot  the copy the installer deploys, and the only one the shims,
 *                pnpm's global config and the hook ever point at,
 *   configDir    the machine-local policy overlay, which is not versioned and so
 *                has no business living inside the repository.
 *
 * The repository is therefore a source tree and nothing else: nothing outside it
 * refers back to it, and moving or deleting a clone cannot disarm the machine.
 */

import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const IS_WINDOWS = process.platform === 'win32';
const IS_MACOS = process.platform === 'darwin';

const localAppData = () => process.env.LOCALAPPDATA ?? path.join(os.homedir(), 'AppData', 'Local');

/** Root of the tree this file belongs to — this file lives in <root>/src. */
export const moduleRoot = path.resolve(fileURLToPath(import.meta.url), '..', '..');

/** Deployed program: the runtime the installer copies, plus the shims. */
const dataHome = IS_WINDOWS
    ? path.join(localAppData(), 'secure-npm')
    : path.join(process.env.XDG_DATA_HOME ?? path.join(os.homedir(), '.local', 'share'), 'secure-npm');

/**
 * The deployed copy of the runtime. Replaced wholesale on every install, so
 * nothing here is ever worth editing by hand — `doctor` reports it as stale the
 * moment it stops matching the source it came from.
 */
export const runtimeRoot = path.join(dataHome, 'runtime');

/** Records what was deployed and from where. Written by `deployRuntime`. */
export const runtimeStampFile = path.join(runtimeRoot, '.secure-npm-runtime');

/**
 * Where shims live. Prepended to PATH so `npm` and `pnpm` resolve here first,
 * and so blocked managers resolve to a refusal instead of a real binary.
 */
export const binDir = path.join(dataHome, 'bin');

/**
 * Marker dropped next to the shims. `which.mjs` skips any PATH entry holding
 * one, which is what stops a shim from resolving to itself.
 */
export const shimMarkerFile = path.join(binDir, '.secure-npm-shims');

/** Hand-edited configuration, never touched by the installer. */
export const configDir = IS_WINDOWS
    ? path.join(localAppData(), 'secure-npm')
    : path.join(process.env.XDG_CONFIG_HOME ?? path.join(os.homedir(), '.config'), 'secure-npm');

export const localPolicyFile = path.join(configDir, 'policy.local.json');

/** Where the overlay used to live. The installer moves it out and says so. */
export const legacyLocalPolicyFile = path.join(moduleRoot, 'policy.local.json');

/**
 * The shared ruleset, read from whichever copy is running: the repository for
 * the installer, the deployed runtime for everything else.
 */
export const policyFile = path.join(moduleRoot, 'policy.json');

/** The same file inside the deployed runtime — what the guard rails actually read. */
export const runtimePolicyFile = path.join(runtimeRoot, 'policy.json');

export const pnpmHookFile = path.join(runtimeRoot, 'hooks', 'pnpmfile.mjs');
export const entryPoint = path.join(runtimeRoot, 'bin', 'secure-npm.mjs');

const stateHome = IS_WINDOWS
    ? path.join(localAppData(), 'secure-npm')
    : path.join(process.env.XDG_STATE_HOME ?? path.join(os.homedir(), '.local', 'state'), 'secure-npm');

export const logDir = path.join(stateHome, 'logs');
export const auditLogFile = path.join(logDir, 'audit.log');

export const cacheDir = IS_WINDOWS
    ? path.join(localAppData(), 'secure-npm', 'cache')
    : path.join(process.env.XDG_CACHE_HOME ?? path.join(os.homedir(), '.cache'), 'secure-npm');

export const packumentCacheDir = path.join(cacheDir, 'packuments');

/** The malicious-package list, kept whole rather than per package. */
export const compromisedCacheFile = path.join(cacheDir, 'compromised-packages.json');

/**
 * pnpm's own config directory. Mirrors `getConfigDir` in pnpm's source — if
 * pnpm ever moves it, `secure-npm --self doctor` reports the mismatch.
 */
export function pnpmConfigDir() {
    if (process.env.XDG_CONFIG_HOME) return path.join(process.env.XDG_CONFIG_HOME, 'pnpm');
    if (IS_MACOS) return path.join(os.homedir(), 'Library', 'Preferences', 'pnpm');
    if (!IS_WINDOWS) return path.join(os.homedir(), '.config', 'pnpm');
    if (process.env.LOCALAPPDATA) return path.join(process.env.LOCALAPPDATA, 'pnpm', 'config');
    return path.join(os.homedir(), '.config', 'pnpm');
}

export const pnpmConfigFile = () => path.join(pnpmConfigDir(), 'config.yaml');

/** npm reads this on every invocation, whatever the working directory. */
export const npmUserConfigFile = () => path.join(os.homedir(), '.npmrc');

export { IS_WINDOWS };
