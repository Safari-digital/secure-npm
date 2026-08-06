/**
 * Every filesystem location the tool uses, resolved once, for Windows and POSIX.
 *
 * The repository itself is the install root: shims and package-manager configs
 * point straight back into it, so `git pull` is the whole update procedure.
 */

import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const IS_WINDOWS = process.platform === 'win32';
const IS_MACOS = process.platform === 'darwin';

/** Repository root — this file lives in <root>/src. */
export const installRoot = path.resolve(fileURLToPath(import.meta.url), '..', '..');

export const policyFile = path.join(installRoot, 'policy.json');
export const localPolicyFile = path.join(installRoot, 'policy.local.json');
export const pnpmHookFile = path.join(installRoot, 'hooks', 'pnpmfile.mjs');
export const entryPoint = path.join(installRoot, 'bin', 'secure-npm.mjs');

/**
 * Where shims live. Prepended to PATH so `npm` and `pnpm` resolve here first,
 * and so blocked managers resolve to a refusal instead of a real binary.
 */
export const binDir = IS_WINDOWS
    ? path.join(process.env.LOCALAPPDATA ?? path.join(os.homedir(), 'AppData', 'Local'), 'secure-npm', 'bin')
    : path.join(process.env.XDG_DATA_HOME ?? path.join(os.homedir(), '.local', 'share'), 'secure-npm', 'bin');

/**
 * Marker dropped next to the shims. `which.mjs` skips any PATH entry holding
 * one, which is what stops a shim from resolving to itself.
 */
export const shimMarkerFile = path.join(binDir, '.secure-npm-shims');

const dataDir = IS_WINDOWS
    ? path.join(process.env.LOCALAPPDATA ?? path.join(os.homedir(), 'AppData', 'Local'), 'secure-npm')
    : path.join(process.env.XDG_STATE_HOME ?? path.join(os.homedir(), '.local', 'state'), 'secure-npm');

export const logDir = path.join(dataDir, 'logs');
export const auditLogFile = path.join(logDir, 'audit.log');

export const cacheDir = IS_WINDOWS
    ? path.join(process.env.LOCALAPPDATA ?? path.join(os.homedir(), 'AppData', 'Local'), 'secure-npm', 'cache')
    : path.join(process.env.XDG_CACHE_HOME ?? path.join(os.homedir(), '.cache'), 'secure-npm');

export const packumentCacheDir = path.join(cacheDir, 'packuments');

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
