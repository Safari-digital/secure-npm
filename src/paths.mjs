import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

export const APP_NAME       = 'secure-npm';

export const IS_WINDOWS     = process.platform === 'win32';
export const IS_MACOS       = process.platform === 'darwin';

const OS_CONFIG_PATH        = process.env.XDG_CONFIG_HOME   ?? path.join(os.homedir(), '.config');
const OS_DATA_HOME_PATH     = process.env.XDG_DATA_HOME     ?? path.join(os.homedir(), '.local', 'share');
const OS_STATE_PATH         = process.env.XDG_STATE_HOME    ?? path.join(os.homedir(), '.local', 'state');
const OS_CACHE_PATH         = process.env.XDG_CACHE_HOME    ?? path.join(os.homedir(), '.cache');
const WINDOWS_APPDATA_PATH  = process.env.LOCALAPPDATA      ?? path.join(os.homedir(), 'AppData', 'Local');
const WINDOWS_APP_PATH      = path.join(WINDOWS_APPDATA_PATH, APP_NAME);

export const MODULE_ROOT_PATH           = path.resolve(fileURLToPath(import.meta.url), '..', '..');
export const APP_PATH                   = IS_WINDOWS ? WINDOWS_APP_PATH : path.join(OS_DATA_HOME_PATH, APP_NAME);
export const APP_RUNTIME_DIR            = path.join(APP_PATH, 'runtime');
export const APP_RUNTIME_STAMP_FILE     = path.join(APP_RUNTIME_DIR, `.${APP_NAME}-runtime`);
export const APP_SOURCE_DIR             = path.join(APP_PATH, 'source');
export const APP_BIN_DIR                = path.join(APP_PATH, 'bin');
export const APP_SHIM_MARKER_FILE       = path.join(APP_BIN_DIR, `.${APP_NAME}-shims`);
export const APP_CONFIG_DIR             = IS_WINDOWS ? WINDOWS_APP_PATH : path.join(OS_CONFIG_PATH, APP_NAME);
export const APP_STATE_PATH             = IS_WINDOWS ? WINDOWS_APP_PATH : path.join(OS_STATE_PATH, APP_NAME);

export const LOCAL_POLICY_FILE          = path.join(APP_CONFIG_DIR,     'policy.local.json');
export const POLICY_FILE                = path.join(MODULE_ROOT_PATH,   'policy.json');
export const RUNTIME_POLICY_FILE        = path.join(APP_RUNTIME_DIR,    'policy.json');
export const APP_LOG_DIR                = path.join(APP_STATE_PATH,     'logs');
export const APP_AUDIT_LOG_FILE         = path.join(APP_LOG_DIR,        'audit.log');

export const APP_CACHE_DIR              = IS_WINDOWS
                                            ? path.join(WINDOWS_APP_PATH, 'cache')
                                            : path.join(OS_CACHE_PATH, APP_NAME);

export const PACKUMENT_CACHE_DIR        = path.join(APP_CACHE_DIR,      'packuments');
export const COMPROMISED_CACHE_FILE     = path.join(APP_CACHE_DIR,      'compromised-packages.json');

export const PNPM_HOOK_FILE             = path.join(APP_RUNTIME_DIR, 'hooks', 'pnpmfile.mjs');
export const APP_ENTRYPOINT             = path.join(APP_RUNTIME_DIR, 'bin', `${APP_NAME}.mjs`);

export const PNPM_CONFIG_DIR = (() => {
    if (process.env.XDG_CONFIG_HOME)
        return path.join(process.env.XDG_CONFIG_HOME, 'pnpm');
    if (IS_MACOS)
        return path.join(os.homedir(), 'Library', 'Preferences', 'pnpm');
    if (!IS_WINDOWS)
        return path.join(os.homedir(), '.config', 'pnpm');
    if (process.env.LOCALAPPDATA)
        return path.join(process.env.LOCALAPPDATA, 'pnpm', 'config');

    return path.join(os.homedir(), '.config', 'pnpm');
})()

export const PNPM_CONFIG_FILE       = path.join(PNPM_CONFIG_DIR, 'config.yaml');
export const NPM_USR_CONFIG_FILE    = path.join(os.homedir(), '.npmrc');
