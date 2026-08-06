#!/usr/bin/env node
/**
 * Installer. Wires four things together and then gets out of the way:
 *
 *   1. shims in a directory that goes first on PATH, so `npm` and `pnpm` route
 *      through the guard rails and `bun`/`yarn`/`deno` route to a refusal,
 *   2. pnpm's global config, which is where pnpm's own supply-chain settings
 *      live and where the resolution hook is registered,
 *   3. the user's .npmrc, so npm refuses lifecycle scripts even when it is
 *      invoked by something that bypassed the shim,
 *   4. optionally PATH itself, behind --set-path.
 *
 * Nothing is copied out of the repository: every generated file points back
 * here, so `git pull` is the entire update procedure.
 *
 * Usage: node install.mjs [--set-path] [--force]
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { loadPolicy } from './src/policy.mjs';
import {
    IS_WINDOWS,
    binDir,
    entryPoint,
    installRoot,
    npmUserConfigFile,
    pnpmConfigDir,
    pnpmConfigFile,
    pnpmHookFile,
    policyFile,
    shimMarkerFile,
} from './src/paths.mjs';

const BLOCK_BEGIN = '# >>> secure-npm >>>';
const BLOCK_END = '# <<< secure-npm <<<';
const MANAGED_MARKER = 'managed by secure-npm';

const flags = new Set(process.argv.slice(2));
const wantsPath = flags.has('--set-path');
const force = flags.has('--force');

const done = [];
const notes = [];

function report(message) {
    done.push(message);
}

/* ------------------------------------------------------------------ shims */

function posixShim(manager) {
    return `#!/bin/sh
# ${MANAGED_MARKER} — do not edit, regenerate with "node install.mjs"
exec node "${entryPoint}" ${manager} "$@"
`;
}

function windowsCmdShim(manager) {
    return `@ECHO OFF\r
REM ${MANAGED_MARKER} — do not edit, regenerate with "node install.mjs"\r
SETLOCAL\r
node "${entryPoint}" ${manager} %*\r
EXIT /B %ERRORLEVEL%\r
`;
}

function windowsPowerShellShim(manager) {
    return `#!/usr/bin/env pwsh
# ${MANAGED_MARKER} — do not edit, regenerate with "node install.mjs"
node "${entryPoint}" ${manager} @args
exit $LASTEXITCODE
`;
}

function writeShim(manager) {
    // The extensionless script is written on Windows too: Git Bash and MSYS
    // resolve it, and they are how most Windows Node work actually happens.
    fs.writeFileSync(path.join(binDir, manager), posixShim(manager), { mode: 0o755 });

    if (IS_WINDOWS) {
        fs.writeFileSync(path.join(binDir, `${manager}.cmd`), windowsCmdShim(manager));
        fs.writeFileSync(path.join(binDir, `${manager}.ps1`), windowsPowerShellShim(manager));
    }
}

function installShims(policy) {
    fs.mkdirSync(binDir, { recursive: true });
    fs.writeFileSync(
        shimMarkerFile,
        `${MANAGED_MARKER}\ninstallRoot=${installRoot}\n\nThis marker tells the wrapper to skip this directory when it looks for the\nreal package managers on PATH. Removing it causes infinite recursion.\n`
    );

    const wrapped = ['npm', 'npx', 'pnpm', 'pnpx'];
    const refused = [...policy.blockedManagers.keys()];

    for (const manager of [...wrapped, ...refused]) writeShim(manager);

    report(`shims        ${binDir}`);
    report(`  wrapped    ${wrapped.join(', ')}`);
    report(`  refused    ${refused.join(', ')}`);
}

/* ------------------------------------------------------- pnpm global config */

function pnpmConfigContents(policy) {
    const exclude = [...policy.minimumReleaseAgeExclude];

    return `# ${MANAGED_MARKER} — regenerate with "node install.mjs"
# Source of truth: ${policyFile}
#
# Applies to every pnpm project on this machine, including projects with no
# pnpm-workspace.yaml and including "pnpm dlx". A project may tighten these in
# its own pnpm-workspace.yaml; this file is the floor.

# A version must have existed for this long before pnpm may resolve it.
# Strict mode fails the install instead of quietly widening the exclude list.
minimumReleaseAge: ${policy.minimumReleaseAgeMinutes}
minimumReleaseAgeStrict: true
minimumReleaseAgeIgnoreMissingTime: false
${exclude.length ? `minimumReleaseAgeExclude:\n${exclude.map(entry => `  - '${entry}'`).join('\n')}\n` : ''}
# Refuses a version published with weaker guarantees than an earlier one.
trustPolicy: ${policy.trustPolicy}
trustPolicyIgnoreAfter: ${policy.trustPolicyIgnoreAfterMinutes}

# No lifecycle scripts at install time. A project that genuinely needs to
# compile fails loudly (ERR_PNPM_IGNORED_BUILDS) rather than running code.
ignoreScripts: ${policy.forceIgnoreScripts}

# git and tarball sub-dependencies carry no publish date and no provenance,
# which is exactly how the checks above get bypassed.
blockExoticSubdeps: ${!policy.allowExoticSources}

# Name-based blocking, which pnpm has no setting for.
globalPnpmfile: '${pnpmHookFile}'
`;
}

function installPnpmConfig(policy) {
    const file = pnpmConfigFile();
    fs.mkdirSync(pnpmConfigDir(), { recursive: true });

    if (fs.existsSync(file)) {
        const existing = fs.readFileSync(file, 'utf8');
        if (!existing.includes(MANAGED_MARKER) && !force) {
            const backup = `${file}.bak-${Date.now()}`;
            fs.copyFileSync(file, backup);
            notes.push(`existing pnpm config was not written by this tool — backed up to ${backup}`);
        }
    }

    fs.writeFileSync(file, pnpmConfigContents(policy));
    report(`pnpm config  ${file}`);
}

/* -------------------------------------------------------------- npm config */

/**
 * .npmrc holds auth tokens, so it is never rewritten wholesale — only the
 * block between the markers is replaced.
 */
function upsertManagedBlock(file, body) {
    const block = `${BLOCK_BEGIN}\n${body.trimEnd()}\n${BLOCK_END}`;
    const existing = fs.existsSync(file) ? fs.readFileSync(file, 'utf8') : '';

    if (existing.includes(BLOCK_BEGIN) && existing.includes(BLOCK_END)) {
        const start = existing.indexOf(BLOCK_BEGIN);
        const end = existing.indexOf(BLOCK_END) + BLOCK_END.length;
        fs.writeFileSync(file, `${existing.slice(0, start)}${block}${existing.slice(end)}`);
        return 'updated';
    }

    const separator = existing === '' || existing.endsWith('\n') ? '' : '\n';
    fs.writeFileSync(file, `${existing}${separator}${block}\n`);
    return existing === '' ? 'created' : 'appended';
}

function installNpmrc() {
    const file = npmUserConfigFile();
    const action = upsertManagedBlock(
        file,
        `# ${MANAGED_MARKER} — regenerate with "node install.mjs"
# npm has no release-age or provenance setting; the wrapper enforces those.
# This line is the part npm can enforce by itself, and it keeps holding even
# when npm is invoked by a tool that never sees the shim.
ignore-scripts=true`
    );

    report(`npm config   ${file} (${action})`);
}

/* -------------------------------------------------------------------- PATH */

function windowsUserPath() {
    return execFileSync(
        'powershell',
        ['-NoProfile', '-NonInteractive', '-Command', "[Environment]::GetEnvironmentVariable('Path','User')"],
        { encoding: 'utf8' }
    ).trim();
}

function setWindowsUserPath(value) {
    execFileSync(
        'powershell',
        [
            '-NoProfile',
            '-NonInteractive',
            '-Command',
            `[Environment]::SetEnvironmentVariable('Path', $env:SECURE_NPM_NEW_PATH, 'User')`,
        ],
        { encoding: 'utf8', env: { ...process.env, SECURE_NPM_NEW_PATH: value } }
    );
}

function installPathWindows() {
    const current = windowsUserPath();
    const entries = current.split(';').filter(Boolean);

    if (entries.some(entry => path.resolve(entry).toLowerCase() === path.resolve(binDir).toLowerCase())) {
        report('PATH         already contains the shim directory');
        return;
    }

    const backup = path.join(binDir, `path-backup-${Date.now()}.txt`);
    fs.writeFileSync(backup, current);

    // setx is deliberately avoided: it truncates PATH at 1024 characters.
    setWindowsUserPath([binDir, ...entries].join(';'));

    report(`PATH         shim directory prepended to the user PATH`);
    report(`  backup     ${backup}`);
    notes.push('open a new terminal for the PATH change to take effect');
}

function installPathPosix() {
    const body = `${BLOCK_BEGIN}
# ${MANAGED_MARKER} — regenerate with "node install.mjs"
export PATH="${binDir}:$PATH"
${BLOCK_END}`;

    const candidates = ['.profile', '.bashrc', '.zshrc']
        .map(name => path.join(os.homedir(), name))
        .filter(file => fs.existsSync(file));

    const targets = candidates.length ? candidates : [path.join(os.homedir(), '.profile')];

    for (const file of targets) {
        upsertManagedBlock(file, body.split('\n').slice(1, -1).join('\n'));
        report(`PATH         ${file}`);
    }

    notes.push('open a new shell, or source the file above, for the PATH change to take effect');
}

/* -------------------------------------------------------------------- main */

function main() {
    const policy = loadPolicy();

    process.stdout.write(`\nsecure-npm installer — ${installRoot}\n\n`);

    installShims(policy);
    installPnpmConfig(policy);
    installNpmrc();

    if (wantsPath) {
        IS_WINDOWS ? installPathWindows() : installPathPosix();
    } else {
        notes.push(`PATH was not modified. Re-run with --set-path, or add this first on PATH: ${binDir}`);
    }

    process.stdout.write(`${done.join('\n')}\n\n`);
    for (const note of notes) process.stdout.write(`  note: ${note}\n`);
    process.stdout.write(`\nNext: secure-npm doctor\n\n`);
}

main();
