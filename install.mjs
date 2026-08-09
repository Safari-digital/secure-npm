#!/usr/bin/env node
/**
 * Installer. Wires five things together and then gets out of the way:
 *
 *   1. a copy of the runtime under %LOCALAPPDATA%, which is what every shim and
 *      every pnpm process then loads,
 *   2. shims in a directory that goes first on PATH, so `npm` and `pnpm` route
 *      through the guard rails and `bun`/`yarn`/`deno` route to a refusal,
 *   3. pnpm's global config, which is where pnpm's own supply-chain settings
 *      live and where the resolution hook is registered,
 *   4. the user's .npmrc, so npm refuses lifecycle scripts even when it is
 *      invoked by something that bypassed the shim,
 *   5. optionally PATH itself, behind --set-path.
 *
 * Nothing generated points back at this repository, which is why running the
 * installer is now part of the update procedure: `git pull` alone changes the
 * source and leaves the deployed copy where it was. `doctor` compares the two.
 *
 * Usage: node install.mjs [--set-path] [--force]
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { loadPolicy } from './src/policy.mjs';
import { deployRuntime } from './src/runtime.mjs';
import { columns, styleFor } from './src/style.mjs';
import {
    IS_WINDOWS,
    binDir,
    configDir,
    entryPoint,
    legacyLocalPolicyFile,
    localPolicyFile,
    moduleRoot,
    npmUserConfigFile,
    pnpmConfigDir,
    pnpmConfigFile,
    pnpmHookFile,
    runtimePolicyFile,
    runtimeRoot,
    shimMarkerFile,
} from './src/paths.mjs';

const BLOCK_BEGIN = '# >>> secure-npm >>>';
const BLOCK_END = '# <<< secure-npm <<<';
const MANAGED_MARKER = 'managed by secure-npm';

const flags = new Set(process.argv.slice(2));
const wantsPath = flags.has('--set-path');
const force = flags.has('--force');

const { dim, bold, yellow } = styleFor(process.stdout);

const done = [];
const notes = [];

/** One row of the final report. `depth` indents the label, never the value. */
function report(label, value, depth = 0) {
    done.push({ label, value, depth });
}

/* ---------------------------------------------------------------- runtime */

function installRuntime() {
    const stamp = deployRuntime(moduleRoot);

    report('runtime', runtimeRoot);
    report('from', `${moduleRoot} ${dim(`(v${stamp.version})`)}`, 1);
}

/**
 * The overlay used to sit in the repository, git-ignored. It is moved rather
 * than copied: two files, one of them silently no longer read, is the worst of
 * the available outcomes.
 */
function migrateLocalPolicy() {
    if (!fs.existsSync(legacyLocalPolicyFile)) return;

    if (fs.existsSync(localPolicyFile)) {
        notes.push(`${legacyLocalPolicyFile} is no longer read — the overlay in use is ${localPolicyFile}`);
        return;
    }

    fs.mkdirSync(configDir, { recursive: true });
    fs.copyFileSync(legacyLocalPolicyFile, localPolicyFile);
    fs.rmSync(legacyLocalPolicyFile);

    report('local policy', `${localPolicyFile} ${dim('(moved out of the repository)')}`);
}

/* ------------------------------------------------------------------ shims */

function posixShim(route) {
    return `#!/bin/sh
# ${MANAGED_MARKER} — do not edit, regenerate with "node install.mjs"
exec node "${entryPoint}" ${route} "$@"
`;
}

function windowsCmdShim(route) {
    return `@ECHO OFF\r
REM ${MANAGED_MARKER} — do not edit, regenerate with "node install.mjs"\r
SETLOCAL\r
node "${entryPoint}" ${route} %*\r
EXIT /B %ERRORLEVEL%\r
`;
}

function windowsPowerShellShim(route) {
    return `#!/usr/bin/env pwsh
# ${MANAGED_MARKER} — do not edit, regenerate with "node install.mjs"
node "${entryPoint}" ${route} @args
exit $LASTEXITCODE
`;
}

/**
 * `route` is the first argument handed to the entry point, which is what tells
 * it what it is being asked to do. For a package manager that is the name that
 * was typed; for the tool's own command it is `--self`, so that a package
 * manager one day called "doctor" could never shadow `secure-npm doctor`.
 */
function writeShim(name, route = name) {
    // The extensionless script is written on Windows too: Git Bash and MSYS
    // resolve it, and they are how most Windows Node work actually happens.
    fs.writeFileSync(path.join(binDir, name), posixShim(route), { mode: 0o755 });

    if (IS_WINDOWS) {
        fs.writeFileSync(path.join(binDir, `${name}.cmd`), windowsCmdShim(route));
        fs.writeFileSync(path.join(binDir, `${name}.ps1`), windowsPowerShellShim(route));
    }
}

function installShims(policy) {
    fs.mkdirSync(binDir, { recursive: true });
    fs.writeFileSync(
        shimMarkerFile,
        `${MANAGED_MARKER}\nruntime=${runtimeRoot}\n\nThis marker tells the wrapper to skip this directory when it looks for the\nreal package managers on PATH. Removing it causes infinite recursion.\n`
    );

    const wrapped = ['npm', 'npx', 'pnpm', 'pnpx'];
    const refused = [...policy.blockedManagers.keys()];

    for (const manager of [...wrapped, ...refused]) writeShim(manager);
    writeShim('secure-npm', '--self');

    report('shims', binDir);
    report('wrapped', wrapped.join(', '), 1);
    report('refused', refused.join(', '), 1);
    report('tool', 'secure-npm', 1);
}

/* ------------------------------------------------------- pnpm global config */

function pnpmConfigContents(policy) {
    const exclude = [...policy.minimumReleaseAgeExclude];

    return `# ${MANAGED_MARKER} — regenerate with "node install.mjs"
# Source of truth: ${runtimePolicyFile}, overlaid with ${localPolicyFile}
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
#
# This setting is a boolean, so it cannot express "these repositories and no
# others". With allowedGitSources in use it is therefore handed to the hook
# below, which enforces the same rule per repository, at every depth.
blockExoticSubdeps: ${!policy.allowExoticSources && policy.allowedGitSources.length === 0}

# Name-based blocking and the git whitelist, neither of which pnpm has a
# setting for.
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
    report('pnpm config', file);
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

    report('npm config', `${file} ${dim(`(${action})`)}`);
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
        report('PATH', `already contains the shim directory ${dim('(unchanged)')}`);
        return;
    }

    const backup = path.join(binDir, `path-backup-${Date.now()}.txt`);
    fs.writeFileSync(backup, current);

    // setx is deliberately avoided: it truncates PATH at 1024 characters.
    setWindowsUserPath([binDir, ...entries].join(';'));

    report('PATH', `shim directory prepended to the user PATH ${dim('(updated)')}`);
    report('backup', backup, 1);
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
        report('PATH', file);
    }

    notes.push('open a new shell, or source the file above, for the PATH change to take effect');
}

/* -------------------------------------------------------------------- main */

function main() {
    // Before the policy is read, not after: on the run that migrates it, the
    // overlay is still in the repository and would otherwise be missed exactly
    // once — on the run that generates pnpm's config from it.
    migrateLocalPolicy();

    // Read from the repository, which is the source of truth at install time;
    // the deployed copy is what every later command reads.
    const policy = loadPolicy();

    installRuntime();
    installShims(policy);
    installPnpmConfig(policy);
    installNpmrc();

    if (wantsPath) {
        IS_WINDOWS ? installPathWindows() : installPathPosix();
    } else {
        notes.push(`PATH was left alone — re-run with --set-path, or put ${binDir} first on PATH yourself`);
    }

    notes.push('re-run this installer after every "git pull" — doctor reports a runtime that has fallen behind');

    // Notes and the closing line share the grid rather than sitting outside it,
    // so the whole report has one label column and one value column.
    const rows = [
        ...done,
        ...notes.map(note => ({ label: 'note', value: note })),
        { label: 'next', value: bold('secure-npm doctor') },
    ];

    const lines = columns(rows, label => (label.trimEnd() === 'note' ? yellow(label) : dim(label)));
    const sections = [lines.slice(0, done.length), lines.slice(done.length)];

    process.stdout.write(`\n${bold('secure-npm installer')}\n\n`);
    process.stdout.write(`${sections.map(section => section.join('\n')).join('\n\n')}\n\n`);
}

main();
