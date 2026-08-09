#!/usr/bin/env node
/**
 * Removes everything install.mjs put in place. Only files carrying the managed
 * marker are touched, so an .npmrc with credentials or a pnpm config someone
 * has since edited by hand survives.
 *
 * Usage: node uninstall.mjs [--set-path]
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { IS_WINDOWS, binDir, npmUserConfigFile, pnpmConfigFile } from './src/paths.mjs';
import { columns, styleFor } from './src/style.mjs';

const BLOCK_BEGIN = '# >>> secure-npm >>>';
const BLOCK_END = '# <<< secure-npm <<<';
const MANAGED_MARKER = 'managed by secure-npm';

const { dim, bold, yellow } = styleFor(process.stdout);

const wantsPath = process.argv.includes('--set-path');
const done = [];

function report(label, value) {
    done.push({ label, value });
}

function removeManagedBlock(file) {
    if (!fs.existsSync(file)) return false;

    const existing = fs.readFileSync(file, 'utf8');
    if (!existing.includes(BLOCK_BEGIN) || !existing.includes(BLOCK_END)) return false;

    const start = existing.indexOf(BLOCK_BEGIN);
    const end = existing.indexOf(BLOCK_END) + BLOCK_END.length;
    const stripped = `${existing.slice(0, start)}${existing.slice(end)}`.replace(/\n{3,}/g, '\n\n');

    fs.writeFileSync(file, stripped.trimStart());
    return true;
}

function removeShims() {
    if (!fs.existsSync(binDir)) return;
    fs.rmSync(binDir, { recursive: true, force: true });
    report('shims', `${binDir} ${dim('(removed)')}`);
}

function removePnpmConfig() {
    const file = pnpmConfigFile();
    if (!fs.existsSync(file)) return;

    if (!fs.readFileSync(file, 'utf8').includes(MANAGED_MARKER)) {
        report('pnpm config', `${file} ${dim('(edited by hand, left alone)')}`);
        return;
    }

    fs.rmSync(file);
    report('pnpm config', `${file} ${dim('(removed)')}`);
}

function removeNpmrcBlock() {
    const file = npmUserConfigFile();
    if (removeManagedBlock(file)) report('npm config', `${file} ${dim('(managed block removed)')}`);
}

function removePathWindows() {
    const current = execFileSync(
        'powershell',
        ['-NoProfile', '-NonInteractive', '-Command', "[Environment]::GetEnvironmentVariable('Path','User')"],
        { encoding: 'utf8' }
    ).trim();

    const target = path.resolve(binDir).toLowerCase();
    const kept = current
        .split(';')
        .filter(Boolean)
        .filter(entry => path.resolve(entry).toLowerCase() !== target);

    if (kept.length === current.split(';').filter(Boolean).length) return;

    execFileSync(
        'powershell',
        [
            '-NoProfile',
            '-NonInteractive',
            '-Command',
            "[Environment]::SetEnvironmentVariable('Path', $env:SECURE_NPM_NEW_PATH, 'User')",
        ],
        { encoding: 'utf8', env: { ...process.env, SECURE_NPM_NEW_PATH: kept.join(';') } }
    );

    report('PATH', `shim directory removed from the user PATH ${dim('(updated)')}`);
}

function removePathPosix() {
    for (const name of ['.profile', '.bashrc', '.zshrc']) {
        const file = path.join(os.homedir(), name);
        if (removeManagedBlock(file)) report('PATH', `${file} ${dim('(managed block removed)')}`);
    }
}

removeShims();
removePnpmConfig();
removeNpmrcBlock();
if (wantsPath) (IS_WINDOWS ? removePathWindows : removePathPosix)();

if (!wantsPath) report('note', 'PATH was left alone — re-run with --set-path to clean it too');

process.stdout.write(`\n${bold('secure-npm uninstaller')}\n\n`);
process.stdout.write(
    done.length
        ? `${columns(done, label => (label.trimEnd() === 'note' ? yellow(label) : dim(label))).join('\n')}\n\n`
        : `  ${dim('nothing to remove')}\n\n`
);
