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

const BLOCK_BEGIN = '# >>> secure-npm >>>';
const BLOCK_END = '# <<< secure-npm <<<';
const MANAGED_MARKER = 'managed by secure-npm';

const wantsPath = process.argv.includes('--set-path');
const done = [];

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
    done.push(`removed shims        ${binDir}`);
}

function removePnpmConfig() {
    const file = pnpmConfigFile();
    if (!fs.existsSync(file)) return;

    if (!fs.readFileSync(file, 'utf8').includes(MANAGED_MARKER)) {
        done.push(`kept pnpm config     ${file} (edited by hand, left alone)`);
        return;
    }

    fs.rmSync(file);
    done.push(`removed pnpm config  ${file}`);
}

function removeNpmrcBlock() {
    const file = npmUserConfigFile();
    if (removeManagedBlock(file)) done.push(`cleaned npm config   ${file}`);
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

    done.push('cleaned user PATH');
}

function removePathPosix() {
    for (const name of ['.profile', '.bashrc', '.zshrc']) {
        const file = path.join(os.homedir(), name);
        if (removeManagedBlock(file)) done.push(`cleaned PATH         ${file}`);
    }
}

removeShims();
removePnpmConfig();
removeNpmrcBlock();
if (wantsPath) (IS_WINDOWS ? removePathWindows : removePathPosix)();

process.stdout.write(`\n${done.join('\n') || 'nothing to remove'}\n\n`);
if (!wantsPath) process.stdout.write(`  note: PATH was left alone. Re-run with --set-path to clean it too.\n\n`);
