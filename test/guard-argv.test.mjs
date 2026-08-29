/**
 * Which command words the wrapper recognises, and what it does with the rest.
 *
 * Classification is load-bearing: every check downstream is gated on it, so a
 * command word that falls through is a command that installs unwatched. `pnpm
 * ci` did exactly that. These tests exist so the next one is caught here.
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test, { after } from 'node:test';
import ArgvGuard from '../src/guards/ArgvGuard.mjs';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-npm-argv-'));
after(() => fs.rmSync(root, { recursive: true, force: true }));

function project(directory, manifest) {
    const dir = path.join(root, directory);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify(manifest));
    return dir;
}

// A workspace: scripts at the root, and others that only exist in a package.
const workspace = project('workspace', { name: 'root', scripts: { dev: 'vite', lint: 'eslint .' } });
project(path.join('workspace', 'apps', 'web'), { name: 'web', scripts: { build: 'vite build' } });
fs.mkdirSync(path.join(workspace, '.git'), { recursive: true });

const install = (manager, argv) => ArgvGuard.classify(manager, argv).isInstall;

test('every pnpm command that installs is recognised as one', () => {
    for (const command of ['install', 'i', 'add', 'ci', 'clean-install', 'ic', 'install-clean', 'install-test', 'it']) {
        assert.equal(install('pnpm', [command]), true, `pnpm ${command}`);
    }
});

test('every npm command that installs is recognised as one', () => {
    for (const command of ['install', 'i', 'ci', 'clean-install', 'install-clean', 'install-test', 'it', 'update']) {
        assert.equal(install('npm', [command]), true, `npm ${command}`);
    }
});

test('commands that install nothing are not treated as installs', () => {
    for (const command of ['run', 'test', 'why', 'store', 'prune', 'clean', 'approve-builds', 'self-update']) {
        assert.equal(install('pnpm', [command]), false, `pnpm ${command}`);
    }
});

test('finds the command past the value of a flag', () => {
    const parsed = ArgvGuard.classify('pnpm', ['--filter', 'web', 'ci']);

    assert.equal(parsed.command, 'ci');
    assert.equal(parsed.isInstall, true);
});

test('says nothing about a command it recognises', () => {
    assert.equal(ArgvGuard.unknownCommandReason('pnpm', ['ci'], workspace), null);
    assert.equal(ArgvGuard.unknownCommandReason('pnpm', ['run', 'build'], workspace), null);
    assert.equal(ArgvGuard.unknownCommandReason('pnpm', [], workspace), null);
    assert.equal(ArgvGuard.unknownCommandReason('pnpm', ['--version'], workspace), null);
});

test('says nothing about a script, which is not a command', () => {
    assert.equal(ArgvGuard.unknownCommandReason('pnpm', ['dev'], workspace), null);
    assert.equal(ArgvGuard.unknownCommandReason('pnpm', ['lint'], workspace), null);
});

test('reaches into the workspace for a script another package declares', () => {
    // `pnpm --filter web build` runs a script that the root manifest never mentions.
    assert.equal(ArgvGuard.unknownCommandReason('pnpm', ['--filter', 'web', 'build'], workspace), null);
});

test('warns about a word that is neither a command nor a script', () => {
    const warning = ArgvGuard.unknownCommandReason('pnpm', ['frobnicate'], workspace);

    assert.match(warning.reason, /frobnicate/);
    assert.match(warning.hint, /no install checks ran/);
});

test('warns rather than throws when the project has no manifest at all', () => {
    const empty = path.join(root, 'empty');
    fs.mkdirSync(empty, { recursive: true });

    assert.match(ArgvGuard.unknownCommandReason('pnpm', ['frobnicate'], empty).reason, /frobnicate/);
});
