/**
 * The pnpmfileChecksum workaround, pinned down.
 *
 * pnpm stamps the hash of the empty string into a lockfile whenever a global
 * pnpmfile is wired up but no local one feeds the digest. These tests fix both
 * halves of the response: knowing which installs run frozen (so the inert hook
 * is dropped), and stripping that one phantom value back out — and only that
 * one — when a resolving install writes it.
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test, { after } from 'node:test';
import {
    EMPTY_PNPMFILE_CHECKSUM,
    frozenLockfileInstall,
    stripPhantomPnpmfileChecksum,
    withGlobalPnpmfileDisabled,
} from '../src/pnpm-checksum.mjs';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-npm-checksum-'));
after(() => fs.rmSync(root, { recursive: true, force: true }));

function lockfile(name, contents) {
    const file = path.join(root, name, 'pnpm-lock.yaml');
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, contents);
    return file;
}

test('the empty checksum is the hash pnpm stamps with no file to digest', () => {
    assert.equal(EMPTY_PNPMFILE_CHECKSUM, 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=');
});

test('ci and its aliases are frozen, whatever the environment', () => {
    for (const command of ['ci', 'clean-install', 'ic', 'install-clean']) {
        assert.equal(frozenLockfileInstall(command, [command], false), true, command);
    }
});

test('a ci opted out of a frozen lockfile is not frozen', () => {
    assert.equal(frozenLockfileInstall('ci', ['ci', '--no-frozen-lockfile'], true), false);
    assert.equal(frozenLockfileInstall('ci', ['ci', '--frozen-lockfile=false'], true), false);
});

test('a plain install freezes on request or under CI, and opt-out always wins', () => {
    assert.equal(frozenLockfileInstall('install', ['install'], false), false);
    assert.equal(frozenLockfileInstall('install', ['install'], true), true);
    assert.equal(frozenLockfileInstall('install', ['install', '--frozen-lockfile'], false), true);
    assert.equal(frozenLockfileInstall('install', ['install', '--frozen-lockfile=true'], false), true);
    assert.equal(frozenLockfileInstall('install', ['install', '--frozen-lockfile=false'], true), false);
    assert.equal(frozenLockfileInstall('install', ['install', '--no-frozen-lockfile'], true), false);
    for (const command of ['i', 'import', 'install-test', 'it']) {
        assert.equal(frozenLockfileInstall(command, [command], true), true, command);
    }
});

test('commands that resolve are never frozen, even asked to be', () => {
    assert.equal(frozenLockfileInstall('add', ['add', 'left-pad'], true), false);
    assert.equal(frozenLockfileInstall('update', ['update'], true), false);
    assert.equal(frozenLockfileInstall('add', ['add', 'x', '--frozen-lockfile'], false), false);
    assert.equal(frozenLockfileInstall('run', ['run', 'build'], true), false);
});

test('switches the global pnpmfile off, before any script separator', () => {
    assert.deepEqual(withGlobalPnpmfileDisabled(['ci']), ['ci', '--config.global-pnpmfile=']);
    assert.deepEqual(withGlobalPnpmfileDisabled(['install', '--frozen-lockfile']), [
        'install',
        '--frozen-lockfile',
        '--config.global-pnpmfile=',
    ]);
    assert.deepEqual(withGlobalPnpmfileDisabled(['run', 'x', '--', '--frozen-lockfile']), [
        'run',
        'x',
        '--config.global-pnpmfile=',
        '--',
        '--frozen-lockfile',
    ]);
});

// The exact shape pnpm writes: the field sits between `settings:` and
// `importers:`, one blank line on each side.
const withPhantom = `lockfileVersion: '9.0'

settings:
  autoInstallPeers: true
  excludeLinksFromLockfile: false

pnpmfileChecksum: ${EMPTY_PNPMFILE_CHECKSUM}

importers:

  .: {}
`;

test('strips the phantom checksum and leaves a single gap behind', () => {
    const file = lockfile('phantom', withPhantom);

    assert.equal(stripPhantomPnpmfileChecksum(file), true);
    const after = fs.readFileSync(file, 'utf8');
    assert.ok(!after.includes('pnpmfileChecksum'));
    assert.match(after, /excludeLinksFromLockfile: false\n\nimporters:/);
});

test('strips it out of a CRLF lockfile too', () => {
    const file = lockfile('phantom-crlf', withPhantom.split('\n').join('\r\n'));

    assert.equal(stripPhantomPnpmfileChecksum(file), true);
    assert.ok(!fs.readFileSync(file, 'utf8').includes('pnpmfileChecksum'));
});

test('leaves a real checksum from a local pnpmfile untouched', () => {
    const real = `lockfileVersion: '9.0'

pnpmfileChecksum: sha256-aRealDigestOfAnActualLocalPnpmfile=

importers:

  .: {}
`;
    const file = lockfile('real', real);

    assert.equal(stripPhantomPnpmfileChecksum(file), false);
    assert.match(fs.readFileSync(file, 'utf8'), /pnpmfileChecksum: sha256-aRealDigestOfAnActualLocalPnpmfile=/);
});

test('does nothing when there is no checksum, or no file', () => {
    const none = lockfile('none', `lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n`);
    assert.equal(stripPhantomPnpmfileChecksum(none), false);
    assert.equal(stripPhantomPnpmfileChecksum(path.join(root, 'missing', 'pnpm-lock.yaml')), false);
});
