/**
 * The pnpmfileChecksum workaround, pinned down.
 *
 * pnpm stamps the hash of the empty string into a lockfile whenever a global
 * pnpmfile is wired up but no local one feeds the digest. These tests fix all
 * three parts of the response: keeping that value out of the lockfile pnpm is
 * about to write, stripping it back out of one that already carries it, and
 * knowing which installs run frozen (so the inert hook is dropped). Only ever
 * that one phantom value - a real local pnpmfile's digest is left alone.
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test, { after } from 'node:test';
import PnpmChecksum from '../src/guards/PnpmChecksum.mjs';
import { POLICY_FILE } from '../src/paths.mjs';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-npm-checksum-'));
after(() => fs.rmSync(root, { recursive: true, force: true }));

function lockfile(name, contents) {
    const file = path.join(root, name, 'pnpm-lock.yaml');
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, contents);
    return file;
}

test('the empty checksum is the hash pnpm stamps with no file to digest', () => {
    assert.equal(PnpmChecksum.EMPTY, 'sha256-47DEQpj8HBSa+/TImW+5JCeuQeRkm5NMpJWZG3hSuFU=');
});

test('drops the phantom checksum from the lockfile pnpm is about to write', () => {
    const lockfile = { lockfileVersion: '9.0', pnpmfileChecksum: PnpmChecksum.EMPTY, importers: {} };

    assert.equal(PnpmChecksum.dropPhantom(lockfile), true);
    assert.ok(!('pnpmfileChecksum' in lockfile));
    assert.deepEqual(Object.keys(lockfile), ['lockfileVersion', 'importers']);
});

test('leaves a real local pnpmfile, or no checksum at all, alone', () => {
    const real = { pnpmfileChecksum: 'sha256-aRealDigestOfAnActualLocalPnpmfile=' };
    assert.equal(PnpmChecksum.dropPhantom(real), false);
    assert.equal(real.pnpmfileChecksum, 'sha256-aRealDigestOfAnActualLocalPnpmfile=');

    assert.equal(PnpmChecksum.dropPhantom({ lockfileVersion: '9.0' }), false);
    assert.equal(PnpmChecksum.dropPhantom(null), false);
    assert.equal(PnpmChecksum.dropPhantom(undefined), false);
});

// The point of the exercise: the drop has to be wired into the hook itself,
// because that is the only part of secure-npm a directly-invoked pnpm loads.
test('the pnpm hook wires the drop into afterAllResolved', async () => {
    // Suppresses the banner the hook prints when it believes it is on its own.
    process.env.SECURE_NPM_POLICY = POLICY_FILE;
    const { hooks } = await import('../hooks/pnpmfile.mjs');

    assert.equal(typeof hooks.afterAllResolved, 'function');

    const lockfile = { lockfileVersion: '9.0', pnpmfileChecksum: PnpmChecksum.EMPTY };
    assert.equal(hooks.afterAllResolved(lockfile), lockfile);
    assert.ok(!('pnpmfileChecksum' in lockfile));

    // Never a reason to fail an install, whatever pnpm hands it.
    assert.doesNotThrow(() => hooks.afterAllResolved(undefined));
    assert.doesNotThrow(() => hooks.afterAllResolved(Object.freeze({ pnpmfileChecksum: PnpmChecksum.EMPTY })));
});

test('ci and its aliases are frozen, whatever the environment', () => {
    for (const command of ['ci', 'clean-install', 'ic', 'install-clean']) {
        assert.equal(PnpmChecksum.frozenLockfileInstall(command, [command], false), true, command);
    }
});

test('a ci opted out of a frozen lockfile is not frozen', () => {
    assert.equal(PnpmChecksum.frozenLockfileInstall('ci', ['ci', '--no-frozen-lockfile'], true), false);
    assert.equal(PnpmChecksum.frozenLockfileInstall('ci', ['ci', '--frozen-lockfile=false'], true), false);
});

test('a plain install freezes on request or under CI, and opt-out always wins', () => {
    assert.equal(PnpmChecksum.frozenLockfileInstall('install', ['install'], false), false);
    assert.equal(PnpmChecksum.frozenLockfileInstall('install', ['install'], true), true);
    assert.equal(PnpmChecksum.frozenLockfileInstall('install', ['install', '--frozen-lockfile'], false), true);
    assert.equal(PnpmChecksum.frozenLockfileInstall('install', ['install', '--frozen-lockfile=true'], false), true);
    assert.equal(PnpmChecksum.frozenLockfileInstall('install', ['install', '--frozen-lockfile=false'], true), false);
    assert.equal(PnpmChecksum.frozenLockfileInstall('install', ['install', '--no-frozen-lockfile'], true), false);
    for (const command of ['i', 'import', 'install-test', 'it']) {
        assert.equal(PnpmChecksum.frozenLockfileInstall(command, [command], true), true, command);
    }
});

test('commands that resolve are never frozen, even asked to be', () => {
    assert.equal(PnpmChecksum.frozenLockfileInstall('add', ['add', 'left-pad'], true), false);
    assert.equal(PnpmChecksum.frozenLockfileInstall('update', ['update'], true), false);
    assert.equal(PnpmChecksum.frozenLockfileInstall('add', ['add', 'x', '--frozen-lockfile'], false), false);
    assert.equal(PnpmChecksum.frozenLockfileInstall('run', ['run', 'build'], true), false);
});

test('switches the global pnpmfile off, before any script separator', () => {
    assert.deepEqual(PnpmChecksum.withGlobalPnpmfileDisabled(['ci']), ['ci', '--config.global-pnpmfile=']);
    assert.deepEqual(PnpmChecksum.withGlobalPnpmfileDisabled(['install', '--frozen-lockfile']), [
        'install',
        '--frozen-lockfile',
        '--config.global-pnpmfile=',
    ]);
    assert.deepEqual(PnpmChecksum.withGlobalPnpmfileDisabled(['run', 'x', '--', '--frozen-lockfile']), [
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

pnpmfileChecksum: ${PnpmChecksum.EMPTY}

importers:

  .: {}
`;

test('strips the phantom checksum and leaves a single gap behind', () => {
    const file = lockfile('phantom', withPhantom);

    assert.equal(PnpmChecksum.stripPhantom(file), true);
    const after = fs.readFileSync(file, 'utf8');
    assert.ok(!after.includes('pnpmfileChecksum'));
    assert.match(after, /excludeLinksFromLockfile: false\n\nimporters:/);
});

test('strips it out of a CRLF lockfile too', () => {
    const file = lockfile('phantom-crlf', withPhantom.split('\n').join('\r\n'));

    assert.equal(PnpmChecksum.stripPhantom(file), true);
    assert.ok(!fs.readFileSync(file, 'utf8').includes('pnpmfileChecksum'));
});

test('leaves a real checksum from a local pnpmfile untouched', () => {
    const real = `lockfileVersion: '9.0'

pnpmfileChecksum: sha256-aRealDigestOfAnActualLocalPnpmfile=

importers:

  .: {}
`;
    const file = lockfile('real', real);

    assert.equal(PnpmChecksum.stripPhantom(file), false);
    assert.match(fs.readFileSync(file, 'utf8'), /pnpmfileChecksum: sha256-aRealDigestOfAnActualLocalPnpmfile=/);
});

test('does nothing when there is no checksum, or no file', () => {
    const none = lockfile('none', `lockfileVersion: '9.0'\n\nimporters:\n\n  .: {}\n`);
    assert.equal(PnpmChecksum.stripPhantom(none), false);
    assert.equal(PnpmChecksum.stripPhantom(path.join(root, 'missing', 'pnpm-lock.yaml')), false);
});
