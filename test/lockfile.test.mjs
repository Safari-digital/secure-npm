/**
 * The parsers, pinned down.
 *
 * These files are machine-written by two package managers across five lockfile
 * formats, and every one of them is read here by hand - a key format that moves
 * would otherwise index to nothing at all, which is indistinguishable from a
 * clean tree. Ported alongside the parsers themselves, from Safari Digital's
 * node-packages-validator.
 */

import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test, { after } from 'node:test';
import LockFiles from '../src/guards/LockFiles.mjs';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-npm-lockfile-'));
after(() => fs.rmSync(root, { recursive: true, force: true }));

function fixture(directory, name, contents) {
    const file = path.join(root, directory, name);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, contents);
    return file;
}

const versions = (index, name) => (index[name] ?? []).map(entry => entry.version).sort();

const npmLock = fixture(
    'npm',
    'package-lock.json',
    JSON.stringify({
        name: 'npm-fixture',
        lockfileVersion: 3,
        packages: {
            '': { name: 'npm-fixture', dependencies: { 'left-pad': '^1.3.0' } },
            'node_modules/left-pad': {
                version: '1.3.0',
                resolved: 'https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz',
            },
            'node_modules/debug': { version: '4.3.4' },
            'node_modules/left-pad/node_modules/debug': { version: '4.4.1' },
            'node_modules/@scope/tool': {
                version: '2.0.0',
                resolved: 'https://registry.npmjs.org/@scope/tool/-/tool-2.0.0.tgz',
            },
            'node_modules/aliased': { name: 'real-package', version: '9.9.9' },
            'node_modules/workspace-pkg': { resolved: 'packages/thing', link: true },
        },
    })
);

const npmLegacyLock = fixture(
    'npm-legacy',
    'package-lock.json',
    JSON.stringify({
        name: 'npm-legacy-fixture',
        lockfileVersion: 1,
        dependencies: {
            'left-pad': { version: '1.3.0' },
            debug: { version: '4.3.4', dependencies: { debug: { version: '4.4.1' } } },
        },
    })
);

const pnpmLock = fixture(
    'pnpm',
    'pnpm-lock.yaml',
    `lockfileVersion: '9.0'

importers:

  .:
    dependencies:
      left-pad:
        specifier: 1.3.0
        version: 1.3.0

packages:

  '@scope/tool@2.0.0':
    resolution: {integrity: sha512-aaa==}

  left-pad@1.3.0:
    resolution: {integrity: sha512-bbb==}

  debug@4.3.4:
    resolution: {integrity: sha512-ccc==}

  debug@4.4.1:
    resolution: {integrity: sha512-ddd==}

  vue-eslint-parser@10.4.0(eslint@9.39.4):
    resolution: {integrity: sha512-eee==}

  tarballed@1.0.0:
    resolution: {tarball: https://example.com/tarballed-1.0.0.tgz}

snapshots:

  only-in-snapshots@9.9.9: {}
`
);

const pnpmLegacyLock = fixture(
    'pnpm-legacy',
    'pnpm-lock.yaml',
    `lockfileVersion: 5.4

packages:

  /@scope/tool/2.0.0:
    resolution: {integrity: sha512-aaa==}

  /debug/4.3.4:
    resolution: {integrity: sha512-bbb==}

  /vue-eslint-parser/9.0.0_eslint@8.0.0:
    resolution: {integrity: sha512-ccc==}
`
);

const manifest = fixture(
    'manifest',
    'package.json',
    JSON.stringify({
        name: 'manifest-fixture',
        dependencies: { 'left-pad': '^1.3.0', '@scope/tool': '~2.0.0' },
        devDependencies: { eslint: '9.39.4' },
        peerDependencies: { debug: '>=4.3.4' },
    })
);

fixture('manifest', 'unknown.txt', 'not a lockfile\n');

test('resolves npm lockfile paths back to package names', () => {
    const index = LockFiles.indexNpmLock(npmLock);

    assert.deepEqual(Object.keys(index).sort(), ['@scope/tool', 'debug', 'left-pad', 'real-package']);
    assert.deepEqual(versions(index, 'left-pad'), ['1.3.0']);
    assert.equal(index['@scope/tool'][0].resolved, 'https://registry.npmjs.org/@scope/tool/-/tool-2.0.0.tgz');
});

test('keeps every version of a package installed more than once', () => {
    assert.deepEqual(versions(LockFiles.indexNpmLock(npmLock), 'debug'), ['4.3.4', '4.4.1']);
});

test('follows npm aliases to the real package name', () => {
    const index = LockFiles.indexNpmLock(npmLock);

    assert.deepEqual(versions(index, 'real-package'), ['9.9.9']);
    assert.equal(index.aliased, undefined);
});

test('ignores the root project and workspace links', () => {
    const index = LockFiles.indexNpmLock(npmLock);

    assert.equal(index['npm-fixture'], undefined);
    assert.equal(index['workspace-pkg'], undefined);
});

test('reads the legacy npm dependencies tree', () => {
    const index = LockFiles.indexNpmLock(npmLegacyLock);

    assert.deepEqual(Object.keys(index).sort(), ['debug', 'left-pad']);
    assert.deepEqual(versions(index, 'debug'), ['4.3.4', '4.4.1']);
});

test('indexes scoped, plain and peer-suffixed pnpm keys', () => {
    const index = LockFiles.indexPnpmLock(pnpmLock);

    assert.deepEqual(versions(index, '@scope/tool'), ['2.0.0']);
    assert.deepEqual(versions(index, 'left-pad'), ['1.3.0']);
    assert.deepEqual(versions(index, 'vue-eslint-parser'), ['10.4.0']);
});

test('keeps every version of a pnpm lockfile', () => {
    assert.deepEqual(versions(LockFiles.indexPnpmLock(pnpmLock), 'debug'), ['4.3.4', '4.4.1']);
});

test('captures pnpm tarball resolutions', () => {
    assert.equal(LockFiles.indexPnpmLock(pnpmLock).tarballed[0].resolved, 'https://example.com/tarballed-1.0.0.tgz');
});

test('stops indexing at the end of the packages section', () => {
    assert.equal(LockFiles.indexPnpmLock(pnpmLock)['only-in-snapshots'], undefined);
});

test('reads legacy pnpm keys', () => {
    const index = LockFiles.indexPnpmLock(pnpmLegacyLock);

    assert.deepEqual(Object.keys(index).sort(), ['@scope/tool', 'debug', 'vue-eslint-parser']);
    assert.deepEqual(versions(index, 'vue-eslint-parser'), ['9.0.0']);
});

test('strips range operators declared in a package.json', () => {
    const index = LockFiles.indexManifest(manifest);

    assert.deepEqual(versions(index, 'left-pad'), ['1.3.0']);
    assert.deepEqual(versions(index, '@scope/tool'), ['2.0.0']);
    assert.deepEqual(versions(index, 'eslint'), ['9.39.4']);
    assert.deepEqual(versions(index, 'debug'), ['4.3.4']);
});

test('picks the parser from the file name', () => {
    assert.ok(LockFiles.indexFile(pnpmLock).debug);
    assert.ok(LockFiles.indexFile(npmLock).debug);
    assert.ok(LockFiles.indexFile(manifest).debug);
    assert.deepEqual(LockFiles.indexFile(path.join(root, 'manifest', 'unknown.txt')), {});
});

test('walks a repository for every indexable file', () => {
    const found = LockFiles.findIndexableFiles(root).map(file => path.basename(file));

    assert.equal(found.length, 5);
    assert.equal(found.filter(name => name === 'package-lock.json').length, 2);
    assert.equal(found.filter(name => name === 'pnpm-lock.yaml').length, 2);
    assert.equal(found.filter(name => name === 'package.json').length, 1);
});
