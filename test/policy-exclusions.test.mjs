import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import test, { after } from 'node:test';
import Rules from '../src/policy/Rules.mjs';
import ArgvGuard from '../src/guards/ArgvGuard.mjs';
import ManifestGuard from '../src/guards/ManifestGuard.mjs';
import PnpmGuard from '../src/guards/PnpmGuard.mjs';

const root = fs.mkdtempSync(path.join(os.tmpdir(), 'secure-npm-exclude-'));
after(() => fs.rmSync(root, { recursive: true, force: true }));

/** A compiled policy, shaped like Policy.#compile returns one. **/
function policy(exclude = []) {
    return {
        minimumReleaseAgeMinutes: 0,
        minimumReleaseAgeExclude: new Set(),
        allowExoticSources: false,
        allowedGitSources: [],
        blockedPackages: [
            { pattern: /^yarn$/, source: '^yarn$', reason: 'yarn package manager' },
            { pattern: /^@oven\//, source: '^@oven/', reason: 'bun platform binaries' },
        ],
        blockedPackagesExclude: new Set(exclude),
        blockedManagers: new Map([['yarn', 'yarn is not an approved package manager on this machine']]),
        registries: { default: 'https://registry.npmjs.org/' },
    };
}

function project(directory, files) {
    const dir = path.join(root, directory);
    fs.mkdirSync(dir, { recursive: true });
    for (const [name, content] of Object.entries(files)) fs.writeFileSync(path.join(dir, name), content);
    return dir;
}

const lockfile = versions =>
    ['lockfileVersion: \'9.0\'', '', 'packages:', '', ...versions.flatMap(version => [`  yarn@${version}:`, '    resolution: {integrity: sha512-fixture}', ''])].join('\n');

test('a bare name waives every version of the package', () => {
    const config = policy(['yarn']);

    assert.equal(Rules.dependencyBlockReason(config, 'yarn', '1.22.22'), null);
    assert.equal(Rules.dependencyBlockReason(config, 'yarn', '4.0.0'), null);
});

test('a pinned entry waives that version and no other', () => {
    const config = policy(['yarn@1.22.22']);

    assert.equal(Rules.dependencyBlockReason(config, 'yarn', '1.22.22'), null);
    assert.match(Rules.dependencyBlockReason(config, 'yarn', '1.23.0') ?? '', /yarn package manager/);
});

test('a pinned entry waives the name where no version is known yet', () => {
    // The pnpm hook sees a range on the way in; the exact version is judged
    // again when pnpm resolves the package itself.
    assert.equal(Rules.dependencyBlockReason(policy(['yarn@1.22.22']), 'yarn'), null);
    assert.match(Rules.dependencyBlockReason(policy(['yarnpkg@1.0.0']), 'yarn') ?? '', /yarn package manager/);
});

test('the exclusion is exact, never a prefix or a pattern', () => {
    const config = policy(['yarn']);

    assert.match(Rules.dependencyBlockReason(config, '@oven/bun-linux-x64', '1.0.0') ?? '', /bun platform binaries/);
    assert.equal(Rules.isBlockExempt(config, 'yarn-berry'), false);
    assert.equal(Rules.isBlockExempt(config, '^yarn$'), false);
});

test('a package nothing blocks is unaffected either way', () => {
    assert.equal(Rules.dependencyBlockReason(policy([]), 'lodash', '4.17.21'), null);
    assert.equal(Rules.dependencyBlockReason(policy(['yarn']), 'lodash', '4.17.21'), null);
});

test('blockedPackageReason itself never consults the exclusion', () => {
    assert.match(Rules.blockedPackageReason(policy(['yarn']), 'yarn') ?? '', /yarn package manager/);
});

test('an excluded package is still refused as a command-line target', () => {
    const violations = ArgvGuard.inspect(policy(['yarn', 'yarn@1.22.22']), 'npm', ['install', 'yarn']);
    const blocked = violations.find(violation => violation.rule === 'blocked-package');

    assert.ok(blocked, 'npm install yarn should still be refused');
    assert.match(blocked.hint, /only covers a package pulled in as a dependency/);
});

test('an excluded package is still refused as an authored dependency', () => {
    const cwd = project('authored', {
        'package.json': JSON.stringify({ name: 'app', dependencies: { yarn: '^1.22.22' } }),
    });

    const violations = ManifestGuard.inspect(policy(['yarn@1.22.22']), cwd);
    assert.equal(violations.length, 1);
    assert.equal(violations[0].rule, 'blocked-package');
});

test('a pnpm lockfile clears the pinned version and refuses the others', () => {
    const cwd = project('locked', { 'pnpm-lock.yaml': lockfile(['1.22.22', '1.23.0']) });

    const { violations, count } = PnpmGuard.inspectLockfile(policy(['yarn@1.22.22']), cwd);

    assert.equal(count, 2, 'both entries are looked at');
    assert.equal(violations.length, 1);
    assert.match(violations[0].subject, /yarn@1\.23\.0/);
    assert.match(violations[0].hint, /blockedPackagesExclude/);
});

test('a pnpm lockfile with no waiver refuses every entry', () => {
    const cwd = project('unlocked', { 'pnpm-lock.yaml': lockfile(['1.22.22', '1.23.0']) });

    const { violations } = PnpmGuard.inspectLockfile(policy([]), cwd);
    assert.equal(violations.length, 2);
});
