/**
 * What counts as a match against the malicious-package list, and what does not.
 *
 * Both halves matter: a rule that under-matches lets a listed release through,
 * and one that over-matches refuses installs that were never in question, which
 * is the fastest way to have the whole check switched off.
 */

import assert from 'node:assert/strict';
import test from 'node:test';
import Compromised from '../src/compromised/Compromised.mjs';

const LIST = { 'all-bad': null, 'some-bad': ['0.0.7', '1.2.3'] };

test('flags every version when the list names none', () => {
    assert.match(Compromised.reason(LIST, 'all-bad', '1.0.0'), /every published version/);
    assert.match(Compromised.reason(LIST, 'all-bad', '99.0.0'), /every published version/);
});

test('flags only the versions the list names', () => {
    assert.match(Compromised.reason(LIST, 'some-bad', '0.0.7'), /this exact version/);
    assert.equal(Compromised.reason(LIST, 'some-bad', '0.0.8'), null);
});

test('recognises a listed release through the tarball it resolves to', () => {
    const resolved = 'https://registry.npmjs.org/some-bad/-/some-bad-1.2.3.tgz';

    assert.match(Compromised.reason(LIST, 'some-bad', 'unknown', resolved), /1\.2\.3/);
    assert.equal(Compromised.reason(LIST, 'some-bad', 'unknown', ''), null);
});

test('says nothing about a package that is not on the list', () => {
    assert.equal(Compromised.reason(LIST, 'left-pad', '1.3.0'), null);
});

test('does not match packages named after an Object prototype member', () => {
    assert.equal(Compromised.reason(LIST, 'constructor', '1.0.0'), null);
    assert.equal(Compromised.reason(LIST, 'toString', '1.0.0'), null);
});

test('judges a version-less subject by name alone, which is what a range is', () => {
    // A manifest declares "^1.0.0", not a version - only an entry covering every
    // published version says anything certain about it.
    assert.match(Compromised.reason(LIST, 'all-bad'), /every published version/);
    assert.equal(Compromised.reason(LIST, 'some-bad'), null);
});

test('has no opinion at all when the check is switched off', () => {
    assert.equal(Compromised.reason(null, 'all-bad', '1.0.0'), null);
    assert.deepEqual(Compromised.find(null, { 'all-bad': [{ version: '1.0.0', resolved: '' }] }), []);
});

test('reports every compromised entry of an index', () => {
    const index = {
        'all-bad': [{ version: '1.0.0', resolved: '' }],
        'some-bad': [
            { version: '0.0.7', resolved: '' },
            { version: '0.0.8', resolved: '' },
        ],
        'left-pad': [{ version: '1.3.0', resolved: '' }],
    };

    const found = Compromised.find(LIST, index);

    assert.deepEqual(
        found.map(({ name, version }) => `${name}@${version}`),
        ['all-bad@1.0.0', 'some-bad@0.0.7']
    );
});

test('turns a list that could not be obtained into a violation, and a missing source into none', () => {
    assert.equal(Compromised.listViolation({ index: LIST, reason: null }), null);
    assert.equal(Compromised.listViolation({ index: null, reason: null }), null);

    const violation = Compromised.listViolation({ index: null, source: 'https://example.com/list.json', reason: 'timed out' });
    assert.equal(violation.rule, 'compromised-list-unavailable');
    assert.match(violation.reason, /timed out/);
});
