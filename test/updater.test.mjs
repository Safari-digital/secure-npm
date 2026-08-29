import assert from 'node:assert/strict';
import test from 'node:test';
import Updater from '../src/install/Updater.mjs';

test('a strictly newer x.y.z wins, whatever the segment widths', () => {
    assert.equal(Updater.newerVersion('1.3.0', '1.2.1'), true);
    assert.equal(Updater.newerVersion('1.10.0', '1.9.9'), true);
    assert.equal(Updater.newerVersion('2.0.0', '1.99.99'), true);
    assert.equal(Updater.newerVersion('1.2.1.1', '1.2.1'), true);
});

test('an equal or older version does not', () => {
    assert.equal(Updater.newerVersion('1.2.1', '1.2.1'), false);
    assert.equal(Updater.newerVersion('1.2.0', '1.2.1'), false);
    assert.equal(Updater.newerVersion('1.2', '1.2.0'), false);
});

test('an unparseable version never claims to be newer', () => {
    assert.equal(Updater.newerVersion('abc', '1.0.0'), false);
    assert.equal(Updater.newerVersion('1.0.0', 'abc'), false);
    assert.equal(Updater.newerVersion(null, '1.0.0'), false);
    assert.equal(Updater.newerVersion('1.0.0', undefined), false);
});
