// Store-level tests: append-only invariant, masking, name validation.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { Store, isValidBaseName, MASK_PLACEHOLDER } from '../store.js';

function freshStore() {
  const dir = mkdtempSync(join(tmpdir(), 'sm-store-'));
  return { store: new Store(join(dir, 'data.json')), dir };
}

test('append-only: auto-increments, preserves old versions, never overwrites', () => {
  const { store, dir } = freshStore();
  try {
    assert.equal(store.addVersion('FOO', 'v1-secret').version, 1);
    assert.equal(store.addVersion('FOO', 'v2-secret').version, 2);

    // Previous version's value is unchanged after appending.
    assert.equal(store.data.FOO['1'], 'v1-secret');
    assert.equal(store.data.FOO['2'], 'v2-secret');

    // A new base name starts at version 1.
    assert.equal(store.addVersion('BAR', 'bar-1').version, 1);

    // There is no API to overwrite — appending again only ever adds max+1.
    assert.equal(store.addVersion('FOO', 'v3-secret').version, 3);
    assert.equal(store.data.FOO['1'], 'v1-secret');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('persistence: a reopened store loads the same data from disk', () => {
  const dir = mkdtempSync(join(tmpdir(), 'sm-store-'));
  try {
    const path = join(dir, 'data.json');
    new Store(path).addVersion('FOO', 'persisted');
    const reopened = new Store(path);
    assert.equal(reopened.data.FOO['1'], 'persisted');
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('masking: listMasked never leaks real values and uses the fixed placeholder', () => {
  const { store, dir } = freshStore();
  try {
    store.addVersion('FOO', 'super-secret-value');
    store.addVersion('FOO', 'another-secret');
    const keys = store.listMasked();

    assert.ok(!JSON.stringify(keys).includes('super-secret-value'));
    assert.ok(!JSON.stringify(keys).includes('another-secret'));
    for (const v of keys[0].versions) {
      assert.equal(v.masked, MASK_PLACEHOLDER);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});

test('name validation: rejects reserved _V<n> suffix and non-upper-snake names', () => {
  assert.equal(isValidBaseName('FOO'), true);
  assert.equal(isValidBaseName('OPENAI_AUTHORIZATION_KEY'), true);
  assert.equal(isValidBaseName('A_VERSION'), true); // _VERSION is not _V<n>

  assert.equal(isValidBaseName('FOO_V2'), false); // reserved version suffix
  assert.equal(isValidBaseName('foo'), false); // lowercase
  assert.equal(isValidBaseName('FOO-BAR'), false); // hyphen
  assert.equal(isValidBaseName(''), false);
  assert.equal(isValidBaseName(undefined), false);
});
