// store.js — load/save data.json, append-only versioning, masking.
//
// Data model (single JSON file):
//   { "<BASE_NAME>": { "<version>": "<secret>" } }
// Top-level keys are base names; nested keys are version numbers (as strings).

import { readFileSync, writeFileSync, renameSync, existsSync, mkdirSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { randomBytes } from 'node:crypto';

/** Fixed placeholder shown by the admin UI — never derived from a real value. */
export const MASK_PLACEHOLDER = '••••••'; // ••••••

/** Read data.json into a plain object. Missing/empty file → {}. */
export function loadData(filePath) {
  if (!existsSync(filePath)) return {};
  const raw = readFileSync(filePath, 'utf8').trim();
  if (!raw) return {};
  return JSON.parse(raw);
}

/**
 * Write data atomically: serialize to a temp file in the same directory, then
 * rename over the target. A crash mid-write leaves the old file intact.
 */
export function saveData(filePath, data) {
  const dir = dirname(filePath);
  mkdirSync(dir, { recursive: true });
  const tmp = join(dir, `.data.${randomBytes(8).toString('hex')}.tmp`);
  writeFileSync(tmp, JSON.stringify(data, null, 2));
  renameSync(tmp, filePath); // atomic replace on POSIX and Windows
}

/** Split a pointer `<BASE>_V<n>` → { base, version }, or null if it doesn't match. */
export function parsePointer(pointer) {
  const m = /^(.+)_V(\d+)$/.exec(pointer);
  if (!m) return null;
  return { base: m[1], version: m[2] };
}

/**
 * A base name is valid when it is upper-snake (^[A-Z0-9_]+$) and does NOT end in
 * the reserved version suffix `_V<n>` (that shape belongs to pointers).
 */
export function isValidBaseName(name) {
  if (typeof name !== 'string') return false;
  if (!/^[A-Z0-9_]+$/.test(name)) return false;
  if (/_V\d+$/.test(name)) return false;
  return true;
}

export class Store {
  constructor(filePath) {
    this.filePath = filePath;
    this.data = loadData(filePath);
  }

  /** Next version for a base name: max(existing) + 1, or 1 for a new base name. */
  nextVersion(name) {
    const versions = this.data[name];
    if (!versions) return 1;
    return Math.max(...Object.keys(versions).map(Number)) + 1;
  }

  /**
   * Append a value as the next version of `name` (creating the base name at
   * version 1 if new). Existing versions are immutable — this never overwrites.
   * Returns { name, version }.
   */
  addVersion(name, value) {
    const version = this.nextVersion(name);
    if (!this.data[name]) this.data[name] = {};
    this.data[name][String(version)] = value;
    saveData(this.filePath, this.data);
    return { name, version };
  }

  /**
   * Resolve a batch of pointers to real values. Pointers that don't parse or
   * don't exist are omitted from the result (the caller decides if that's fatal).
   */
  resolve(pointers) {
    const values = {};
    for (const pointer of pointers) {
      const parsed = parsePointer(pointer);
      if (!parsed) continue;
      const value = this.data[parsed.base]?.[parsed.version];
      if (value !== undefined) values[pointer] = value;
    }
    return values;
  }

  /** Return the real stored value for a base name + version, or undefined if absent. */
  getValue(name, version) {
    return this.data[name]?.[String(version)];
  }

  /** Admin listing — base names + versions, values masked. Never returns secrets. */
  listMasked() {
    return Object.keys(this.data)
      .sort()
      .map((name) => ({
        name,
        versions: Object.keys(this.data[name])
          .map(Number)
          .sort((a, b) => a - b)
          .map((version) => ({ version, masked: MASK_PLACEHOLDER })),
      }));
  }
}
