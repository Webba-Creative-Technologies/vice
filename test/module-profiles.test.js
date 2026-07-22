import assert from 'node:assert/strict';
import test from 'node:test';

import {
  ALL_MODULES,
  AVAILABLE_MODULES,
  DEFAULT_LIBRARY_MODULES,
  PASSIVE_MODULES,
  SPECIALIZED_MODULES,
} from '../src/core/modules.js';

const EXPECTED_FULL_MODULES = [
  'js',
  'files',
  'headers',
  'supabase',
  'authinjection',
  'vps',
  'attacks',
  'login',
  'stack',
  'subdomains',
  'dns',
  'api',
  'storage',
  'websocket',
  'tls',
  'wordpress',
];

test('full profile keeps all 16 engine modules', () => {
  assert.deepEqual(ALL_MODULES, EXPECTED_FULL_MODULES);
  assert.equal(new Set(ALL_MODULES).size, 16);
});

test('passive profile stays a strict full-profile subset', () => {
  assert.deepEqual(PASSIVE_MODULES, ['headers', 'tls', 'dns', 'stack', 'files', 'js']);
  assert.ok(PASSIVE_MODULES.every((module) => ALL_MODULES.includes(module)));
  assert.ok(!PASSIVE_MODULES.includes('attacks'));
  assert.ok(!PASSIVE_MODULES.includes('login'));
  assert.ok(!PASSIVE_MODULES.includes('storage'));
});

test('library defaults preserve the existing public API', () => {
  assert.deepEqual(DEFAULT_LIBRARY_MODULES, ['js', 'files', 'headers', 'supabase', 'stack', 'tls']);
});

test('specialized modules stay outside standard full scans', () => {
  assert.deepEqual(SPECIALIZED_MODULES, ['ai-rag']);
  assert.ok(!ALL_MODULES.includes('ai-rag'));
  assert.deepEqual(AVAILABLE_MODULES, [...ALL_MODULES, 'ai-rag']);
});

test('module profiles cannot be mutated by consumers', () => {
  assert.throws(() => ALL_MODULES.push('unknown'), TypeError);
  assert.throws(() => PASSIVE_MODULES.splice(0, 1), TypeError);
  assert.throws(() => SPECIALIZED_MODULES.push('unknown'), TypeError);
  assert.throws(() => AVAILABLE_MODULES.splice(0, 1), TypeError);
});
