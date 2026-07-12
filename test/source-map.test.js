import assert from 'node:assert/strict';
import test from 'node:test';

import { analyzeSourceMap } from '../src/core/detectors/source-map.js';

test('invalid source map responses are ignored', () => {
  assert.equal(analyzeSourceMap('<html>not a map</html>'), null);
  assert.equal(analyzeSourceMap('{"status":"ok"}'), null);
});

test('ordinary client source maps stay low severity', () => {
  const result = analyzeSourceMap(JSON.stringify({
    version: 3,
    sources: ['src/app.ts'],
    sourcesContent: ['export const app = true;'],
    mappings: '',
  }));

  assert.equal(result.kind, 'source-metadata');
  assert.equal(result.severity, 'FAIBLE');
});

test('embedded credential material makes source maps critical', () => {
  const result = analyzeSourceMap(JSON.stringify({
    version: 3,
    sources: ['src/config.ts'],
    sourcesContent: ['export const stripe = "sk_live_1234567890abcdefghijkl";'],
    mappings: '',
  }));

  assert.equal(result.kind, 'credentials');
  assert.equal(result.severity, 'CRITIQUE');
  assert.deepEqual(result.secretTypes, ['Stripe Secret Key']);
  assert.equal(JSON.stringify(result).includes('sk_live_'), false);
});

test('server source paths raise exposure severity without secrets', () => {
  const result = analyzeSourceMap(JSON.stringify({
    version: 3,
    sources: ['backend/auth/controller.ts'],
    sourcesContent: ['export function login() {}'],
    mappings: '',
  }));

  assert.equal(result.kind, 'sensitive-sources');
  assert.equal(result.severity, 'MOYENNE');
});

test('source maps ignore public credential identifiers', () => {
  const result = analyzeSourceMap(JSON.stringify({
    version: 3,
    sources: ['src/api.ts'],
    sourcesContent: ['const SUPABASE_ANON_KEY = "public"; fetch(url, { headers: { apikey: SUPABASE_ANON_KEY } });'],
    mappings: '',
  }));

  assert.equal(result.kind, 'source-metadata');
  assert.deepEqual(result.secretTypes, []);
});
