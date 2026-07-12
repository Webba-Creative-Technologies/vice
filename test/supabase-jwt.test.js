import assert from 'node:assert/strict';
import test from 'node:test';

import { classifySupabaseJwt, isPublicSupabaseAnonMatch, SECRET_PATTERNS } from '../src/utils/patterns.js';

const header = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9';

function makeJwt(role) {
  const payload = Buffer.from(JSON.stringify({ role, iss: 'supabase', exp: 9999999999 })).toString('base64url');
  return `${header}.${payload}.testsignature`;
}

function matchingSupabasePatterns(token) {
  return SECRET_PATTERNS
    .filter((pattern) => pattern.name.startsWith('Supabase ') && pattern.name !== 'Supabase URL')
    .filter((pattern) => {
      pattern.regex.lastIndex = 0;
      const match = pattern.regex.exec(token);
      return match && (!pattern.validate || pattern.validate(match[0]));
    })
    .map((pattern) => pattern.name);
}

test('Supabase JWT role decoder distinguishes anon tokens', () => {
  const token = makeJwt('anon');

  assert.equal(classifySupabaseJwt(token), 'anon');
  assert.deepEqual(matchingSupabasePatterns(token), []);
});

test('Supabase JWT role decoder distinguishes service tokens', () => {
  const token = makeJwt('service_role');

  assert.equal(classifySupabaseJwt(token), 'service_role');
  assert.deepEqual(matchingSupabasePatterns(token), ['Supabase Service Role']);
});

test('Supabase JWT role decoder rejects malformed values', () => {
  assert.equal(classifySupabaseJwt('not-a-jwt'), null);
});

test('public anon tokens are ignored in bearer and api key contexts', () => {
  const token = makeJwt('anon');
  const bearer = `Bearer ${token}`;
  const source = `const config={apiKey:"${token}"}`;
  const apiKeyMatch = `apiKey:"${token.split('.')[0]}`;

  assert.equal(isPublicSupabaseAnonMatch(bearer, bearer, 0), true);
  assert.equal(isPublicSupabaseAnonMatch(source, apiKeyMatch, source.indexOf(apiKeyMatch)), true);
});
