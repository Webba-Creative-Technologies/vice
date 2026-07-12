import assert from 'node:assert/strict';
import test from 'node:test';

import { classifyAuthenticatedSupabaseRead, classifySupabaseRead, classifySupabaseWrite, COMMON_SENSITIVE_TABLE_CANDIDATES, extractSupabaseTableCandidates, normalizeSupabaseSchemaTables } from '../src/core/detectors/supabase.js';

test('intentional public catalog data stays informational', () => {
  const result = classifySupabaseRead('products', [{ id: 1, name: 'Public item' }]);

  assert.equal(result.severity, 'INFO');
});

test('personal data exposed through Supabase is high severity', () => {
  const result = classifySupabaseRead('directory', [{ email: 'person@example.com' }]);

  assert.equal(result.severity, 'ELEVEE');
  assert.deepEqual(result.paths, ['[0].email']);
});

test('credential fields remain critical', () => {
  const result = classifySupabaseRead('config', [{ api_key: '0123456789abcdef' }]);

  assert.equal(result.severity, 'CRITIQUE');
});

test('sensitive table names raise otherwise generic reads', () => {
  const result = classifySupabaseRead('user_profiles', [{ id: 'user-1', theme: 'dark' }]);

  assert.equal(result.severity, 'ELEVEE');
});

test('Supabase table discovery extracts client calls and REST paths', () => {
  const tables = extractSupabaseTableCandidates([
    `client.from('newsletter_subscribers').select('*')`,
    'fetch("/rest/v1/player_bank_accounts?select=*")',
    `Array.from('not-a-table')`,
  ]);

  assert.deepEqual(tables, ['newsletter_subscribers', 'player_bank_accounts']);
  assert.deepEqual(normalizeSupabaseSchemaTables(['/scripts', '/rpc/search_docs', '/bad-name']), ['scripts']);
});

test('purchases and API key tables are sensitive by name', () => {
  assert.equal(classifySupabaseRead('purchases', [{ id: 'purchase-1' }]).severity, 'ELEVEE');
  assert.equal(classifySupabaseRead('platform_api_keys', [{ id: 'key-1' }]).severity, 'ELEVEE');
});

test('fallback inventory covers common server-side sensitive tables', () => {
  assert.ok(COMMON_SENSITIVE_TABLE_CANDIDATES.includes('platform_api_keys'));
  assert.ok(COMMON_SENSITIVE_TABLE_CANDIDATES.includes('player_bank_accounts'));
  assert.ok(COMMON_SENSITIVE_TABLE_CANDIDATES.includes('server_secrets'));
  assert.ok(COMMON_SENSITIVE_TABLE_CANDIDATES.length < 50);
});

test('financial and capability metadata is sensitive data', () => {
  const result = classifySupabaseRead('ledger', [{ account_no: 'MW-1234', balance: 500 }]);
  assert.equal(result.severity, 'ELEVEE');
  assert.deepEqual(result.paths, ['[0].account_no', '[0].balance']);
});

test('empty tables remain inconclusive', () => {
  assert.equal(classifySupabaseRead('users', []), null);
});

test('confirmed anonymous writes remain actionable', () => {
  assert.equal(classifySupabaseWrite('feedback', 201).severity, 'ELEVEE');
  assert.equal(classifySupabaseWrite('users', 201).severity, 'CRITIQUE');
  assert.equal(classifySupabaseWrite('feedback', 403), null);
});

test('authenticated reads distinguish owned and foreign personal rows', () => {
  const identity = { userId: 'user-1', email: 'audit@example.test' };
  const owned = classifyAuthenticatedSupabaseRead('profiles', [{ user_id: 'user-1', email: 'audit@example.test' }], identity);
  const foreign = classifyAuthenticatedSupabaseRead('profiles', [{ user_id: 'user-2', email: 'other@example.test' }], identity);

  assert.equal(owned.severity, 'INFO');
  assert.equal(foreign.severity, 'ELEVEE');
  assert.equal(foreign.classification, 'confirmed');
});

test('authenticated sensitive rows without ownership stay probable', () => {
  const result = classifyAuthenticatedSupabaseRead('profiles', [{ display_name: 'Someone' }], { userId: 'user-1' });
  assert.equal(result.severity, 'MOYENNE');
  assert.equal(result.confidence, 'medium');
});
