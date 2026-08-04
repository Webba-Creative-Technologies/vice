import assert from 'node:assert/strict';
import test from 'node:test';

import { classifyPublicJson } from '../src/core/detectors/public-json.js';

test('public operational JSON stays informational', () => {
  const result = classifyPublicJson({ status: 'ok', userCount: 42, accountType: 'public' });

  assert.equal(result.kind, 'public-json');
  assert.equal(result.severity, 'INFO');
});

test('credential fields require meaningful values', () => {
  const result = classifyPublicJson({
    access_token: 'eyJhbGciOiJIUzI1NiJ9.payload.signature',
  });

  assert.equal(result.kind, 'credentials');
  assert.equal(result.severity, 'CRITIQUE');
  assert.deepEqual(result.paths, ['access_token']);
});

test('redacted secrets are not reported as exposed credentials', () => {
  const result = classifyPublicJson({ secret: 'redacted', token: null });

  assert.equal(result.kind, 'public-json');
});

test('provider-formatted placeholders are not exposed credentials', () => {
  const result = classifyPublicJson({
    secret: ['sk', 'test', 'x'.repeat(24)].join('_'),
    token: 'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
    api_key: 'VITE_PUBLIC_API_KEY',
  });

  assert.equal(result.kind, 'public-json');
});

test('personal data is classified from exact field names', () => {
  const result = classifyPublicJson({
    users: [
      { email: 'first@example.com' },
      { email: 'second@example.com', phone_number: '+33123456789' },
    ],
  });

  assert.equal(result.kind, 'personal-data');
  assert.equal(result.severity, 'ELEVEE');
  assert.deepEqual(result.paths, ['users[0].email', 'users[1].email', 'users[1].phone_number']);
});

test('similar field names do not trigger sensitive classification', () => {
  const result = classifyPublicJson({
    token_required: true,
    password_enabled: false,
    email_support_enabled: true,
  });

  assert.equal(result.kind, 'public-json');
});

test('ordinary token and permission metadata stays informational', () => {
  const result = classifyPublicJson({ token: 'next-page', permissions: ['read'], scopes: ['catalog'] });
  assert.equal(result.kind, 'public-json');
});

test('password capability states are not treated as credentials', () => {
  const result = classifyPublicJson({ password: 'disabled', password_hash: 'not-set' });
  assert.equal(result.kind, 'public-json');
});
