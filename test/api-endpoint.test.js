import assert from 'node:assert/strict';
import test from 'node:test';

import { resolveFirstPartyApiEndpoint } from '../src/core/detectors/api-endpoint.js';

const target = 'https://app.example';

test('API audit resolves relative first-party endpoints', () => {
  assert.equal(
    resolveFirstPartyApiEndpoint(target, '/api/users'),
    'https://app.example/api/users',
  );
});

test('API audit rejects third-party endpoints carrying credentials', () => {
  assert.equal(
    resolveFirstPartyApiEndpoint(
      target,
      'https://discord.com/api/webhooks/123456789/secret-token',
    ),
    null,
  );
});

test('API audit rejects malformed endpoints', () => {
  assert.equal(resolveFirstPartyApiEndpoint(target, 'https://[invalid'), null);
});
