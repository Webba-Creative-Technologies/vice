import test from 'node:test';
import assert from 'node:assert/strict';

import { classifyRateLimitEvidence } from '../src/core/detectors/rate-limit.js';

test('confirms enforcement from an HTTP 429 response', () => {
  const result = classifyRateLimitEvidence([
    { status: 401 },
    { status: 429, headers: { 'retry-after': '60' } },
  ]);

  assert.deepEqual(result, { state: 'enforced', attempt: 2, reason: 'HTTP 429' });
});

test('recognizes browser challenges and localized blocking messages', () => {
  const result = classifyRateLimitEvidence([
    { status: 200, body: 'Trop de tentatives, réessayez plus tard.' },
  ]);

  assert.equal(result.state, 'enforced');
  assert.equal(result.reason, 'blocking challenge');
});

test('recognizes declared limits without claiming they were triggered', () => {
  const result = classifyRateLimitEvidence([
    { status: 401, headers: { 'X-RateLimit-Limit': '100', 'X-RateLimit-Remaining': '95' } },
  ]);

  assert.equal(result.state, 'advertised');
  assert.deepEqual(result.headers, ['x-ratelimit-limit', 'x-ratelimit-remaining']);
});

test('does not infer a vulnerability from five ordinary responses', () => {
  const result = classifyRateLimitEvidence(
    Array.from({ length: 5 }, () => ({ status: 401, body: 'Invalid credentials' })),
  );

  assert.equal(result.state, 'inconclusive');
  assert.match(result.reason, /cannot prove/i);
});
