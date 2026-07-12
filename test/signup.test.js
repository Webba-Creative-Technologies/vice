import assert from 'node:assert/strict';
import test from 'node:test';

import { classifySignupResponse } from '../src/core/detectors/signup.js';

test('public signup with immediate session remains informational', () => {
  const result = classifySignupResponse(200, { user: { id: 'user-1' }, access_token: 'token' });
  assert.equal(result.severity, 'INFO');
  assert.equal(result.kind, 'immediate-session');
});

test('confirmation signup and rejected signup are distinguished', () => {
  assert.equal(classifySignupResponse(200, { user: { id: 'user-1' } }).kind, 'confirmation');
  assert.equal(classifySignupResponse(422, { message: 'validation' }).kind, 'restricted');
  assert.equal(classifySignupResponse(429, {}).kind, 'rate-limited');
});
