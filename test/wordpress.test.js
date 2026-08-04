import assert from 'node:assert/strict';
import test from 'node:test';
import { classifyWordpressSurface } from '../src/core/detectors/wordpress.js';

test('WordPress login path is informational hardening', () => {
  const result = classifyWordpressSurface('default-login');
  assert.equal(result.severity, 'INFO');
  assert.equal(result.classification, 'hardening');
});

test('WordPress public author identities are informational', () => {
  assert.equal(classifyWordpressSurface('author-enumeration').severity, 'INFO');
  assert.equal(classifyWordpressSurface('rest-users').severity, 'INFO');
});

test('WordPress HTTP cron remains a low-confidence heuristic', () => {
  const result = classifyWordpressSurface('http-cron');
  assert.equal(result.severity, 'INFO');
  assert.equal(result.confidence, 'low');
});
