import assert from 'node:assert/strict';
import test from 'node:test';
import { classifyWordpressSurface } from '../src/core/detectors/wordpress.js';

test('WordPress login path is informational hardening', () => {
  const result = classifyWordpressSurface('default-login');
  assert.equal(result.severity, 'INFO');
  assert.equal(result.classification, 'hardening');
});

test('WordPress user enumeration is medium rather than high', () => {
  assert.equal(classifyWordpressSurface('author-enumeration').severity, 'MOYENNE');
  assert.equal(classifyWordpressSurface('rest-users').severity, 'MOYENNE');
});

test('WordPress HTTP cron remains a low-confidence heuristic', () => {
  const result = classifyWordpressSurface('http-cron');
  assert.equal(result.severity, 'FAIBLE');
  assert.equal(result.confidence, 'low');
});
