import assert from 'node:assert/strict';
import test from 'node:test';

import { classifyCorsPolicy } from '../src/core/detectors/cors.js';

const evilOrigin = 'https://evil.example';

test('CORS confirms reflected origins with credentials', () => {
  const result = classifyCorsPolicy({
    requestOrigin: evilOrigin,
    allowOrigin: evilOrigin,
    allowCredentials: 'true',
  });

  assert.equal(result.kind, 'reflected-origin-with-credentials');
  assert.equal(result.severity, 'CRITIQUE');
});

test('CORS lowers reflected origins without credentials', () => {
  const result = classifyCorsPolicy({
    requestOrigin: evilOrigin,
    allowOrigin: evilOrigin,
    allowCredentials: 'false',
  });

  assert.equal(result.kind, 'reflected-origin');
  assert.equal(result.severity, 'MOYENNE');
});

test('CORS treats public wildcard as informational', () => {
  const result = classifyCorsPolicy({
    requestOrigin: evilOrigin,
    allowOrigin: '*',
  });

  assert.equal(result.kind, 'public-wildcard');
  assert.equal(result.severity, 'INFO');
});

test('CORS does not claim wildcard credentials are exploitable', () => {
  const result = classifyCorsPolicy({
    requestOrigin: evilOrigin,
    allowOrigin: '*',
    allowCredentials: 'true',
  });

  assert.equal(result.kind, 'wildcard-with-credentials');
  assert.equal(result.severity, 'INFO');
});

test('CORS ignores a nonmatching allowlist origin', () => {
  assert.equal(classifyCorsPolicy({
    requestOrigin: evilOrigin,
    allowOrigin: 'https://app.example',
    allowCredentials: 'true',
  }), null);
});
