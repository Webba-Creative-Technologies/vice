import assert from 'node:assert/strict';
import test from 'node:test';

import { classifyHardeningSignal } from '../src/core/detectors/hardening.js';

test('missing CSP is a low-severity hardening signal', () => {
  assert.deepEqual(classifyHardeningSignal('missing-csp'), {
    severity: 'FAIBLE',
    category: 'hardening',
  });
});

test('public API documentation is informational', () => {
  assert.deepEqual(classifyHardeningSignal('public-api-docs'), {
    severity: 'INFO',
    category: 'exposure',
  });
});

test('GraphQL introspection is not classified as a vulnerability', () => {
  assert.equal(classifyHardeningSignal('graphql-introspection').severity, 'INFO');
});

test('unknown hardening signals are ignored', () => {
  assert.equal(classifyHardeningSignal('unknown'), null);
});
