import assert from 'node:assert/strict';
import test from 'node:test';
import { classifyDkimSearch } from '../src/core/detectors/dns-email.js';

test('known DKIM selector is confirmed informational evidence', () => {
  const result = classifyDkimSearch('selector1', ['default', 'selector1']);
  assert.equal(result.severity, 'INFO');
  assert.equal(result.confidence, 'high');
});

test('missing common DKIM selectors is inconclusive', () => {
  const result = classifyDkimSearch(null, ['default', 'selector1']);
  assert.equal(result.severity, 'INFO');
  assert.equal(result.confidence, 'low');
  assert.equal(result.classification, 'heuristic');
});
