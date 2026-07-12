import assert from 'node:assert/strict';
import test from 'node:test';

import {
  addDiscoveredIp,
  addFinding,
  clearFindings,
  getDiscoveredIps,
  getFindings,
} from '../src/core/findings.js';

test('finding manager merges exact duplicate findings', () => {
  clearFindings();
  addFinding('LOW', 'Headers', 'Missing header', 'X-Test is missing', 'Add it');
  addFinding('LOW', 'Headers', 'Missing header', 'X-Test is missing', 'Add it');

  assert.equal(getFindings().length, 1);
  assert.equal(getFindings()[0].occurrences, 2);
  clearFindings();
});

test('finding manager preserves separate file locations', () => {
  clearFindings();
  addFinding('HIGH', 'Code', 'Dynamic SQL', 'query interpolation', 'Parameterize', { file: 'a.js' });
  addFinding('HIGH', 'Code', 'Dynamic SQL', 'query interpolation', 'Parameterize', { file: 'b.js' });

  assert.equal(getFindings().length, 2);
  clearFindings();
});

test('finding manager lets classification infer confidence', () => {
  clearFindings();
  addFinding('HIGH', 'Code', 'Potential unsafe sink', 'Untrusted flow is not proven', 'Review it');

  assert.equal(getFindings()[0].classification, 'heuristic');
  assert.equal(getFindings()[0].confidence, 'low');
  clearFindings();
});

test('clearing findings also clears scan discovery state', () => {
  addDiscoveredIp('203.0.113.10');
  clearFindings();

  assert.deepEqual(getDiscoveredIps(), []);
});
