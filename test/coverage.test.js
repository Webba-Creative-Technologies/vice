import assert from 'node:assert/strict';
import test from 'node:test';

import { summarizeCoverage } from '../src/core/coverage.js';

test('coverage reports complete module execution', () => {
  const result = summarizeCoverage(['headers', 'tls'], [
    { module: 'headers', status: 'completed' },
    { module: 'tls', status: 'completed' },
  ]);

  assert.equal(result.status, 'complete');
  assert.equal(result.ratio, 1);
});

test('coverage exposes skipped modules', () => {
  const result = summarizeCoverage(['js', 'api'], [
    { module: 'crawl', status: 'completed' },
  ]);

  assert.equal(result.status, 'incomplete');
  assert.deepEqual(result.skipped, ['js', 'api']);
  assert.equal(result.ratio, 0);
});

test('coverage exposes failed modules', () => {
  const result = summarizeCoverage(['headers', 'tls'], [
    { module: 'headers', status: 'completed' },
    { module: 'tls', status: 'failed' },
  ]);

  assert.equal(result.status, 'partial');
  assert.deepEqual(result.failed, ['tls']);
  assert.equal(result.ratio, 0.5);
});

test('coverage ignores internal crawl instrumentation', () => {
  const result = summarizeCoverage(['js'], [
    { module: 'crawl', status: 'completed' },
    { module: 'js', status: 'completed' },
  ]);

  assert.deepEqual(result.completed, ['js']);
});

test('coverage becomes partial when a global budget is exhausted', () => {
  const result = summarizeCoverage(
    ['headers'],
    [{ module: 'headers', status: 'completed' }],
    { limitations: ['network_request_budget_exhausted'] },
  );

  assert.equal(result.status, 'partial');
  assert.equal(result.ratio, 1);
  assert.deepEqual(result.limitations, ['network_request_budget_exhausted']);
});
