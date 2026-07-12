import test from 'node:test';
import assert from 'node:assert/strict';

import { boundedAdd, boundedPush } from '../src/core/budget.js';

test('boundedAdd preserves uniqueness without exceeding its budget', () => {
  const values = new Set(['first']);

  assert.equal(boundedAdd(values, 'first', 2), true);
  assert.equal(boundedAdd(values, 'second', 2), true);
  assert.equal(boundedAdd(values, 'third', 2), false);
  assert.deepEqual([...values], ['first', 'second']);
});

test('boundedPush rejects values after its budget', () => {
  const values = [];

  assert.equal(boundedPush(values, 'first', 1), true);
  assert.equal(boundedPush(values, 'second', 1), false);
  assert.deepEqual(values, ['first']);
});
