import assert from 'node:assert/strict';
import test from 'node:test';

import { mapWithConcurrency } from '../src/core/concurrency.js';

test('concurrency mapper preserves order and respects limit', async () => {
  let active = 0;
  let maximum = 0;
  const result = await mapWithConcurrency([30, 5, 20, 1], 2, async (delay, index) => {
    active++;
    maximum = Math.max(maximum, active);
    await new Promise((resolve) => setTimeout(resolve, delay));
    active--;
    return index * 10;
  });

  assert.deepEqual(result, [0, 10, 20, 30]);
  assert.equal(maximum, 2);
});

test('concurrency mapper handles empty input', async () => {
  assert.deepEqual(await mapWithConcurrency([], 4, async () => 'unused'), []);
});
