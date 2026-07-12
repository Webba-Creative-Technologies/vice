import assert from 'node:assert/strict';
import test from 'node:test';

import { classifyTimingSamples } from '../src/core/detectors/timing.js';

test('repeated stable timing delays confirm a signal', () => {
  const result = classifyTimingSamples([110, 120, 115], [2120, 2150], 2000);

  assert.deepEqual(result, { controlMedian: 115, attackMedian: 2135, difference: 2020 });
});

test('one slow response does not confirm timing injection', () => {
  assert.equal(classifyTimingSamples([100, 110, 105], [2100, 130], 2000), null);
});

test('unstable baseline does not confirm timing injection', () => {
  assert.equal(classifyTimingSamples([100, 1500, 200], [2300, 2400], 2000), null);
});

test('insufficient samples are rejected', () => {
  assert.equal(classifyTimingSamples([100], [2200], 2000), null);
});
