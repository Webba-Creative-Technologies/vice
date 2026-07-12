import assert from 'node:assert/strict';
import test from 'node:test';

import { createScanMetrics } from '../src/core/metrics.js';

test('metrics record completed module duration and findings', async () => {
  let time = 100;
  let findings = 2;
  const metrics = createScanMetrics({
    now: () => time,
    getFindingCount: () => findings,
  });

  await metrics.run('headers', async () => {
    time += 24.6;
    findings += 3;
  });
  time += 5;

  assert.deepEqual(metrics.finish(), {
    total_duration_ms: 30,
    steps: [{
      module: 'headers',
      status: 'completed',
      duration_ms: 25,
      findings_added: 3,
    }],
  });
});

test('metrics record failed modules without swallowing errors', async () => {
  let time = 0;
  const metrics = createScanMetrics({ now: () => time });

  await assert.rejects(
    metrics.run('tls', async () => {
      time = 12;
      throw new Error('handshake failed');
    }),
    /handshake failed/,
  );

  assert.deepEqual(metrics.finish().steps, [{
    module: 'tls',
    status: 'failed',
    duration_ms: 12,
    findings_added: 0,
  }]);
});
