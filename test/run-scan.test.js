import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';

import { buildBlackBoxReport, calculateScanScore, runScan } from '../scan.js';

test('black-box score caps duplicates and excludes low-confidence signals', () => {
  const lowConfidence = Array.from({ length: 5 }, () => ({
    severity: 'CRITIQUE',
    rule_id: 'vice/test/heuristic',
    confidence: 'low',
  }));
  const confirmed = Array.from({ length: 5 }, () => ({
    severity: 'CRITIQUE',
    rule_id: 'vice/test/confirmed',
    confidence: 'high',
  }));

  assert.equal(calculateScanScore(lowConfidence).score, 100);
  assert.equal(calculateScanScore(confirmed).score, 55);
});

test('runScan rejects private targets unless explicitly enabled', async () => {
  await assert.rejects(
    runScan({ url: 'http://127.0.0.1', modules: ['headers'], requestTimeoutMs: 50 }),
    { code: 'blocked_private_target' },
  );
});

test('runScan integrates findings, metrics, and coverage locally', async () => {
  const progress = [];
  const server = http.createServer((request, response) => {
    if (request.url === '/') {
      response.setHeader('content-type', 'text/html');
      response.end('<html><body>VICE local fixture home page</body></html>');
      return;
    }
    if (request.url === '/.env') {
      response.setHeader('content-type', 'text/plain');
      response.end('DATABASE_URL=postgresql://fixture:fixture@localhost/app\n');
      return;
    }
    response.statusCode = 404;
    response.end('not found');
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();

  try {
    const result = await runScan({
      url: `http://127.0.0.1:${address.port}`,
      modules: ['files'],
      requestTimeoutMs: 1000,
      allowPrivateTargets: true,
      onProgress: (event) => progress.push(event),
    });

    assert.deepEqual(result.modules, ['files']);
    assert.equal(result.coverage.status, 'complete');
    assert.equal(result.score_reliable, true);
    assert.equal(result.scoring_version, '2026.07.11.3');
    assert.equal(result.metrics.steps[0].module, 'files');
    assert.ok(result.metrics.network.network_requests > 0);
    assert.equal(progress.some((event) => event.stage === 'start' && event.module === 'files'), true);
    assert.equal(progress.some((event) => event.stage === 'progress' && event.module === 'files'), true);
    assert.equal(progress.some((event) => event.stage === 'complete' && event.module === 'files'), true);

    const exposedEnv = result.findings.find((finding) => finding.title.includes('/.env'));
    assert.equal(exposedEnv?.severity, 'CRITIQUE');
    assert.match(exposedEnv?.rule_id || '', /^vice\//);
    assert.match(exposedEnv?.fingerprint || '', /^[a-f0-9]{16}$/);
    assert.equal(exposedEnv?.engine_version, '3.4.0');
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});

test('black-box reports explain score and coverage', () => {
  const score = calculateScanScore([
    { severity: 'CRITIQUE', rule_id: 'vice/test/confirmed', confidence: 'high' },
    { severity: 'FAIBLE', rule_id: 'vice/test/heuristic', confidence: 'low' },
  ]);
  const report = buildBlackBoxReport('https://example.test', {
    ...score,
    score_breakdown: score,
    findings: [],
    modules: ['headers'],
    errors: [],
    coverage: { status: 'partial', limitations: ['network_budget_exhausted'] },
    score_reliable: false,
  }, '2026-07-12T00:00:00.000Z');

  assert.equal(report.engine_version, '3.4.0');
  assert.equal(report.ruleset_version, '2026.07.22.1');
  assert.equal(report.score_reliable, false);
  assert.equal(report.score_breakdown.total_penalty, 15);
  assert.equal(report.score_breakdown.excluded.confidence, 1);
});

test('runScan waits for declared client bundles before analysis', async () => {
  const server = http.createServer((request, response) => {
    if (request.url === '/') {
      response.setHeader('content-type', 'text/html');
      response.end('<html><body><script src="/app.js"></script></body></html>');
      return;
    }
    if (request.url === '/app.js') {
      response.setHeader('content-type', 'application/javascript');
      response.end('window.gameServer = "http://203.0.113.42:30121";');
      return;
    }
    response.statusCode = 404;
    response.end('not found');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));

  try {
    const result = await runScan({
      url: `http://127.0.0.1:${server.address().port}`,
      modules: ['js'],
      requestTimeoutMs: 1000,
      allowPrivateTargets: true,
    });

    assert.equal(result.findings.some(finding => (
      finding.rule_id === 'vice/discovery/public-ip-reference'
      && finding.detail.includes('203.0.113.42:30121')
    )), true);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('Supabase-only scans use client table fallback without web findings', async () => {
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://fixture.local');
    if (url.pathname === '/') {
      response.setHeader('content-type', 'text/html');
      response.end(`<html><body><script>window.db={from(){return {}}};window.db.from('newsletter_subscribers')</script></body></html>`);
      return;
    }
    if (url.pathname === '/rest/v1/') {
      response.statusCode = 401;
      response.setHeader('content-type', 'application/json');
      response.end('{"message":"schema hidden"}');
      return;
    }
    if (url.pathname === '/rest/v1/newsletter_subscribers') {
      response.setHeader('content-type', 'application/json');
      response.end('[{"email":"person@example.test","unsubscribe_token":"capability-token"}]');
      return;
    }
    if (url.pathname === '/auth/v1/settings') {
      response.setHeader('content-type', 'application/json');
      response.end('{"external":{},"disable_signup":true}');
      return;
    }
    response.statusCode = 404;
    response.end('not found');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const baseUrl = `http://127.0.0.1:${server.address().port}`;

  try {
    const result = await runScan({
      url: baseUrl,
      modules: ['supabase'],
      supabaseUrl: baseUrl,
      supabaseKey: 'fixture-anon-key',
      allowPrivateTargets: true,
    });

    assert.equal(result.findings.some(finding => finding.module === 'SRI' || finding.module === 'Source Map'), false);
    assert.equal(result.findings.some(finding => finding.title.includes('newsletter_subscribers') && finding.severity === 'ELEVEE'), true);
    assert.equal(result.score, 92);
    assert.equal(result.coverage.status, 'partial');
    assert.deepEqual(result.coverage.limitations, ['supabase_schema_inventory_unavailable']);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('runScan marks scores unreliable after network budget exhaustion', async () => {
  const server = http.createServer((request, response) => {
    response.statusCode = request.url === '/' ? 200 : 404;
    response.end(request.url === '/' ? 'home' : 'not found');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));

  try {
    const result = await runScan({
      url: `http://127.0.0.1:${server.address().port}`,
      modules: ['files'],
      allowPrivateTargets: true,
      maxNetworkRequests: 1,
    });

    assert.equal(result.metrics.network.budget_exhausted, true);
    assert.equal(result.coverage.status, 'partial');
    assert.deepEqual(result.coverage.limitations, ['network_budget_exhausted']);
    assert.equal(result.score_reliable, false);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('runScan rejects promptly after caller cancellation', async () => {
  const server = http.createServer((request, response) => {
    setTimeout(() => response.end('late'), 300);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const controller = new AbortController();

  try {
    const started = Date.now();
    const pending = runScan({
      url: `http://127.0.0.1:${server.address().port}`,
      modules: ['files', 'headers'],
      allowPrivateTargets: true,
      signal: controller.signal,
    });
    setTimeout(() => controller.abort(new Error('scan_cancelled')), 20);

    await assert.rejects(pending, /scan_cancelled/);
    assert.ok(Date.now() - started < 250);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
