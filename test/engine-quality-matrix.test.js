import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';
import { runScan, calculateScanScore } from '../scan.js';
import { createLoginProbe, permitsLoginRequest } from '../src/core/login-audit.js';
import { inspectPublicObject } from '../src/core/storage-audit.js';
import { auditObjectAuthorization } from '../src/core/authorization-audit.js';
import { createSurfaceInventory } from '../src/core/surfaces.js';

test('impact ceilings distinguish confirmed compromise, exposure and hardening', () => {
  const confirmed = severity => [{ severity, confidence: 'high', classification: 'confirmed', rule_id: 'fixture/proof' }];
  assert.equal(calculateScanScore(confirmed('CRITIQUE')).score, 39);
  assert.equal(calculateScanScore(confirmed('ELEVEE')).score, 69);
  assert.equal(calculateScanScore(confirmed('INFO')).score, 100);
  assert.equal(calculateScanScore([], { coverageStatus: 'partial' }).score, 89);
  const duplicate = [...confirmed('MOYENNE'), ...confirmed('MOYENNE')].map(f => ({ ...f, cause_key: 'one-defect' }));
  assert.equal(calculateScanScore(duplicate).score, 97);
});

test('login policy permits only bounded synthetic submissions on the primary origin', () => {
  const probe = createLoginProbe('https://app.example');
  const body = new URLSearchParams({ email: probe.email, password: probe.password }).toString();
  assert.equal(permitsLoginRequest(probe, new URL('https://foreign.example/login'), 'POST', body), false);
  assert.equal(permitsLoginRequest(probe, new URL('https://app.example/login'), 'POST', 'email=real&password=real'), false);
  for (let i = 0; i < 3; i++) assert.equal(permitsLoginRequest(probe, new URL('https://app.example/login'), 'POST', body), true);
  assert.equal(permitsLoginRequest(probe, new URL('https://app.example/login'), 'POST', body), false);
});

test('storage needs sensitive contents, not a sensitive filename', async () => {
  assert.equal(await inspectPublicObject(new Response('Sample invoice template', { headers: { 'content-type': 'text/plain' } })), null);
  const exposure = await inspectPublicObject(new Response('{"api_key":"A7b8C9d0E1f2G3h4I5j6"}', { headers: { 'content-type': 'application/json' } }));
  assert.equal(exposure.severity, 'CRITIQUE');
});

test('authorization comparison separates exposed and protected owner-associated objects', async () => {
  const inventory = createSurfaceInventory('https://app.example');
  inventory.addRequest('/documents/7', { contentType: 'application/json' });
  for (const exposed of [true, false]) {
    const findings = [];
    await auditObjectAuthorization({ inventory, baseUrl: 'https://app.example', profiles: [
      { userId: 'a', headers: { authorization: 'Bearer a' } }, { userId: 'b', headers: { authorization: 'Bearer b' } },
    ], fetch: async (_url, options) => new Response(exposed || options.headers.authorization === 'Bearer a'
      ? '{"id":7,"owner_id":"a","email":"fixture@example.test"}' : '{}', { status: !exposed && options.headers.authorization.endsWith('b') ? 403 : 200 }),
    finding: (...args) => findings.push(args) });
    assert.equal(findings.length, exposed ? 1 : 0);
  }
});

test('Supabase publishable audit reaches table reads without a fake bearer token', async () => {
  const calls = [];
  const server = http.createServer((req, res) => {
    calls.push({ url: req.url, authorization: req.headers.authorization });
    res.setHeader('content-type', 'application/json');
    if (req.url === '/rest/v1/') res.end('{"paths":{"/credentials":{}}}');
    else if (req.url.startsWith('/rest/v1/credentials?')) res.end('[{"api_key":"A7b8C9d0E1f2G3h4I5j6"}]');
    else res.end('{}');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const url = `http://127.0.0.1:${server.address().port}`;
    const result = await runScan({ url, supabaseUrl: url, supabaseKey: 'sb_publishable_A7b8C9d0E1f2G3h4I5j6', modules: ['supabase'], allowPrivateTargets: true });
    assert.ok(calls.some(call => call.url.startsWith('/rest/v1/credentials?')));
    assert.ok(calls.every(call => !call.authorization));
    assert.ok(result.findings.some(f => f.severity === 'CRITIQUE'));
    assert.equal(result.score, 39);
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});
