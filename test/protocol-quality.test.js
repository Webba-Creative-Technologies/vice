import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import test from 'node:test';
import { lookupDmarc } from '../src/core/dns-policy.js';
import { probeTls } from '../src/core/tls-probes.js';
import { subscriptionFrame } from '../src/core/websocket-discovery.js';
import { publicClientSources } from '../src/core/audit-checks.js';
import { secretFindingPolicy } from '../src/core/detectors/bundle-secrets.js';
import { metaCsp, hasFrameRestriction } from '../src/core/detectors/policies.js';
import { auditObservedQueries } from '../src/core/observed-api.js';
import { createSurfaceInventory } from '../src/core/surfaces.js';

test('DMARC inherits the subdomain policy without converting resolver failure into absence', async () => {
  const result = await lookupDmarc('app.example.com', async name => {
    if (name === '_dmarc.app.example.com') throw Object.assign(new Error(), { code: 'ENODATA' });
    return [['v=DMARC1; p=reject; sp=none']];
  });
  assert.equal(result.effective, 'none');
  assert.equal(result.owner, 'example.com');
  await assert.rejects(lookupDmarc('example.com', async () => { throw Object.assign(new Error('timeout'), { code: 'ETIMEOUT' }); }), /timeout/);
  assert.equal((await lookupDmarc('example.com', async () => [['v=DMARC1; p=reject; p=none']])).effective, null);
});

test('TLS distinguishes accepted, explicitly rejected and untestable protocols', async () => {
  for (const [message, expected] of [[null, 'accepted'], ['alert protocol version', 'rejected'], ['no ciphers available', 'unknown'], ['ECONNRESET', 'unknown']]) {
    let destroyed = false;
    const result = await probeTls({}, (_options, accepted) => {
      const socket = Object.assign(new EventEmitter(), { destroy() { destroyed = true; }, getProtocol: () => 'TLSv1', getCipher: () => ({ name: 'fixture' }) });
      queueMicrotask(() => message ? socket.emit('error', new Error(message)) : accepted());
      return socket;
    });
    assert.equal(result.state, expected);
    assert.equal(destroyed, true);
  }
});

test('realtime replay strips credentials and rejects arbitrary messages', () => {
  const frame = subscriptionFrame(JSON.stringify({ event: 'phx_join', topic: 'realtime:records', payload: { access_token: 'private', config: { postgres_changes: [{ table: 'records', filter: 'user_id=eq.private' }] } } }));
  assert.equal(frame.includes('private'), false);
  assert.match(frame, /records/);
  assert.equal(subscriptionFrame('{"event":"delete","payload":{"all":true}}'), null);
  assert.equal(subscriptionFrame('{"type":"subscribe","payload":{"query":"mutation { deleteAll }"}}'), null);
});

test('session-only sources are excluded from public secret evidence', async () => {
  const context = { authContext: {}, stackSources: [
    { content: 'private-session', kind: 'Browser storage', url: 'https://app.example' },
    { content: 'private-html', kind: 'Rendered HTML', url: 'https://app.example' },
    { content: 'public-script', kind: 'External JS', url: 'https://app.example/app.js' },
  ] };
  const result = await publicClientSources(['private-session', 'private-html', 'public-script'], context,
    async url => new Response(url.endsWith('.js') ? 'public-script' : 'public-html'));
  assert.deepEqual(result, ['public-html', 'public-script']);
  assert.equal(secretFindingPolicy('Supabase Publishable Key').severity, 'INFO');
  assert.equal(secretFindingPolicy('Supabase Secret Key').severity, 'CRITIQUE');
  assert.equal(secretFindingPolicy('Discord Webhook').severity, 'ELEVEE');
});

test('frame and meta policies follow effective directives', () => {
  assert.equal(metaCsp('<meta content="script-src \'self\'" http-equiv="Content-Security-Policy">'), "script-src 'self'");
  assert.equal(hasFrameRestriction('ALLOW-FROM https://example.com', ''), false);
  assert.equal(hasFrameRestriction('DENY', 'frame-ancestors *'), false);
  assert.equal(hasFrameRestriction('', "frame-ancestors 'self'"), true);
});

test('anonymous GraphQL replay excludes credential-bearing variables', async () => {
  const inventory = createSurfaceInventory('https://app.example');
  inventory.addRequest('/graphql', { method: 'POST', body: JSON.stringify({ query: 'query($token:String!) { viewer(token:$token) { email } }', variables: { token: 'private-session' } }) });
  inventory.addRequest('/graphql', { method: 'POST', body: JSON.stringify({ query: '{ viewer { email phone } }' }) });
  const calls = [];
  const findings = [];
  await auditObservedQueries(inventory, async (_url, options) => {
    calls.push(options);
    return Response.json({ data: { viewer: { email: 'fixture@example.test', phone: '0123456789' } } });
  }, (...finding) => findings.push(finding));
  assert.equal(calls.length, 1);
  assert.equal(JSON.stringify(calls).includes('private-session'), false);
  assert.equal(findings.length, 1);
});
