import assert from 'node:assert/strict';
import test from 'node:test';

import { authorizedDiscoveryRoot, createScopePolicy, isBlockedIp } from '../src/core/scope.js';

const publicResolver = async () => [{ address: '93.184.216.34', family: 4 }];

test('scope allows the verified host and its children only', async () => {
  const scope = createScopePolicy('https://app.example.com', { resolver: publicResolver });

  await assert.doesNotReject(scope.assertUrl('https://app.example.com/api'));
  await assert.doesNotReject(scope.assertUrl('wss://events.app.example.com/ws'));
  await assert.rejects(scope.assertUrl('https://api.example.com'), { code: 'blocked_host' });
  await assert.rejects(scope.assertUrl('https://example.net'), { code: 'blocked_host' });
});

test('private public-suffix tenants never authorize sibling tenants', () => {
  assert.equal(authorizedDiscoveryRoot('alice.github.io'), 'alice.github.io');
  assert.equal(authorizedDiscoveryRoot('example.co.uk'), 'example.co.uk');
  assert.equal(authorizedDiscoveryRoot('app.example.co.uk'), 'app.example.co.uk');
});

test('scope permits only explicit secondary and trusted hosts', async () => {
  const scope = createScopePolicy('https://example.com', {
    resolver: publicResolver,
    allowedHosts: ['project.supabase.co'],
    trustedHosts: ['crt.sh'],
  });

  await assert.doesNotReject(scope.assertUrl('https://project.supabase.co/rest/v1/'));
  assert.equal((await scope.assertUrl('https://crt.sh/')).trusted, true);
  await assert.rejects(scope.assertUrl('https://other.supabase.co'), { code: 'blocked_host' });
});

test('scope blocks credentials, ports, private addresses, and rebinding', async () => {
  let call = 0;
  const scope = createScopePolicy('https://example.com', {
    resolver: async () => [{ address: call++ === 0 ? '93.184.216.34' : '93.184.216.35', family: 4 }],
  });

  await scope.assertUrl('https://example.com/first');
  await assert.rejects(scope.assertUrl('https://example.com/second'), { code: 'dns_rebinding_detected' });
  await assert.rejects(scope.assertUrl('https://user:pass@example.com'), { code: 'blocked_url_credentials' });
  await assert.rejects(scope.assertUrl('https://example.com:8443'), { code: 'blocked_port' });

  const privateScope = createScopePolicy('https://internal.example', {
    resolver: async () => [{ address: '169.254.169.254', family: 4 }],
  });
  await assert.rejects(privateScope.assertUrl('https://internal.example'), { code: 'blocked_private_target' });
});

test('IP classifier covers IPv4, IPv6, mapped, and transition ranges', () => {
  for (const address of ['127.0.0.1', '10.0.0.1', '100.64.0.1', '169.254.169.254', '::1', 'fd00::1', 'fe80::1', '::ffff:127.0.0.1', '2002:7f00:0001::']) {
    assert.equal(isBlockedIp(address), true, address);
  }
  assert.equal(isBlockedIp('93.184.216.34'), false);
  assert.equal(isBlockedIp('2606:2800:220:1:248:1893:25c8:1946'), false);
});

test('private targets require an explicit local-test override', async () => {
  const blocked = createScopePolicy('http://127.0.0.1');
  const allowed = createScopePolicy('http://127.0.0.1', { allowPrivateTargets: true });

  await assert.rejects(blocked.assertUrl('http://127.0.0.1'), { code: 'blocked_private_target' });
  await assert.doesNotReject(allowed.assertUrl('http://127.0.0.1'));
});

test('raw socket addresses must match a pinned target address and port', async () => {
  const scope = createScopePolicy('https://example.com', {
    resolver: publicResolver,
    allowedPorts: ['22', '443'],
  });
  await scope.assertUrl('https://example.com');

  assert.equal(scope.assertAddress('93.184.216.34', 22), '93.184.216.34');
  assert.throws(() => scope.assertAddress('93.184.216.35', 22), { code: 'blocked_address' });
  assert.throws(() => scope.assertAddress('93.184.216.34', 5432), { code: 'blocked_port' });
});

test('scope enforces global DNS and answer budgets', async () => {
  const dnsBudget = createScopePolicy('https://example.com', {
    resolver: publicResolver,
    allowedHosts: ['api.example.net'],
    maxDnsResolutions: 1,
  });
  await dnsBudget.assertUrl('https://example.com');
  await assert.rejects(dnsBudget.assertUrl('https://api.example.net'), { code: 'dns_budget_exhausted' });
  assert.equal(dnsBudget.metrics().budget_exhausted, true);

  const answerBudget = createScopePolicy('https://example.com', {
    resolver: async () => Array.from({ length: 3 }, (_, index) => ({ address: `93.184.216.${index + 1}`, family: 4 })),
    maxDnsAnswers: 2,
  });
  await assert.rejects(answerBudget.assertUrl('https://example.com'), { code: 'dns_answer_too_large' });
});

test('observed public service hosts are authorized without user interaction', async () => {
  const scope = createScopePolicy('https://example.com', { resolver: publicResolver });

  await assert.rejects(scope.assertUrl('https://api.service.test/v1'), { code: 'blocked_host' });
  await assert.doesNotReject(scope.authorizeDiscoveredUrl('https://api.service.test/v1'));
  await assert.doesNotReject(scope.assertUrl('https://api.service.test/v2'));
  assert.equal(scope.metrics().discovered_hosts, 1);
});

test('automatic discovery still rejects private secondary services', async () => {
  const scope = createScopePolicy('https://example.com', {
    resolver: async hostname => [{ address: hostname === 'example.com' ? '93.184.216.34' : '10.0.0.5', family: 4 }],
  });
  await scope.assertUrl('https://example.com');

  await assert.rejects(scope.authorizeDiscoveredUrl('https://internal.service.test'), { code: 'blocked_private_target' });
  assert.equal(scope.isHostAllowed('internal.service.test'), false);
});
