import assert from 'node:assert/strict';
import test from 'node:test';

import { installScopedRequestInterception } from '../src/core/browser-scope.js';
import { createScopePolicy } from '../src/core/scope.js';

class FakePage {
  async setRequestInterception(value) { this.interception = value; }
  on(event, handler) { if (event === 'request') this.requestHandler = handler; }
}

function fakeRequest(url, headers = {}, method = 'GET') {
  return {
    continued: null,
    aborted: null,
    url: () => url,
    headers: () => headers,
    method: () => method,
    async continue(overrides = {}) { this.continued = overrides; },
    async abort(reason) { this.aborted = reason; },
  };
}

const resolver = async () => [{ address: '93.184.216.34', family: 4 }];

test('browser scope allows observed public resources without authentication', async () => {
  const page = new FakePage();
  const scope = createScopePolicy('https://example.com', { resolver });
  const metrics = { allowed: 0, blocked: 0, auth_injected: 0, mutations_blocked: 0 };
  await installScopedRequestInterception(page, { scope, metrics });

  const request = fakeRequest('https://tracker.example.net/script.js');
  await page.requestHandler(request);

  assert.equal(page.interception, true);
  assert.deepEqual(request.continued, { headers: {} });
  assert.equal(request.aborted, null);
  assert.deepEqual(metrics, { allowed: 1, blocked: 0, auth_injected: 0, mutations_blocked: 0 });
});

test('browser scope blocks observed private resources', async () => {
  const page = new FakePage();
  const scope = createScopePolicy('https://example.com', {
    resolver: async hostname => [{ address: hostname === 'example.com' ? '93.184.216.34' : '169.254.169.254', family: 4 }],
  });
  await installScopedRequestInterception(page, { scope });

  const request = fakeRequest('https://metadata.service.test/latest');
  await page.requestHandler(request);

  assert.equal(request.continued, null);
  assert.equal(request.aborted, 'blockedbyclient');
});

test('browser auth headers are injected only on the exact target origin', async () => {
  const page = new FakePage();
  const scope = createScopePolicy('https://example.com', { resolver });
  const metrics = { allowed: 0, blocked: 0, auth_injected: 0, mutations_blocked: 0 };
  await installScopedRequestInterception(page, {
    scope,
    metrics,
    authHeaders: { Authorization: 'Bearer private-token' },
  });

  const target = fakeRequest('https://example.com/private', { accept: '*/*' });
  const child = fakeRequest('https://assets.example.com/app.js', { accept: '*/*' });
  await page.requestHandler(target);
  await page.requestHandler(child);

  assert.equal(target.continued.headers.Authorization, 'Bearer private-token');
  assert.equal('Authorization' in child.continued.headers, false);
  assert.deepEqual(metrics, { allowed: 2, blocked: 0, auth_injected: 1, mutations_blocked: 0 });
});

test('browser scope blocks form mutations before network access', async () => {
  const page = new FakePage();
  const scope = createScopePolicy('https://example.com', { resolver });
  const metrics = { allowed: 0, blocked: 0, auth_injected: 0, mutations_blocked: 0 };
  await installScopedRequestInterception(page, { scope, metrics });

  const request = fakeRequest('https://example.com/account', {}, 'POST');
  await page.requestHandler(request);

  assert.equal(request.continued, null);
  assert.equal(request.aborted, 'blockedbyclient');
  assert.deepEqual(metrics, { allowed: 0, blocked: 1, auth_injected: 0, mutations_blocked: 1 });
});

test('browser scope allows local document protocols without credentials', async () => {
  const page = new FakePage();
  const scope = createScopePolicy('https://example.com', { resolver });
  await installScopedRequestInterception(page, {
    scope,
    authHeaders: { Authorization: 'Bearer private-token' },
  });

  const request = fakeRequest('data:text/plain,fixture');
  await page.requestHandler(request);

  assert.deepEqual(request.continued, {});
  assert.equal(request.aborted, null);
});

test('browser scope aborts requests after scan cancellation', async () => {
  const page = new FakePage();
  const scope = createScopePolicy('https://example.com', { resolver });
  const controller = new AbortController();
  await installScopedRequestInterception(page, { scope, signal: controller.signal });
  controller.abort();

  const request = fakeRequest('https://example.com/slow');
  await page.requestHandler(request);

  assert.equal(request.aborted, 'aborted');
  assert.equal(request.continued, null);
});
