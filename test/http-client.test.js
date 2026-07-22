import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';

import { createHttpClient } from '../src/core/http-client.js';
import { createScopePolicy } from '../src/core/scope.js';

async function withServer(handler, fn) {
  const server = http.createServer(handler);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();

  try {
    return await fn(`http://127.0.0.1:${address.port}`);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
}

test('HTTP client deduplicates identical GET requests', async () => {
  let hits = 0;
  await withServer((request, response) => {
    hits++;
    response.setHeader('content-type', 'application/json');
    response.end('{"ok":true}');
  }, async (url) => {
    const client = createHttpClient();
    assert.equal(await (await client.fetch(url)).text(), '{"ok":true}');
    assert.equal(await (await client.fetch(url)).text(), '{"ok":true}');

    assert.equal(hits, 1);
    assert.equal(client.metrics().cache_hits, 1);
    assert.equal(client.metrics().network_requests, 1);
  });
});

test('HTTP client keeps CORS origins in the cache key', async () => {
  let hits = 0;
  await withServer((request, response) => {
    hits++;
    response.end(request.headers.origin || 'none');
  }, async (url) => {
    const client = createHttpClient();
    await client.fetch(url, { headers: { Origin: 'https://one.example' } });
    await client.fetch(url, { headers: { Origin: 'https://two.example' } });

    assert.equal(hits, 2);
  });
});

test('HTTP client never caches read-only POST requests', async () => {
  let hits = 0;
  await withServer((request, response) => {
    hits++;
    response.end('created');
  }, async (url) => {
    const client = createHttpClient();
    const options = { method: 'POST', body: '{"query":"{ __typename }"}', readOnly: 'graphql-query' };
    await client.fetch(url, options);
    await client.fetch(url, options);

    assert.equal(hits, 2);
    assert.equal(client.metrics().cache_hits, 0);
  });
});

test('HTTP client blocks unmarked mutations before network access', async () => {
  await withServer((request, response) => {
    response.end('unexpected');
  }, async (url) => {
    const client = createHttpClient();
    const response = await client.fetch(url, { method: 'DELETE' });

    assert.equal(response, null);
    assert.equal(client.metrics().network_requests, 0);
    assert.equal(client.metrics().mutations_blocked, 1);
  });
});

test('HTTP client rejects GraphQL mutations marked as read-only', async () => {
  await withServer((request, response) => {
    response.end('unexpected');
  }, async (url) => {
    const client = createHttpClient();
    const response = await client.fetch(url, {
      method: 'POST',
      readOnly: 'graphql-query',
      body: '{"query":"mutation { removeAccount }"}',
    });

    assert.equal(response, null);
    assert.equal(client.metrics().network_requests, 0);
    assert.equal(client.metrics().mutations_blocked, 1);
  });
});

test('HTTP client truncates oversized response bodies', async () => {
  await withServer((request, response) => {
    response.end('x'.repeat(100));
  }, async (url) => {
    const client = createHttpClient({ maxResponseBytes: 16 });
    const response = await client.fetch(url);

    assert.equal((await response.text()).length, 16);
    assert.equal(response.headers.get('x-vice-body-truncated'), 'true');
    assert.equal(client.metrics().truncated_responses, 1);
  });
});

test('HTTP client returns null after timeout', async () => {
  await withServer((request, response) => {
    setTimeout(() => response.end('late'), 50);
  }, async (url) => {
    const client = createHttpClient({ timeoutMs: 10 });

    assert.equal(await client.fetch(url), null);
    assert.equal(client.metrics().failed_requests, 1);
  });
});

test('HTTP client follows same-scope redirects manually', async () => {
  let hits = 0;
  await withServer((request, response) => {
    hits++;
    if (request.url === '/start') {
      response.writeHead(302, { location: '/finish' });
      response.end();
      return;
    }
    response.end('finished');
  }, async (url) => {
    const scope = createScopePolicy(url, { allowPrivateTargets: true });
    const client = createHttpClient({ scope });
    const response = await client.fetch(`${url}/start`);

    assert.equal(await response.text(), 'finished');
    assert.equal(hits, 2);
    assert.equal(client.metrics().redirects_followed, 1);
  });
});

test('HTTP client permits bounded AI probe posts', async () => {
  let body = '';
  await withServer((request, response) => {
    request.setEncoding('utf8');
    request.on('data', (chunk) => { body += chunk; });
    request.on('end', () => response.end('{"answer":"READY"}'));
  }, async (url) => {
    const client = createHttpClient();
    const response = await client.fetch(url, {
      method: 'POST',
      probe: 'ai-rag',
      body: '{"message":"READY"}',
    });

    assert.equal(await response.text(), '{"answer":"READY"}');
    assert.equal(body, '{"message":"READY"}');
    assert.equal(client.metrics().mutations_blocked, 0);
  });
});

test('HTTP client rejects oversized AI probe posts', async () => {
  await withServer((request, response) => response.end('unexpected'), async (url) => {
    const client = createHttpClient();
    const response = await client.fetch(url, {
      method: 'POST',
      probe: 'ai-rag',
      body: 'x'.repeat(64 * 1024 + 1),
    });

    assert.equal(response, null);
    assert.equal(client.metrics().network_requests, 0);
    assert.equal(client.metrics().mutations_blocked, 1);
  });
});

test('HTTP client rejects redirect destinations outside scope', async () => {
  let hits = 0;
  await withServer((request, response) => {
    hits++;
    response.writeHead(302, { location: `http://localhost:${serverPort(request)}/private` });
    response.end();
  }, async (url) => {
    const scope = createScopePolicy(url, { allowPrivateTargets: true });
    const client = createHttpClient({ scope });

    assert.equal(await client.fetch(url), null);
    assert.equal(hits, 1);
    assert.equal(client.metrics().blocked_requests, 1);
  });
});

test('HTTP client strips credentials across allowed origins', async () => {
  let receivedAuthorization = null;
  let receivedApiKey = null;
  await withServer((request, response) => {
    receivedAuthorization = request.headers.authorization || null;
    receivedApiKey = request.headers.apikey || null;
    response.end('done');
  }, async (destination) => {
    await withServer((request, response) => {
      response.writeHead(302, { location: destination });
      response.end();
    }, async (source) => {
      const ports = [new URL(source).port, new URL(destination).port];
      const scope = createScopePolicy(source, { allowPrivateTargets: true, allowedPorts: ports });
      const client = createHttpClient({ scope });
      const response = await client.fetch(source, { headers: { Authorization: 'Bearer private-token', apikey: 'private-key' } });

      assert.equal(await response.text(), 'done');
      assert.equal(receivedAuthorization, null);
      assert.equal(receivedApiKey, null);
    });
  });
});

test('HTTP client propagates an external abort signal', async () => {
  await withServer((request, response) => {
    setTimeout(() => response.end('late'), 100);
  }, async (url) => {
    const controller = new AbortController();
    const client = createHttpClient({ timeoutMs: 1000, signal: controller.signal });
    const pending = client.fetch(url);
    controller.abort(new Error('scan_cancelled'));

    assert.equal(await pending, null);
    assert.equal(client.metrics().aborted_requests, 1);
  });
});

test('HTTP client stops after the global request budget', async () => {
  await withServer((request, response) => response.end('ok'), async (url) => {
    const client = createHttpClient({ maxNetworkRequests: 1 });

    assert.ok(await client.fetch(`${url}/first`));
    assert.equal(await client.fetch(`${url}/second`), null);
    assert.equal(client.metrics().network_requests, 1);
    assert.equal(client.metrics().budget_exhausted, true);
  });
});

test('HTTP client caps aggregate response bytes', async () => {
  await withServer((request, response) => response.end('x'.repeat(20)), async (url) => {
    const client = createHttpClient({ maxResponseBytes: 20, maxTotalResponseBytes: 25 });
    const first = await client.fetch(`${url}/first`);
    const second = await client.fetch(`${url}/second`);

    assert.equal((await first.text()).length, 20);
    assert.equal((await second.text()).length, 5);
    assert.equal(client.metrics().bytes_received, 25);
    assert.equal(client.metrics().budget_exhausted, true);
  });
});

function serverPort(request) {
  return request.headers.host.split(':').pop();
}
