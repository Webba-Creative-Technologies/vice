import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';
import { createSurfaceInventory, isGraphqlRead } from '../src/core/surfaces.js';
import { auditInputParameters } from '../src/core/parameter-audit.js';
import { runScan } from '../scan.js';

test('surface inventory confines origins, actions, secrets and budgets', () => {
  const inventory = createSurfaceInventory('https://app.example', { pages: 3 });
  for (const value of ['/logout', '/items?token=private', 'https://foreign.example/', '/search?q=one', '/account', '/extra']) inventory.addPage(value);
  assert.equal(inventory.pages.size, 3);
  assert.equal(inventory.nextPage().url, 'https://app.example/search?q=one');
  inventory.addRequest('/search?q=one');
  inventory.addRequest('/graphql', { method: 'POST', body: '{"query":"mutation { deleteAll }"}' });
  assert.equal(inventory.requests.size, 1);
});

test('read-only GraphQL distinguishes queries, strings, batching and mutations', () => {
  assert.equal(isGraphqlRead('{"query":"query { search(text: \\\"mutation\\\") }"}'), true);
  assert.equal(isGraphqlRead('{"query":"query A { viewer { id } } mutation B { deleteAll }"}'), false);
  assert.equal(isGraphqlRead('{"query":"subscription { events }"}'), false);
  assert.equal(isGraphqlRead('[{"query":"{ __typename }"},{"query":"mutation { deleteAll }"}]'), false);
});

test('parameter audit finds traversal and differential errors without trusting baseline errors', async () => {
  for (const vulnerable of [true, false]) {
    const inventory = createSurfaceInventory('https://app.example');
    for (const path of ['/download?file=report', '/search?term=hello', '/broken?term=hello']) inventory.addRequest(path);
    const findings = [];
    await auditInputParameters({ inventory, baseUrl: 'https://app.example', finding: (...args) => findings.push(args), fetch: async value => {
      const url = new URL(value);
      const body = url.pathname === '/broken' ? 'SQLSTATE[42000]' : vulnerable && url.searchParams.get('file')?.includes('../')
        ? 'root:x:0:0:root:/root:/bin/bash\n' : vulnerable && url.searchParams.get('term')?.includes("'") ? 'SQLSTATE[42000]' : 'ordinary response';
      return new Response(body);
    }});
    assert.equal(findings.length, vulnerable ? 2 : 0);
    assert.equal(findings.some(f => f[3].includes('/broken')), false);
  }
});

test('real crawl reaches nested SPA links and API responses outside api paths', async () => {
  const visited = [];
  const server = http.createServer((req, res) => {
    visited.push(req.url);
    if (req.url === '/records?owner=7') {
      res.setHeader('content-type', 'application/json');
      res.end('{"api_key":"A7b8C9d0E1f2G3h4I5j6"}');
    } else {
      res.setHeader('content-type', 'text/html');
      if (req.url === '/') res.end('<a href="/level-one">Enter</a>');
      else if (req.url === '/level-one') res.end('<a href="/private-area">Continue</a>');
      else if (req.url === '/private-area') res.end('<script>fetch("/records?owner=7")</script>');
      else { res.statusCode = 404; res.end('not found'); }
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const result = await runScan({ url: `http://127.0.0.1:${server.address().port}`, modules: ['api'], allowPrivateTargets: true, requestTimeoutMs: 1000 });
    assert.deepEqual(result.errors, []);
    assert.ok(visited.includes('/private-area'));
    assert.ok(result.findings.some(f => f.module === 'API Audit' && f.severity === 'CRITIQUE'));
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});
