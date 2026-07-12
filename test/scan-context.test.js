import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';

import { runScan } from '../scan.js';
import { createScanContext, getScanContext, withScanContext } from '../src/core/scan-context.js';

async function startFixture(exposesEnvironment) {
  const server = http.createServer((request, response) => {
    setTimeout(() => {
      if (request.url === '/') {
        response.setHeader('content-type', 'text/html');
        response.end('<html><body>fixture</body></html>');
      } else if (exposesEnvironment && request.url === '/.env') {
        response.setHeader('content-type', 'text/plain');
        response.end('DATABASE_URL=postgresql://fixture:fixture@localhost/app\n');
      } else {
        response.statusCode = 404;
        response.end('not found');
      }
    }, 5);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return {
    server,
    url: `http://127.0.0.1:${server.address().port}`,
  };
}

test('scan context stays available across asynchronous work', async () => {
  const context = createScanContext({ authContext: { headers: { authorization: 'one' } } });
  await withScanContext(context, async () => {
    await Promise.resolve();
    assert.equal(getScanContext(), context);
  });
  assert.equal(getScanContext(), null);
});

test('concurrent runScan calls never mix findings', async () => {
  const exposed = await startFixture(true);
  const clean = await startFixture(false);

  try {
    const [exposedResult, cleanResult] = await Promise.all([
      runScan({ url: exposed.url, modules: ['files'], requestTimeoutMs: 1000, allowPrivateTargets: true }),
      runScan({ url: clean.url, modules: ['files'], requestTimeoutMs: 1000, allowPrivateTargets: true }),
    ]);

    assert.ok(exposedResult.findings.some(finding => finding.title.includes('/.env')));
    assert.equal(cleanResult.findings.some(finding => finding.title.includes('/.env')), false);
    assert.equal(exposedResult.coverage.status, 'complete');
    assert.equal(cleanResult.coverage.status, 'complete');
  } finally {
    await Promise.all([
      new Promise(resolve => exposed.server.close(resolve)),
      new Promise(resolve => clean.server.close(resolve)),
    ]);
  }
});
