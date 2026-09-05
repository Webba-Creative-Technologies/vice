import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';
import { runScan } from '../scan.js';

test('stack detection ignores generic analytics words and unused provider references', async () => {
  const server = http.createServer((request, response) => {
    response.setHeader('content-type', 'text/html');
    response.end(`<html><body>
      <h1>A crisp image for each customer segment</h1>
      <p>Documentation about gtag and google-analytics</p>
      <script>const unused = ["https://cdn.segment.com/analytics.js/v1/example/analytics.min.js", "$crisp", "gtag("];</script>
      <!-- <script src="https://client.crisp.chat/l.js"></script> -->
      <script type="application/json">{"sample":"<script src='https://client.crisp.chat/l.js'>"}<\/script>
    </body></html>`);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const result = await runScan({
      url: `http://127.0.0.1:${server.address().port}`,
      modules: ['stack'],
      allowPrivateTargets: true,
      requestTimeoutMs: 1000,
    });
    assert.equal(result.errors.length, 0);
    const detail = result.findings.filter(f => f.module === 'Stack Detection').map(f => f.detail).join('\n');
    assert.doesNotMatch(detail, /Google Analytics|Segment|Crisp/);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});

test('stack evidence identifies a generated cache bundle without URL secrets', async () => {
  const server = http.createServer((request, response) => {
    if (request.url === '/') {
      response.setHeader('content-type', 'text/html');
      response.end('<html><body><script src="/cache/app.a1b2.js?token=fixture-private"></script></body></html>');
    } else if (request.url.startsWith('/cache/app.a1b2.js')) {
      response.setHeader('content-type', 'application/javascript');
      response.end('const unused = "segment crisp gtag";\nwindow.__REACT_DEVTOOLS__ = {};');
    } else {
      response.statusCode = 404;
      response.end('not found');
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const result = await runScan({
      url: `http://127.0.0.1:${server.address().port}`, modules: ['js', 'stack'],
      allowPrivateTargets: true, requestTimeoutMs: 1000,
    });
    assert.equal(result.errors.length, 0);
    const detail = result.findings.filter(f => f.module === 'Stack Detection').map(f => f.detail).join('\n');
    assert.match(detail, /React/);
    assert.match(detail, /cache\/app\.a1b2\.js:2:8/);
    assert.doesNotMatch(detail, /fixture-private|Google Analytics|Segment|Crisp/);
  } finally {
    await new Promise(resolve => server.close(resolve));
  }
});
