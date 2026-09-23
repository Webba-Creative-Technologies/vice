import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';
import { auditReflectedXss } from '../src/core/parameter-audit.js';
import { createSurfaceInventory } from '../src/core/surfaces.js';
import { runScan } from '../scan.js';

test('XSS audit continues after inert reflection and ignores unrelated dialogs', async () => {
  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://localhost');
    res.setHeader('content-type', 'text/html');
    const value = url.searchParams.get('q') || '';
    if (url.pathname === '/unsafe') res.end(`<html><body>${value}</body></html>`);
    else res.end(`<html><body><script>alert('unrelated')</script><textarea>${value.replaceAll('<', '&lt;')}</textarea></body></html>`);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const { default: puppeteer } = await import('puppeteer');
  const browser = await puppeteer.launch({ headless: true, args: process.env.VICE_DISABLE_CHROMIUM_SANDBOX === '1' ? ['--no-sandbox'] : [] });
  try {
    const origin = `http://127.0.0.1:${server.address().port}`;
    const inventory = createSurfaceInventory(origin);
    inventory.addRequest('/safe?q=hello');
    inventory.addRequest('/unsafe?q=hello');
    const findings = [];
    await auditReflectedXss({ inventory, baseUrl: origin, fetch, page: await browser.newPage(), finding: (...args) => findings.push(args) });
    assert.equal(findings.length, 1);
    assert.match(findings[0][3], /\/unsafe/);
  } finally { await browser.close(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});

test('login audit observes JavaScript POST instead of trusting the default form method', async () => {
  const submissions = [];
  const server = http.createServer((req, res) => {
    if (req.url === '/session' && req.method === 'POST') {
      let body = '';
      req.on('data', chunk => { body += chunk; });
      req.on('end', () => { submissions.push(body); res.statusCode = 401; res.end('invalid synthetic credentials'); });
      return;
    }
    res.setHeader('content-type', 'text/html');
    res.end(`<form id="login"><input type="email" name="email"><input type="password" name="password"><button>Login</button></form>
      <script>document.forms[0].onsubmit = event => { event.preventDefault(); fetch('/session', {method:'POST',body:new URLSearchParams(new FormData(event.target))}); };</script>`);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const result = await runScan({ url: `http://127.0.0.1:${server.address().port}/`, modules: ['login'], allowPrivateTargets: true, requestTimeoutMs: 1000 });
    assert.deepEqual(result.errors, []);
    assert.equal(submissions.length, 3);
    assert.match(submissions[0], /audit.invalid/);
    assert.equal(result.findings.some(f => /password in the URL/.test(f.title)), false);
    assert.equal(result.metrics.checks.login.fail, 1, 'HTTP is independently detected even though the method is POST');
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});

test('attack audit does not treat a baseline file example or a non-redirect Location as exploitation', async () => {
  const server = http.createServer((req, res) => {
    res.setHeader('content-type', 'text/html');
    res.setHeader('location', 'https://vice-redirect-probe.invalid/');
    res.end('<html><body><pre>root:x:0:0:root:/root:/bin/bash\n</pre></body></html>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const result = await runScan({ url: `http://127.0.0.1:${server.address().port}`, modules: ['attacks'], allowPrivateTargets: true, requestTimeoutMs: 1000 });
    assert.deepEqual(result.errors, []);
    assert.equal(result.findings.some(f => ['Path Traversal', 'Open Redirect'].includes(f.module) && f.severity !== 'INFO'), false);
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});

test('XSS observes delayed DOM execution while the escaped variant remains safe', async () => {
  const server = http.createServer((req, res) => {
    res.setHeader('content-type', 'text/html');
    const property = req.url.startsWith('/unsafe') ? 'innerHTML' : 'textContent';
    res.end(`<main id="preview"></main><script>setTimeout(()=>{document.getElementById('preview').${property}=new URLSearchParams(location.search).get('label')||''},700)</script>`);
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const { default: puppeteer } = await import('puppeteer');
  const browser = await puppeteer.launch({ headless: true, args: process.env.VICE_DISABLE_CHROMIUM_SANDBOX === '1' ? ['--no-sandbox'] : [] });
  try {
    const origin = `http://127.0.0.1:${server.address().port}`;
    const inventory = createSurfaceInventory(origin);
    inventory.addRequest('/safe?label=welcome');
    inventory.addRequest('/unsafe?label=welcome');
    const findings = [];
    await auditReflectedXss({ inventory, baseUrl: origin, fetch, page: await browser.newPage(), finding: (...args) => findings.push(args) });
    assert.equal(findings.length, 1);
    assert.match(findings[0][3], /\/unsafe/);
  } finally { await browser.close(); server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});

test('login discovery never submits a registration form found on the starting page', async () => {
  let submissions = 0;
  const server = http.createServer((req, res) => {
    if (req.method === 'POST') submissions++;
    res.setHeader('content-type', 'text/html');
    res.end('<form method="post"><input type="email" name="email"><input type="password" name="password" autocomplete="new-password"><button>Create account</button></form>');
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  try {
    const result = await runScan({ url: `http://127.0.0.1:${server.address().port}`, modules: ['login'], allowPrivateTargets: true });
    assert.equal(submissions, 0);
    assert.equal(result.metrics.checks.login.unknown, 1);
    assert.equal(result.findings.some(f => f.rule_id === 'vice/login/injection-session'), false);
  } finally { server.closeAllConnections(); await new Promise(resolve => server.close(resolve)); }
});
