import http from 'node:http';
import { performance } from 'node:perf_hooks';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { writeFile } from 'node:fs/promises';

const [baselinePath, candidatePath, outputPath, repetitions = '3', selection = 'all'] = process.argv.slice(2);
if (!outputPath) throw new Error('Usage: node benchmark/improvements.mjs baseline/scan.js candidate/scan.js output.json [repetitions] [case]');
const engines = { baseline: await import(pathToFileURL(resolve(baselinePath))), candidate: await import(pathToFileURL(resolve(candidatePath))) };
const cases = [
  { id: 'application-vulnerable', family: 'application', vulnerable: true, modules: ['api', 'attacks'], expected: ['api-credentials', 'sql', 'traversal', 'redirect', 'xss'] },
  { id: 'application-fixed', family: 'application', vulnerable: false, modules: ['api', 'attacks'], expected: [] },
  { id: 'direct-vulnerable', family: 'direct', vulnerable: true, modules: ['files', 'api'], expected: ['env', 'api-credentials'] },
  { id: 'direct-fixed', family: 'direct', vulnerable: false, modules: ['files', 'api'], expected: [] },
  { id: 'supabase-vulnerable', family: 'supabase', vulnerable: true, modules: ['supabase'], expected: ['supabase'] },
  { id: 'supabase-fixed', family: 'supabase', vulnerable: false, modules: ['supabase'], expected: [] },
  { id: 'login-vulnerable', family: 'login', vulnerable: true, modules: ['login'], expected: ['login-injection'] },
  { id: 'login-fixed', family: 'login', vulnerable: false, modules: ['login'], expected: [] },
  { id: 'graphql-vulnerable', family: 'graphql', vulnerable: true, modules: ['api'], expected: ['graphql-credentials'] },
  { id: 'graphql-fixed', family: 'graphql', vulnerable: false, modules: ['api'], expected: [] },
  { id: 'browser-false-signals', family: 'false-signals', vulnerable: false, modules: ['attacks'], expected: [] },
  { id: 'delayed-dom-vulnerable', family: 'delayed-dom', vulnerable: true, modules: ['attacks'], expected: ['xss'] },
  { id: 'delayed-dom-fixed', family: 'delayed-dom', vulnerable: false, modules: ['attacks'], expected: [] },
];
const credential = 'A7b8C9d0E1f2G3h4I5j6';
const passwd = 'root:x:0:0:root:/root:/bin/bash\n';
const escapeHtml = value => String(value).replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;').replaceAll('"', '&quot;');

function detector(finding) {
  if (finding.severity === 'INFO' || finding.confidence === 'low') return null;
  const text = `${finding.title} ${finding.detail}`;
  if (finding.module === 'XSS') return 'xss';
  if (finding.module === 'Path Traversal') return 'traversal';
  if (finding.module === 'Open Redirect') return 'redirect';
  if (finding.module === 'API Audit' && /boolean|database error|SQL injection/i.test(text)) return 'sql';
  if (finding.module === 'API Audit' && /credential/i.test(text)) return 'api-credentials';
  if (finding.module === 'GraphQL' && /sensitive fields anonymously/.test(text)) return 'graphql-credentials';
  if (finding.module === 'Login Audit' && /injection probe returned session/.test(text)) return 'login-injection';
  if (/supabase/i.test(finding.module) && /credential/i.test(text)) return 'supabase';
  if (finding.module === 'Exposed Files' && /\.env/.test(text)) return 'env';
  return null;
}

async function scan(engine, scenario) {
  const requests = [];
  let database;
  if (scenario.family === 'application') {
    const { DatabaseSync } = await import('node:sqlite');
    database = new DatabaseSync(':memory:');
    database.exec("CREATE TABLE records(id INTEGER, title TEXT); INSERT INTO records VALUES(7, 'Public item')");
  }
  const server = http.createServer((request, response) => {
    const url = new URL(request.url, 'http://localhost');
    requests.push({ method: request.method, path: url.pathname });
    response.setHeader('x-content-type-options', 'nosniff');
    response.setHeader('x-frame-options', 'DENY');
    const html = body => { response.setHeader('content-type', 'text/html'); response.end(`<html><body>${body}</body></html>`); };
    const json = (body, status = 200) => { response.statusCode = status; response.setHeader('content-type', 'application/json'); response.end(JSON.stringify(body)); };
    const missing = () => { response.statusCode = 404; response.end('fixture route not found'); };
    if (scenario.family === 'supabase') {
      if (request.headers.authorization) return json({ error: 'publishable keys are not JWTs' }, 401);
      if (url.pathname === '/rest/v1/') return json({ paths: { '/credentials': {} } });
      if (url.pathname === '/rest/v1/credentials') return json(scenario.vulnerable ? [{ api_key: credential }] : [], scenario.vulnerable ? 200 : 403);
      return missing();
    }
    if (scenario.family === 'login') {
      if (url.pathname === '/session' && request.method === 'POST') {
        let body = '';
        request.on('data', chunk => { body += chunk; });
        request.on('end', () => {
          const email = new URLSearchParams(body).get('email');
          return scenario.vulnerable && email?.includes("' OR")
            ? json({ user: { id: 'fixture-user' }, access_token: `fixture-session-${credential}` })
            : json({ error: 'Invalid credentials' }, 401);
        });
        return;
      }
      if (url.pathname === '/') return html('<form><input type="email" name="email"><input type="password" name="password"><button>Login</button></form><script>document.forms[0].onsubmit=e=>{e.preventDefault();fetch("/session",{method:"POST",body:new URLSearchParams(new FormData(e.target))})}</script>');
      return missing();
    }
    if (scenario.family === 'graphql') {
      if (url.pathname === '/') return html('<script>fetch("/transport",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({query:"{ viewer { api_key } }"})})</script>');
      if (url.pathname === '/transport' && request.method === 'POST') return json(scenario.vulnerable ? { data: { viewer: { api_key: credential } } } : { errors: [{ message: 'Unauthenticated' }] });
      return missing();
    }
    if (scenario.family === 'direct') {
      if (url.pathname === '/') return html('<h1>Direct API fixture</h1>');
      if (url.pathname === '/.env' && scenario.vulnerable) { response.setHeader('content-type', 'text/plain'); return response.end(`DATABASE_URL=postgresql://fixture:${credential}@localhost/app\n`); }
      if (url.pathname === '/api/users') return json(scenario.vulnerable ? [{ api_key: credential }] : [], scenario.vulnerable ? 200 : 403);
      return missing();
    }
    if (scenario.family === 'false-signals') {
      const destination = [...url.searchParams.values()].find(value => /^https?:/.test(value));
      if (destination) response.setHeader('location', destination);
      return html(`<pre>${passwd}</pre>${url.searchParams.has('q') ? '<script>alert("unrelated-notice")</script>' : ''}`);
    }
    if (url.pathname === '/') return html(`<!--${url.searchParams.get('q') || ''}--><a href="/workspace">Workspace</a>`);
    if (url.pathname === '/workspace') return html('<a href="/workspace/tools">Tools</a>');
    if (url.pathname === '/workspace/tools') {
      if (scenario.family === 'delayed-dom') return html('<a href="/preview?label=welcome">Preview</a>');
      return html('<a href="/preview?label=welcome">Preview</a><a href="/download?file=report.txt">Download</a><a href="/continue?next=/workspace">Continue</a><script>fetch("/records?item_id=7");fetch("/directory");</script>');
    }
    if (url.pathname === '/preview') {
      if (scenario.family === 'delayed-dom') return html(`<main id="preview"></main><script>setTimeout(()=>{document.getElementById('preview').${scenario.vulnerable ? 'innerHTML' : 'textContent'}=new URLSearchParams(location.search).get('label')||''},700)</script>`);
      return html(scenario.vulnerable ? url.searchParams.get('label') || '' : escapeHtml(url.searchParams.get('label') || ''));
    }
    if (url.pathname === '/directory') return json(scenario.vulnerable ? [{ api_key: credential }] : [{ product: 'Public catalogue' }]);
    if (url.pathname === '/records') {
      const id = url.searchParams.get('item_id');
      if (!scenario.vulnerable && !/^\d+$/.test(id || '')) return json({ error: 'Invalid identifier' }, 400);
      try {
        return json(scenario.vulnerable
          ? database.prepare(`SELECT id, title FROM records WHERE id = ${id}`).all()
          : database.prepare('SELECT id, title FROM records WHERE id = ?').all(Number(id)));
      } catch (error) { response.statusCode = 500; return response.end(`SQLSTATE[42000]: ${error.message}`); }
    }
    if (url.pathname === '/download') {
      response.setHeader('content-type', 'text/plain');
      return response.end(scenario.vulnerable && url.searchParams.get('file')?.includes('../') ? passwd : 'Public report');
    }
    if (url.pathname === '/continue') {
      const next = url.searchParams.get('next');
      if (scenario.vulnerable && /^https?:/.test(next || '')) { response.statusCode = 302; response.setHeader('location', next); return response.end(); }
      return html('Continue within the application');
    }
    missing();
  });
  await new Promise(resolveListen => server.listen(0, '127.0.0.1', resolveListen));
  const url = `http://127.0.0.1:${server.address().port}`;
  const started = performance.now();
  try {
    const result = await engine.runScan({ url, modules: scenario.modules, allowPrivateTargets: true, requestTimeoutMs: 1500,
      ...(scenario.family === 'supabase' ? { supabaseUrl: url, supabaseKey: `sb_publishable_${credential}` } : {}),
    });
    const detected = [...new Set(result.findings.map(detector).filter(Boolean))];
    return { duration_ms: Math.round(performance.now() - started), score: result.score, coverage: result.coverage.status,
      detected, missed: scenario.expected.filter(item => !detected.includes(item)), false_positives: detected.filter(item => !scenario.expected.includes(item)),
      requests: requests.length, network: result.metrics.network, errors: result.errors,
      findings: result.findings.map(({ module, title, severity, classification, rule_id }) => ({ module, title, severity, classification, rule_id })),
    };
  } finally { server.closeAllConnections(); await new Promise(resolveClose => server.close(resolveClose)); database?.close(); }
}

const output = { schema: 1, node: process.version, started_at: new Date().toISOString(), baseline: resolve(baselinePath), candidate: resolve(candidatePath), repetitions: Number(repetitions), cases: [] };
for (let repetition = 0; repetition < Number(repetitions); repetition++) {
  for (const scenario of cases.filter(item => selection === 'all' || selection.split(',').includes(item.id))) {
    const pair = { id: scenario.id, expected: scenario.expected, repetition: repetition + 1 };
    for (const label of repetition % 2 ? ['candidate', 'baseline'] : ['baseline', 'candidate']) {
      pair[label] = await scan(engines[label], scenario);
      console.log(JSON.stringify({ case: scenario.id, repetition: repetition + 1, engine: label, duration_ms: pair[label].duration_ms, detected: pair[label].detected, missed: pair[label].missed, false_positives: pair[label].false_positives, errors: pair[label].errors.length }));
    }
    output.cases.push(pair);
    await writeFile(outputPath, JSON.stringify(output, null, 2));
  }
}
