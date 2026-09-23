import { randomUUID } from 'node:crypto';
import { surfaceUrl } from './surfaces.js';

export function parameterTargets(inventory, baseUrl, limit = 24) {
  const targets = new Map();
  for (const request of inventory?.requests.values() || []) {
    if (request.method !== 'GET') continue;
    const url = surfaceUrl(request.url, baseUrl);
    if (!url) continue;
    for (const name of url.searchParams.keys()) {
      const key = `${url.pathname}:${name}`;
      if (!targets.has(key) && targets.size < limit) targets.set(key, { url: url.href, name });
    }
  }
  for (const page of inventory?.pages.values() || []) {
    if (page.url.includes('#') && targets.size < limit) targets.set(`${page.url}:#`, { url: page.url, name: '#' });
  }
  return [...targets.values()];
}

export async function auditReflectedXss({ inventory, baseUrl, fetch, page, finding, outcome }) {
  const targets = parameterTargets(inventory, baseUrl);
  if (!targets.length) targets.push(...['q', 'search'].map(name => ({ url: baseUrl, name })));
  for (const target of targets.slice(0, 12)) {
    const marker = `vice_${randomUUID().replaceAll('-', '')}`;
    const url = new URL(target.url);
    url.searchParams.set(target.name, marker);
    const response = await fetch(url.href, { cache: 'no-store' });
    if (!response) { outcome?.('unknown'); continue; }
    const html = await response.text();
    if (!/html/i.test(response.headers.get('content-type') || '')) continue;
    const reflected = html.includes(marker);
    const eventPayload = `"><img src="data:image/png,vice" onerror="alert('${marker}')">`;
    const payloads = reflected ? [
      eventPayload,
      `</script><script>alert('${marker}')</script>`,
      `';alert('${marker}');//`,
    ] : [eventPayload];
    let executed = false;
    let loaded = false;
    for (const payload of payloads) {
      let executionObserved;
      const execution = new Promise(resolve => { executionObserved = resolve; });
      let observationTimer;
      const onDialog = async dialog => {
        if (dialog.message() === marker) { executed = true; executionObserved(); }
        await dialog.dismiss().catch(() => {});
      };
      page.on('dialog', onDialog);
      try {
        if (target.name === '#') url.hash = payload;
        else url.searchParams.set(target.name, payload);
        await page.goto(url.href, { waitUntil: 'domcontentloaded', timeout: 6000 });
        loaded = true;
        await Promise.race([execution, new Promise(resolve => { observationTimer = setTimeout(resolve, 1000); })]);
      } catch { outcome?.('unknown'); }
      finally { clearTimeout(observationTimer); page.off('dialog', onDialog); }
      if (executed) break;
    }
    if (executed) finding('ELEVEE', 'XSS', `Script execution through parameter ${target.name}`,
      `Route: ${new URL(target.url).pathname}. A unique audit marker executed in the browser.`,
      'Apply contextual output encoding and remove unsafe DOM sinks.',
      { rule_id: 'vice/xss/execution', classification: 'confirmed', confidence: 'high' });
    outcome?.(executed ? 'fail' : loaded ? 'pass' : 'unknown');
  }
}

const SQL_ERROR = /SQLSTATE\[|syntax error at or near|unterminated quoted string|You have an error in your SQL syntax|sqlite3?\.OperationalError|ORA-\d{5}|System\.Data\.SqlClient/i;
const FILE_CONTENT = /(?:^|\n)root:[^\n]*:0:0:[^\n]*\/(?:bin|sbin)\//;

export async function auditInputParameters({ inventory, baseUrl, fetch, finding, outcome }) {
  for (const target of parameterTargets(inventory, baseUrl, 16)) {
    const url = new URL(target.url);
    const original = url.searchParams.get(target.name);
    const baseline = await fetch(url.href, { cache: 'no-store' });
    if (!baseline || baseline.status >= 400) { outcome?.('unknown'); continue; }
    const body = await baseline.text();
    if (/^(?:file|path|filename|document|download|template)$/i.test(target.name)) {
      url.searchParams.set(target.name, '../../../../etc/passwd');
      const response = await fetch(url.href, { cache: 'no-store' });
      const content = response ? await response.text() : '';
      if (FILE_CONTENT.test(content) && !FILE_CONTENT.test(body)) finding('CRITIQUE', 'Path Traversal', 'System file read through an application parameter',
        `Route: ${url.pathname}, parameter: ${target.name}. A passwd record absent from the normal response was returned.`,
        'Resolve file identifiers through a server-side allowlist.', { rule_id: 'vice/files/path-traversal', classification: 'confirmed', confidence: 'high' });
      outcome?.(response ? FILE_CONTENT.test(content) && !FILE_CONTENT.test(body) ? 'fail' : 'pass' : 'unknown');
      continue;
    }
    if (/redirect|return|next|callback|destination|continue|^url$/i.test(target.name)) {
      const marker = `https://vice-${randomUUID()}.invalid/`;
      url.searchParams.set(target.name, marker);
      const response = await fetch(url.href, { redirect: 'manual', cache: 'no-store' });
      let redirected = false;
      try { redirected = response?.status >= 300 && response.status < 400 && new URL(response.headers.get('location'), url).origin === new URL(marker).origin; } catch {}
      if (redirected) finding('MOYENNE', 'Open Redirect', 'Application redirects to the supplied external origin',
        `Route: ${url.pathname}, parameter: ${target.name}. The external destination was not followed.`,
        'Restrict return destinations to intended origins.', { rule_id: 'vice/redirect/external', classification: 'confirmed', confidence: 'high' });
      outcome?.(response ? redirected ? 'fail' : 'pass' : 'unknown');
      continue;
    }
    if (SQL_ERROR.test(body)) continue;
    let errors = 0;
    let completed = 0;
    for (const suffix of ["'", "\"'"]) {
      url.searchParams.set(target.name, `${original}${suffix}`);
      const response = await fetch(url.href, { cache: 'no-store' });
      if (response) { completed++; if (SQL_ERROR.test(await response.text())) errors++; }
    }
    let booleanInjection = false;
    if (/^\d{1,12}$/.test(original) && /(?:^|_)id$|Id$/.test(target.name)) {
      const replies = [];
      for (const expression of ['1=1', '1=2', '2*3=6', '2*3=7']) {
        url.searchParams.set(target.name, `${original} AND ${expression}`);
        const response = await fetch(url.href, { cache: 'no-store' });
        replies.push(response?.status === baseline.status ? await response.text() : null);
      }
      booleanInjection = replies[0] === body && replies[2] === body && replies[1] !== null
        && replies[1] !== body && replies[1] === replies[3];
    }
    if (booleanInjection) finding('ELEVEE', 'API Audit', 'Boolean expressions alter an identifier query',
      `Route: ${url.pathname}, parameter: ${target.name}. Two true expressions reproduced the baseline; two false expressions produced the same different response.`,
      'Use parameterized statements and strict input types.',
      { rule_id: 'vice/api/boolean-injection', classification: errors === 2 ? 'confirmed' : 'probable', confidence: 'high' });
    else if (errors === 2) finding('MOYENNE', 'API Audit', 'Input causes reproducible database errors',
      `Route: ${url.pathname}, parameter: ${target.name}. Two quote probes caused database errors absent from the normal response. Exploitation is not established.`,
      'Use parameterized statements and avoid exposing database errors.', { rule_id: 'vice/api/database-error', classification: 'probable', confidence: 'medium' });
    outcome?.(booleanInjection || errors === 2 ? 'fail' : completed === 2 ? 'pass' : 'unknown');
  }
}
