import { randomUUID } from 'node:crypto';
import { surfaceUrl } from './surfaces.js';

export async function discoverLoginPage({ page, baseUrl, inventory, fetch }) {
  const observed = [...(inventory?.forms.values() || [])].filter(form => form.inputs.some(input => input.type === 'password')).map(form => form.pageUrl);
  const common = ['/login', '/auth/login', '/signin', '/auth/signin', '/sign-in', '/auth/sign-in', '/connexion', '/auth', '/account/login', '/user/login'];
  const candidates = [...new Set([baseUrl, ...observed, ...common.map(path => new URL(path, baseUrl).href)])].slice(0, 16);
  let rendered = 0;
  for (const value of candidates) {
    const url = surfaceUrl(value, baseUrl);
    if (!url) continue;
    if (value !== baseUrl && !observed.includes(value)) {
      const response = await fetch(url.href);
      if (response?.status !== 200 || !/password|mot de passe|login|connexion|sign.?in/i.test(await response.text())) continue;
    }
    if (++rendered > 4) break;
    try {
      const response = await page.goto(url.href, { waitUntil: 'domcontentloaded', timeout: 6000 });
      if (!response || response.status() >= 400) continue;
      await page.waitForNetworkIdle({ idleTime: 250, timeout: 1500 }).catch(() => {});
      if (new URL(page.url()).origin !== new URL(baseUrl).origin) continue;
      if (await page.evaluate(() => [...document.forms].some(form => form.querySelector('input[type="password"]')))) return page.url();
    } catch {}
  }
  return null;
}

export function createLoginProbe(origin) {
  const marker = `vice-${randomUUID()}`;
  return { origin, email: `${marker}@audit.invalid`, password: `${marker}-A7!`, remaining: 3, networkRemaining: 3 };
}

export function permitsLoginRequest(probe, url, method, body, network = false) {
  const counter = network ? 'networkRemaining' : 'remaining';
  if (!probe || probe[counter] <= 0 || url.origin !== probe.origin || method !== 'POST') return false;
  let content = String(body || '');
  try { content = decodeURIComponent(content.replaceAll('+', ' ')); } catch {}
  if (content.length > 16384 || !content.includes(probe.password) || !(content.includes(probe.email) || content.includes(encodeURIComponent(probe.email)))) return false;
  probe[counter]--;
  return true;
}

export async function auditLoginForm(page, probe, finding) {
  const fields = await page.evaluate(() => {
    const password = document.querySelector('input[type="password"]');
    const form = password?.form;
    if (!form) return null;
    const submit = form.querySelector('button[type="submit"], button:not([type]), input[type="submit"]');
    if (form.querySelectorAll('input[type="password"]').length > 1 || password.autocomplete === 'new-password'
      || /^(?:sign\s*up|register|create account|créer un compte)/i.test((submit?.textContent || submit?.value || '').trim())) return null;
    const email = form.querySelector('input[type="email"], input[name*="email"], input[name*="user"], input[autocomplete="username"]');
    return email ? { password: password.name || password.id, email: email.name || email.id } : null;
  });
  if (!fields?.password || !fields?.email) return { attempted: 0, outcome: 'unknown' };
  const requests = [];
  const sent = new Set();
  const responses = [];
  const reads = new Set();
  const loginUrl = page.url();
  const onRequest = request => {
    let body = request.postData() || '';
    try { body = decodeURIComponent(body.replaceAll('+', ' ')); } catch {}
    if (request.url().includes(encodeURIComponent(probe.password)) || body.includes(probe.password)) {
      requests.push({ method: request.method(), url: request.url() });
      sent.add(request);
    }
  };
  const onResponse = response => {
    if (!sent.has(response.request())) return;
    const read = (async () => {
      let data;
      try { data = JSON.parse((await response.text()).slice(0, 65536)); } catch {}
      responses.push({ status: response.status(), rejected: [401, 403].includes(response.status()) || Boolean(data?.error),
        session: Boolean(data?.user?.id && typeof data?.access_token === 'string' && data.access_token.length >= 20) });
    })();
    reads.add(read);
    read.finally(() => reads.delete(read));
  };
  page.on('request', onRequest);
  page.on('response', onResponse);
  try {
    const submit = async emailValue => {
      await page.evaluate(({ fields, probe, emailValue }) => {
      const find = name => [...document.querySelectorAll('input')].find(input => input.name === name || input.id === name);
      const email = find(fields.email), password = find(fields.password);
      const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, 'value').set;
      if (!email || !password) return;
      for (const [input, value] of [[email, emailValue], [password, probe.password]]) {
        setter.call(input, value);
        input.dispatchEvent(new Event('input', { bubbles: true }));
        input.dispatchEvent(new Event('change', { bubbles: true }));
      }
        password.form.noValidate = true;
        password.form.requestSubmit();
      }, { fields, probe: { password: probe.password }, emailValue });
      await page.waitForNetworkIdle({ idleTime: 300, timeout: 3000 }).catch(() => {});
      await Promise.allSettled([...reads]);
    };
    await submit(probe.email);
    if (responses[0]?.rejected) {
      for (const suffix of ["' OR '1'='1'--", "' OR '2'='2'--"]) {
        if (responses.some(response => response.status === 429 || response.session)) break;
        await page.goto(loginUrl, { waitUntil: 'domcontentloaded', timeout: 6000 });
        await submit(probe.email + suffix);
      }
    }
  } finally { page.off('request', onRequest); page.off('response', onResponse); }
  const exposed = requests.find(request => request.method === 'GET' && request.url.includes(encodeURIComponent(probe.password)));
  const insecure = requests.find(request => new URL(request.url).protocol === 'http:');
  if (exposed || insecure) finding('ELEVEE', 'Login Audit', exposed ? 'Login sends a password in the URL' : 'Login sends credentials over HTTP',
    'A submission using synthetic audit credentials demonstrated insecure password transport. Values are omitted.',
    'Submit credentials in a POST body over HTTPS.', { rule_id: 'vice/login/credential-transport', classification: 'confirmed', confidence: 'high' });
  const injectedSession = responses[0]?.rejected && responses.slice(1).some(response => response.session);
  if (injectedSession) finding('ELEVEE', 'Login Audit', 'A login injection probe returned session material after the control was rejected',
    'The synthetic control was rejected; an injected username returned an access token and a user identifier. Session values are omitted and no account data was accessed.',
    'Use parameterized authentication queries and verify server-side credential validation.',
    { rule_id: 'vice/login/injection-session', classification: 'probable', confidence: 'high' });
  if (responses.some(response => response.status === 429)) finding('INFO', 'Login Audit', 'Login throttling observed',
    'The server returned HTTP 429 during at most three synthetic attempts.', '',
    { rule_id: 'vice/login/rate-limit-observed', classification: 'confirmed', confidence: 'high' });
  return { attempted: requests.length, outcome: exposed || insecure || injectedSession ? 'fail' : responses.some(response => response.rejected) ? 'pass' : 'unknown' };
}
