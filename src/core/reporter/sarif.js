// ──────────────────────────────────────────────
// VICE — SARIF v2.1.0 Reporter
// Webba Creative Technologies (c) 2026
//
// Produces a SARIF v2.1.0 document suitable for upload to
// GitHub code scanning via github/codeql-action/upload-sarif@v3.
// ──────────────────────────────────────────────

const SARIF_SCHEMA = 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json';
const SARIF_VERSION = '2.1.0';
const INFO_URI = 'https://github.com/Webba-Creative-Technologies/vice';
const HELP_URI = 'https://github.com/Webba-Creative-Technologies/vice#github-action';

// ── Severity mapping (VICE → SARIF level) ──────────────────────

function severityToLevel(severity) {
  switch (severity) {
    case 'CRITICAL':
    case 'CRITIQUE':
    case 'HIGH':
    case 'ELEVEE':
      return 'error';
    case 'MEDIUM':
    case 'MOYENNE':
      return 'warning';
    case 'LOW':
    case 'FAIBLE':
      return 'note';
    case 'INFO':
    default:
      return 'note';
  }
}

function isInfoSeverity(severity) {
  return severity === 'INFO';
}

// ── Path normalization ────────────────────────────────────────

function normalizePath(p) {
  if (!p) return '.';
  return String(p).replace(/\\/g, '/');
}

// ── Rule ID derivation ────────────────────────────────────────

function slugify(s) {
  return String(s || '')
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '') || 'generic';
}

export function findingToRuleId(finding) {
  const module = finding && finding.module ? finding.module : '';
  const title = finding && finding.title ? finding.title : '';

  // Code Vulnerabilities
  if (module === 'Code Vulnerabilities') {
    if (/^SQL Injection: Template/i.test(title)) return 'vice/code/sqli-template';
    if (/^SQL Injection: String concatenation/i.test(title)) return 'vice/code/sqli-concat';
    if (/^SQL Injection: Interpolated/i.test(title)) return 'vice/code/sqli-where';
    if (/^dangerouslySetInnerHTML/i.test(title)) return 'vice/code/xss-react';
    if (/^v-html/i.test(title)) return 'vice/code/xss-vue';
    if (/^innerHTML/i.test(title)) return 'vice/code/xss-dom';
    if (/^eval\(\)/i.test(title) || /\beval\b/i.test(title)) return 'vice/code/eval';
    if (/^Command injection/i.test(title)) return 'vice/code/cmd-injection';
    if (/^Open redirect/i.test(title)) return 'vice/code/open-redirect';
    if (/^Weak hash/i.test(title)) return 'vice/code/weak-crypto';
    if (/^Potential ReDoS/i.test(title)) return 'vice/code/redos';
    return 'vice/code/generic';
  }

  // Auth & Middleware
  if (module === 'Auth & Middleware') {
    if (/^CORS wildcard/i.test(title)) return 'vice/auth/cors-wildcard';
    if (/^Hardcoded password/i.test(title)) return 'vice/auth/hardcoded-password';
    if (/^Insecure session cookie/i.test(title)) return 'vice/auth/insecure-session';
    if (/^Session without httpOnly/i.test(title)) return 'vice/auth/session-no-httponly';
    if (/^JWT without expiration/i.test(title)) return 'vice/auth/jwt-no-expiration';
    if (/No rate limiting/i.test(title)) return 'vice/auth/no-rate-limiting';
    if (/No CSRF/i.test(title)) return 'vice/auth/no-csrf';
    if (/Helmet not installed/i.test(title)) return 'vice/auth/no-helmet';
    if (/No auth middleware/i.test(title)) return 'vice/auth/no-auth-middleware';
    return 'vice/auth/generic';
  }

  // Code Secrets
  if (module === 'Code Secrets') {
    if (/^Hardcoded secret/i.test(title) || /secret/i.test(title)) return 'vice/secrets/hardcoded-secret';
    return 'vice/secrets/hardcoded-secret';
  }

  // Environment Files
  if (module === 'Environment Files') {
    if (/\.env/i.test(title)) return 'vice/env/exposed-env';
    return 'vice/env/exposed-env';
  }

  // Dependencies
  if (module === 'Dependencies') {
    return 'vice/deps/vulnerable-dep';
  }

  // Supabase RLS
  if (module === 'Supabase RLS') {
    return 'vice/rls/missing-rls';
  }

  // Headers Config
  if (module === 'Headers Config') {
    if (/No CSP/i.test(title)) return 'vice/headers/no-csp';
    if (/No HSTS/i.test(title)) return 'vice/headers/no-hsts';
    if (/X-Powered-By/i.test(title)) return 'vice/headers/x-powered-by';
    return 'vice/headers/generic';
  }

  // Git History
  if (module === 'Git History') return 'vice/git-history/leaked-secret';

  // Container
  if (module === 'Container') return 'vice/container/misconfig';

  // CI/CD Security
  if (module === 'CI/CD Security') {
    if (/Unpinned action/i.test(title)) return 'vice/ci/unpinned-action';
    if (/Secret echoed|Hardcoded secret/i.test(title)) return 'vice/ci/secret-leak';
    if (/pull_request_target/i.test(title)) return 'vice/ci/pr-target';
    if (/write-all/i.test(title)) return 'vice/ci/write-all';
    if (/comment body/i.test(title)) return 'vice/ci/script-injection';
    return 'vice/ci/generic';
  }

  // Storage Security (localStorage / sessionStorage tokens)
  if (module === 'Storage Security') return 'vice/storage/token-in-storage';

  // SRI
  if (module === 'SRI') return 'vice/sri/missing-integrity';

  // Mixed Content
  if (module === 'Mixed Content') return 'vice/mixed-content/http-on-https';

  // TLS
  if (module === 'TLS') return 'vice/tls/issue';

  // GraphQL
  if (module === 'GraphQL') return 'vice/graphql/issue';

  // WordPress
  if (module === 'WordPress') return 'vice/wordpress/issue';

  // Fallback
  const moduleSlug = slugify(module);
  return `vice/${moduleSlug}/generic`;
}

// ── Rule metadata ─────────────────────────────────────────────

const RULE_METADATA = {
  'vice/code/sqli-template': {
    name: 'SqlInjectionTemplateLiteral',
    short: 'SQL injection via template literal',
    full: 'Template literals with interpolation in SQL queries allow attackers to inject arbitrary SQL. Use parameterized queries instead.',
    level: 'error',
  },
  'vice/code/sqli-concat': {
    name: 'SqlInjectionStringConcat',
    short: 'SQL injection via string concatenation',
    full: 'Concatenating user input into SQL query strings allows attackers to inject arbitrary SQL. Use parameterized queries instead.',
    level: 'error',
  },
  'vice/code/sqli-where': {
    name: 'SqlInjectionWhereClause',
    short: 'SQL injection in WHERE clause',
    full: 'Interpolating variables directly into SQL WHERE clauses is a SQL injection vector. Use parameterized queries.',
    level: 'error',
  },
  'vice/code/xss-react': {
    name: 'XssReactDangerouslySetInnerHtml',
    short: 'React dangerouslySetInnerHTML detected',
    full: 'dangerouslySetInnerHTML injects raw HTML and creates an XSS risk if the data originates from user input. Sanitize with DOMPurify.',
    level: 'error',
  },
  'vice/code/xss-vue': {
    name: 'XssVueVHtml',
    short: 'Vue v-html directive detected',
    full: 'v-html injects raw HTML and creates an XSS risk if the data originates from user input. Use text interpolation or sanitize the value.',
    level: 'error',
  },
  'vice/code/xss-dom': {
    name: 'XssInnerHtmlAssignment',
    short: 'innerHTML assignment detected',
    full: 'Direct innerHTML assignment injects raw HTML into the DOM and creates an XSS risk. Use textContent or a sanitizer.',
    level: 'error',
  },
  'vice/code/eval': {
    name: 'EvalUsage',
    short: 'Dynamic code execution detected',
    full: 'Dynamic code execution APIs run arbitrary code and are an injection vector. Refactor to avoid them.',
    level: 'error',
  },
  'vice/code/cmd-injection': {
    name: 'CommandInjection',
    short: 'Command injection risk detected',
    full: 'Shell commands built from interpolation or concatenation can be exploited for command injection. Use execFile with separate arguments.',
    level: 'error',
  },
  'vice/code/open-redirect': {
    name: 'OpenRedirect',
    short: 'Open redirect detected',
    full: 'Redirecting to a user-controlled URL without validation enables open redirect attacks. Validate against an allow-list of origins.',
    level: 'error',
  },
  'vice/code/weak-crypto': {
    name: 'WeakHashAlgorithm',
    short: 'Weak hash algorithm (MD5/SHA1)',
    full: 'MD5 and SHA1 are not considered secure. Use SHA-256 for hashing or bcrypt/argon2 for passwords.',
    level: 'warning',
  },
  'vice/code/redos': {
    name: 'RegexDenialOfService',
    short: 'Potential regular expression DoS',
    full: 'A RegExp built from user input can cause catastrophic backtracking and denial of service. Never build RegExp from untrusted input.',
    level: 'error',
  },
  'vice/code/generic': {
    name: 'CodeVulnerability',
    short: 'Code vulnerability detected',
    full: 'A potential code vulnerability was detected by VICE.',
    level: 'warning',
  },

  'vice/auth/cors-wildcard': {
    name: 'CorsWildcardOrigin',
    short: 'CORS wildcard origin detected',
    full: 'Allowing all origins (*) lets any site call the API with user cookies. Restrict origins to a specific allow-list.',
    level: 'error',
  },
  'vice/auth/hardcoded-password': {
    name: 'HardcodedPassword',
    short: 'Hardcoded password in source',
    full: 'A password is hardcoded in source code. Move credentials to environment variables or a secrets manager.',
    level: 'error',
  },
  'vice/auth/insecure-session': {
    name: 'InsecureSessionCookie',
    short: 'Insecure session cookie',
    full: 'Session cookie is configured with secure: false and may be transmitted over plain HTTP. Set secure: true in production.',
    level: 'error',
  },
  'vice/auth/session-no-httponly': {
    name: 'SessionCookieNotHttpOnly',
    short: 'Session cookie without httpOnly',
    full: 'Session cookie is accessible via JavaScript, enabling XSS-based session theft. Add httpOnly: true.',
    level: 'error',
  },
  'vice/auth/jwt-no-expiration': {
    name: 'JwtWithoutExpiration',
    short: 'JWT signed without expiration',
    full: 'A JWT signed without expiresIn is valid forever if stolen. Always set an expiresIn when calling jwt.sign().',
    level: 'error',
  },
  'vice/auth/no-rate-limiting': {
    name: 'NoRateLimiting',
    short: 'No rate limiting detected',
    full: 'No rate limiting package or middleware was detected. Endpoints are vulnerable to brute force attacks.',
    level: 'error',
  },
  'vice/auth/no-csrf': {
    name: 'NoCsrfProtection',
    short: 'No CSRF protection detected',
    full: 'No CSRF protection was detected. Forms may be vulnerable to cross-site request forgery.',
    level: 'warning',
  },
  'vice/auth/no-helmet': {
    name: 'HelmetNotInstalled',
    short: 'Helmet not installed',
    full: 'Helmet (which sets secure HTTP headers) is not installed in this Express project.',
    level: 'warning',
  },
  'vice/auth/no-auth-middleware': {
    name: 'NoAuthMiddleware',
    short: 'No auth middleware detected',
    full: 'No authentication middleware was detected. Auth may be handled by an external service.',
    level: 'note',
  },
  'vice/auth/generic': {
    name: 'AuthMiddlewareIssue',
    short: 'Auth / middleware issue detected',
    full: 'A potential auth or middleware issue was detected by VICE.',
    level: 'warning',
  },

  'vice/secrets/hardcoded-secret': {
    name: 'HardcodedSecret',
    short: 'Hardcoded secret in source',
    full: 'A secret, API key or token appears to be hardcoded in source code. Move it to environment variables.',
    level: 'error',
  },

  'vice/env/exposed-env': {
    name: 'ExposedEnvFile',
    short: 'Exposed environment file',
    full: 'An environment file may be exposed or misconfigured. Verify .env files are git-ignored and not deployed.',
    level: 'warning',
  },

  'vice/deps/vulnerable-dep': {
    name: 'VulnerableDependency',
    short: 'Vulnerable dependency detected',
    full: 'A dependency with a known vulnerability was detected. Update to a patched version.',
    level: 'warning',
  },

  'vice/rls/missing-rls': {
    name: 'SupabaseRlsIssue',
    short: 'Supabase RLS policy issue',
    full: 'A Supabase Row Level Security policy issue was detected. Enable RLS on all user-facing tables.',
    level: 'error',
  },

  'vice/headers/no-csp': {
    name: 'NoContentSecurityPolicy',
    short: 'No Content-Security-Policy header',
    full: 'No Content-Security-Policy header was detected. CSP mitigates XSS and data injection attacks.',
    level: 'warning',
  },
  'vice/headers/no-hsts': {
    name: 'NoHstsHeader',
    short: 'No HSTS header',
    full: 'No Strict-Transport-Security header was detected. HSTS forces HTTPS connections.',
    level: 'warning',
  },
  'vice/headers/x-powered-by': {
    name: 'XPoweredByExposed',
    short: 'X-Powered-By header exposed',
    full: 'The X-Powered-By header leaks server technology information. Disable it.',
    level: 'note',
  },
  'vice/headers/generic': {
    name: 'HeadersConfigIssue',
    short: 'Headers configuration issue',
    full: 'A headers configuration issue was detected by VICE.',
    level: 'warning',
  },
};

// ── Rule taxonomy (CWE + OWASP Top 10 2021) ───────────────────
// Mapping every concrete rule to a CWE id and an OWASP category.
// Used to enrich SARIF properties.tags and the JSON report with
// references that GitHub Code Scanning and human reviewers expect.
export const RULE_TAXONOMY = {
  'vice/code/sqli-template':       { cwe: 89,  owasp: 'A03:2021' },
  'vice/code/sqli-concat':         { cwe: 89,  owasp: 'A03:2021' },
  'vice/code/sqli-where':          { cwe: 89,  owasp: 'A03:2021' },
  'vice/code/xss-react':           { cwe: 79,  owasp: 'A03:2021' },
  'vice/code/xss-vue':             { cwe: 79,  owasp: 'A03:2021' },
  'vice/code/xss-dom':             { cwe: 79,  owasp: 'A03:2021' },
  'vice/code/eval':                { cwe: 95,  owasp: 'A03:2021' },
  'vice/code/cmd-injection':       { cwe: 78,  owasp: 'A03:2021' },
  'vice/code/open-redirect':       { cwe: 601, owasp: 'A01:2021' },
  'vice/code/weak-crypto':         { cwe: 327, owasp: 'A02:2021' },
  'vice/code/redos':               { cwe: 1333, owasp: 'A05:2021' },
  'vice/auth/cors-wildcard':       { cwe: 942, owasp: 'A01:2021' },
  'vice/auth/hardcoded-password':  { cwe: 798, owasp: 'A07:2021' },
  'vice/auth/insecure-session':    { cwe: 614, owasp: 'A05:2021' },
  'vice/auth/session-no-httponly': { cwe: 1004, owasp: 'A05:2021' },
  'vice/auth/jwt-no-expiration':   { cwe: 613, owasp: 'A07:2021' },
  'vice/auth/no-rate-limiting':    { cwe: 307, owasp: 'A04:2021' },
  'vice/auth/no-csrf':             { cwe: 352, owasp: 'A01:2021' },
  'vice/auth/no-helmet':           { cwe: 693, owasp: 'A05:2021' },
  'vice/secrets/hardcoded-secret': { cwe: 798, owasp: 'A07:2021' },
  'vice/env/exposed-env':          { cwe: 200, owasp: 'A05:2021' },
  'vice/deps/vulnerable-dep':      { cwe: 1104, owasp: 'A06:2021' },
  'vice/rls/missing-rls':          { cwe: 862, owasp: 'A01:2021' },
  'vice/headers/no-csp':           { cwe: 693, owasp: 'A05:2021' },
  'vice/headers/no-hsts':          { cwe: 319, owasp: 'A02:2021' },
  'vice/headers/x-powered-by':     { cwe: 200, owasp: 'A05:2021' },

  // Phase 3+ modules
  'vice/git-history/leaked-secret':    { cwe: 798,  owasp: 'A07:2021' },
  'vice/container/misconfig':          { cwe: 668,  owasp: 'A05:2021' },
  'vice/ci/unpinned-action':           { cwe: 1357, owasp: 'A08:2021' },
  'vice/ci/secret-leak':               { cwe: 532,  owasp: 'A09:2021' },
  'vice/ci/pr-target':                 { cwe: 829,  owasp: 'A08:2021' },
  'vice/ci/write-all':                 { cwe: 250,  owasp: 'A04:2021' },
  'vice/ci/script-injection':          { cwe: 78,   owasp: 'A03:2021' },
  'vice/storage/token-in-storage':     { cwe: 922,  owasp: 'A02:2021' },
  'vice/sri/missing-integrity':        { cwe: 829,  owasp: 'A08:2021' },
  'vice/mixed-content/http-on-https':  { cwe: 311,  owasp: 'A02:2021' },
  'vice/tls/issue':                    { cwe: 326,  owasp: 'A02:2021' },
  'vice/graphql/issue':                { cwe: 200,  owasp: 'A05:2021' },
  'vice/wordpress/issue':              { cwe: 200,  owasp: 'A05:2021' },
};

// Map rule level (or finding severity) to a CVSS-style numeric string,
// the format GitHub Code Scanning expects for properties["security-severity"].
const LEVEL_TO_SECURITY_SEVERITY = {
  error: '7.0',
  warning: '5.0',
  note: '3.0',
};

// Enrich a findings array with `ruleId`, `cwe`, and `owasp` fields.
// Returns a new array, does not mutate the input.
export function enrichWithTaxonomy(findings) {
  if (!Array.isArray(findings)) return findings;
  return findings.map(f => {
    const ruleId = findingToRuleId(f);
    const tax = RULE_TAXONOMY[ruleId];
    const enriched = { ...f, ruleId };
    if (tax) {
      enriched.cwe = `CWE-${tax.cwe}`;
      enriched.owasp = tax.owasp;
    }
    return enriched;
  });
}

function getRuleMetadata(ruleId, finding) {
  if (RULE_METADATA[ruleId]) return RULE_METADATA[ruleId];

  // Generic fallback derived from the finding
  const title = (finding && finding.title) || 'VICE finding';
  const detail = (finding && finding.detail) || '';
  const pascal = slugify(ruleId.split('/').pop() || 'Generic')
    .split('-')
    .map(s => s.charAt(0).toUpperCase() + s.slice(1))
    .join('') || 'ViceFinding';
  return {
    name: pascal || 'ViceFinding',
    short: String(title).slice(0, 120),
    full: String(detail || title).slice(0, 500),
    level: 'warning',
  };
}

// ── Location extraction ───────────────────────────────────────

function extractLocation(finding) {
  // 1. Use explicit finding.location if present
  if (finding && finding.location && finding.location.file) {
    return {
      file: finding.location.file,
      line: typeof finding.location.line === 'number' ? finding.location.line : undefined,
    };
  }

  // 2. Try parsing `in src/foo.js:42` from the title
  const title = (finding && finding.title) || '';
  const titleMatch = title.match(/in (.+?):(\d+)/);
  if (titleMatch) {
    return { file: titleMatch[1], line: parseInt(titleMatch[2], 10) };
  }

  // 3. Try parsing `src/foo.js:42` at the start of a line in detail
  const detail = (finding && finding.detail) || '';
  const detailMatch = detail.match(/^(.+?):(\d+)/m);
  if (detailMatch) {
    return { file: detailMatch[1], line: parseInt(detailMatch[2], 10) };
  }

  // 4. Default project root location with no region
  return { file: '.', line: undefined };
}

function buildLocation(finding) {
  const { file, line } = extractLocation(finding);
  const physicalLocation = {
    artifactLocation: { uri: normalizePath(file) },
  };
  if (typeof line === 'number' && line > 0) {
    physicalLocation.region = { startLine: line };
  }
  return { physicalLocation };
}

// ── Main entry point ──────────────────────────────────────────

export function buildSarif(findings, version) {
  const safeFindings = Array.isArray(findings) ? findings : [];
  const filtered = safeFindings.filter(f => f && !isInfoSeverity(f.severity) && !f.baselined);

  const ruleMap = new Map();
  const results = [];

  for (const finding of filtered) {
    const ruleId = findingToRuleId(finding);
    if (!ruleMap.has(ruleId)) {
      const meta = getRuleMetadata(ruleId, finding);
      const taxonomy = RULE_TAXONOMY[ruleId];
      const tags = ['security'];
      if (taxonomy) {
        tags.push(`external/cwe/cwe-${taxonomy.cwe}`);
        tags.push(`owasp/${taxonomy.owasp.toLowerCase().replace(':', '-')}`);
      }
      ruleMap.set(ruleId, {
        id: ruleId,
        name: meta.name,
        shortDescription: { text: meta.short },
        fullDescription: { text: meta.full },
        helpUri: HELP_URI,
        defaultConfiguration: { level: meta.level },
        properties: {
          tags,
          'security-severity': LEVEL_TO_SECURITY_SEVERITY[meta.level] || '5.0',
          ...(taxonomy ? { cwe: `CWE-${taxonomy.cwe}`, owasp: taxonomy.owasp } : {}),
        },
      });
    }

    const level = severityToLevel(finding.severity);
    const messageText = (finding.title && String(finding.title)) || (finding.detail && String(finding.detail)) || 'VICE finding';
    results.push({
      ruleId,
      level,
      message: { text: messageText },
      locations: [buildLocation(finding)],
    });
  }

  return {
    $schema: SARIF_SCHEMA,
    version: SARIF_VERSION,
    runs: [
      {
        tool: {
          driver: {
            name: 'VICE',
            version: version || '0.0.0',
            informationUri: INFO_URI,
            rules: Array.from(ruleMap.values()),
          },
        },
        results,
      },
    ],
  };
}
