// ──────────────────────────────────────────────
// VICE - Shared Regex Patterns
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

const SUPABASE_JWT_SOURCE = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+';

export function extractAssignedSecretValue(match) {
  const text = String(match || '').trim();
  const bearer = text.match(/^Bearer\s+([^\s]+)$/i);
  if (bearer) return bearer[1];
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) return text;
  const namedAssignment = text.match(/^[A-Za-z_][A-Za-z0-9_.-]*\s*(?:=|:(?!\/\/))\s*(.+)$/);
  if (namedAssignment) return namedAssignment[1].replace(/^["']|["']$/g, '').trim();
  const quoted = text.match(/[=:]\s*["']([^"']+)["']\s*$/);
  if (quoted) return quoted[1];
  const assigned = text.match(/[=:"']+\s*([A-Za-z0-9_.!@#$%^&*\/-]+)\s*$/);
  return assigned?.[1] || text;
}

export function isLikelyGenericSecret(match) {
  const value = extractAssignedSecretValue(match);
  if (value.length < 16) return false;
  if (/^[A-Z][A-Z0-9_]+$/.test(value)) return false;
  if (/^[a-z]+(?:[_-][a-z]+){1,}$|^[a-z]+(?:[A-Z][a-z]+){1,}$/.test(value)) return false;
  return /\d/.test(value) || (/[A-Z]/.test(value) && /[a-z]/.test(value));
}

export function classifySupabaseJwt(token) {
  try {
    const parts = String(token || '').split('.');
    if (parts.length !== 3) return null;
    const payload = JSON.parse(Buffer.from(parts[1], 'base64url').toString('utf8'));
    return typeof payload.role === 'string' ? payload.role : null;
  } catch {
    return null;
  }
}

export function isPublicSupabaseAnonMatch(source, match, matchIndex = -1) {
  const value = extractAssignedSecretValue(match);
  if (classifySupabaseJwt(value) === 'anon') return true;

  const index = matchIndex >= 0 ? matchIndex : String(source || '').indexOf(String(match || ''));
  if (index < 0) return false;
  const context = String(source || '').slice(index, index + String(match || '').length + 512);
  const candidates = context.match(new RegExp(SUPABASE_JWT_SOURCE, 'g')) || [];
  return candidates.some((token) => classifySupabaseJwt(token) === 'anon' && (
    String(match || '').includes(token.split('.')[0]) || /^Bearer\s/i.test(String(match || ''))
  ));
}

export function isPlaceholderSecret(match) {
  const text = String(match || '').trim();
  const value = extractAssignedSecretValue(text).replace(/^["']|["']$/g, '').trim();
  if (!value) return true;

  if (/^(?:(?:VITE|NEXT_PUBLIC|PUBLIC|REACT_APP|NUXT_PUBLIC)_)?[A-Z][A-Z0-9_]{2,}$/.test(value)
    && /(?:API|AUTH|CREDENTIAL|KEY|PASSWORD|SECRET|TOKEN)/.test(value)) {
    return true;
  }

  if (/^AKIAIOSFODNN7EXAMPLE$|^ASIA[A-Z0-9]{9}EXAMPLE$/i.test(value)) return true;
  if (/aws[_-]?(?:secret|secret[_-]?access)[_-]?key/i.test(text) && /EXAMPLEKEY$/i.test(value)) return true;

  if (/^(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\//i.test(value)) {
    try {
      const parsed = new URL(value);
      const host = parsed.hostname.toLowerCase();
      const password = decodeURIComponent(parsed.password || '');
      if (/(^|\.)(?:example\.(?:com|net|org)|example|invalid|test)$/.test(host)) return true;
      if (password && isPlaceholderValue(password)) return true;
    } catch {}
  }

  const discordToken = value.match(/^https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/([^/?#]+)/i)?.[1];
  if (discordToken && isPlaceholderValue(discordToken)) return true;

  const providerBody = value
    .replace(/^(?:sk|pk)_(?:live|test)_/i, '')
    .replace(/^gh[pousr]_/i, '')
    .replace(/^github_pat_/i, '')
    .replace(/^glpat-/i, '')
    .replace(/^npm_/i, '')
    .replace(/^pypi-AgEIcHlwaS5vcmc/i, '')
    .replace(/^xox[baprs]-/i, '')
    .replace(/^SG\./i, '')
    .replace(/^AIzaSy/i, '')
    .replace(/^AIza/i, '');

  return isPlaceholderValue(value) || (providerBody !== value && isPlaceholderValue(providerBody));
}

function isPlaceholderValue(value) {
  const normalized = String(value || '').trim().toLowerCase();
  const compact = normalized.replace(/[^a-z0-9]/g, '');

  if (/^(?:redacted|masked|hidden|none|null|undefined|todo|fixme|development|develop|dev|local|testing|testonly)$/.test(compact)) {
    return true;
  }

  if (/^(?:your|example|placeholder|dummy|sample|fake|mock)(?:api|access|auth|client|credential|key|password|private|public|secret|service|stripe|token|value|here|aws|firebase|github|gitlab|npm|sendgrid|slack|twilio)*\d*$/.test(compact)) {
    return true;
  }

  if (/^(?:changeme|replaceme|replace(?:this|withrealvalue|withsecret)|insert(?:key|secret|token|value)?here|notareal(?:key|password|secret|token)|notasecret)$/.test(compact)) {
    return true;
  }

  if (/^(?:x+|y+|z+|0+)$/.test(compact)) return true;
  if (compact.length < 12) return false;
  if (compact.length > 4096) return false;

  const repetitionLength = (compact + compact).indexOf(compact, 1);
  return repetitionLength > 0
    && repetitionLength < compact.length
    && compact.length % repetitionLength === 0;
}

export const SECRET_PATTERNS = [
  { name: 'Supabase Service Role',  regex: new RegExp(SUPABASE_JWT_SOURCE, 'g'), validate: token => classifySupabaseJwt(token) === 'service_role' },
  { name: 'Discord Webhook',        regex: /https:\/\/(?:canary\.|ptb\.)?discord(?:app)?\.com\/api\/webhooks\/\d+\/[A-Za-z0-9_-]+/gi },
  { name: 'Stripe Secret Key',      regex: /sk_(live|test)_[a-zA-Z0-9]{20,}/g },
  { name: 'Stripe Publishable Key', regex: /pk_(live|test)_[a-zA-Z0-9]{20,}/g },
  { name: 'AWS Access Key',         regex: /AKIA[0-9A-Z]{16}/g },
  { name: 'AWS Temporary Access Key', regex: /ASIA[0-9A-Z]{16}/g },
  { name: 'AWS Secret Key',         regex: /(?:aws_secret|secret_key|secretAccessKey)[\s:="']+[a-zA-Z0-9\/+=]{30,}/gi },
  { name: 'Firebase API Key',       regex: /AIza[0-9A-Za-z_-]{35}/g },
  { name: 'Google OAuth',           regex: /[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com/g },
  { name: 'GitHub Token',           regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g },
  { name: 'GitHub Fine-grained Token', regex: /github_pat_[A-Za-z0-9_]{40,}/g },
  { name: 'GitLab Token',           regex: /glpat-[A-Za-z0-9_-]{20,}/g },
  { name: 'npm Token',              regex: /npm_[A-Za-z0-9]{36}/g },
  { name: 'PyPI Token',             regex: /pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{40,}/g },
  { name: 'Slack Token',            regex: /xox[baprs]-[A-Za-z0-9-]{10,}/g },
  { name: 'SendGrid API Key',       regex: /SG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{20,}/g },
  { name: 'Twilio Auth Token',      regex: /(?:TWILIO_AUTH_TOKEN|twilio[_-]?auth[_-]?token)[\s:="']+([a-f0-9]{32})/gi },
  { name: 'Database Credential URL', regex: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis):\/\/[^:\s/]+:[^@\s/]+@[^\s"'`]+/gi },
  { name: 'Client Secret',          regex: /(?:client[_-]?secret|clientSecret)[\s]*[=:][\s]*["'][a-zA-Z0-9_\-!@#$%^&*]{16,}["']/gi, validate: isLikelyGenericSecret },
  { name: 'Generic API Key',        regex: /(?:api[_-]?key|apikey|api_secret)[\s:="']+[a-zA-Z0-9_\-]{16,}/gi, validate: isLikelyGenericSecret },
  { name: 'Generic Secret',         regex: /(?:secret|passwd|pwd)[\s]*[=:][\s]*["'][a-zA-Z0-9_\-!@#$%^&*]{16,}["']/gi, validate: isLikelyGenericSecret },
  { name: 'Private Key',            regex: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
  { name: 'Bearer Token',           regex: /Bearer\s+[a-zA-Z0-9_\-\.]+/g },
];

export const IP_PATTERN = /(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)(?::\d{2,5})?(?!\d)/g;

export const SECURITY_HEADERS = [
  { name: 'Strict-Transport-Security', severity: 'MOYENNE' },
  { name: 'Content-Security-Policy',   severity: 'ELEVEE' },
  { name: 'X-Frame-Options',           severity: 'MOYENNE' },
  { name: 'X-Content-Type-Options',    severity: 'MOYENNE' },
  { name: 'Referrer-Policy',           severity: 'FAIBLE' },
  { name: 'Permissions-Policy',        severity: 'FAIBLE' },
];

export const LEAK_HEADERS = ['X-Powered-By', 'Server', 'X-AspNet-Version', 'X-AspNetMvc-Version'];

export const SENSITIVE_PATHS = [
  '/.env', '/.env.local', '/.env.production', '/.env.development',
  '/.git/config', '/.git/HEAD',
  '/wp-config.php', '/config.json', '/package.json',
  '/.DS_Store', '/robots.txt', '/sitemap.xml',
  '/.htaccess', '/server.js', '/api/', '/.well-known/',
  '/graphql', '/admin', '/debug', '/phpinfo.php',
  '/_next/static/', '/static/js/',
];
