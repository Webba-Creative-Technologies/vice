// ──────────────────────────────────────────────
// VICE - Shared Regex Patterns
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

const SUPABASE_JWT_SOURCE = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\\.[a-zA-Z0-9_-]+\\.[a-zA-Z0-9_-]+';

export function extractAssignedSecretValue(match) {
  const text = String(match || '').trim();
  const bearer = text.match(/^Bearer\s+([^\s]+)$/i);
  if (bearer) return bearer[1];
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
  const quoted = text.match(/["']([^"']+)["']\s*$/);
  const assigned = text.match(/[=:]\s*([^\s]+)\s*$/);
  const value = (quoted?.[1] || assigned?.[1] || text).replace(/^["']|["']$/g, '').trim();

  return /^(?:your[_-].+|example(?:[_-].+)?|placeholder(?:[_-].+)?|x{3,}|y{3,}|z{3,}|changeme|replace[_-].+|insert[_-].+|todo|fixme|development|develop|dev|local|dummy|sample|testing?)$/i.test(value);
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
