// ──────────────────────────────────────────────
// VICE — Shared Regex Patterns
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

export const SECRET_PATTERNS = [
  { name: 'Supabase URL',           regex: /https?:\/\/[a-z0-9\-]+\.supabase\.co/gi },
  { name: 'Supabase Anon Key',      regex: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/g },
  { name: 'Stripe Secret Key',      regex: /sk_(live|test)_[a-zA-Z0-9]{20,}/g },
  { name: 'Stripe Publishable Key', regex: /pk_(live|test)_[a-zA-Z0-9]{20,}/g },
  { name: 'AWS Access Key',         regex: /AKIA[0-9A-Z]{16}/g },
  { name: 'AWS Secret Key',         regex: /(?:aws_secret|secret_key|secretAccessKey)[\s:="']+[a-zA-Z0-9\/+=]{30,}/gi },
  { name: 'Firebase API Key',       regex: /AIza[0-9A-Za-z_-]{35}/g },
  { name: 'Google OAuth',           regex: /[0-9]+-[a-z0-9_]{32}\.apps\.googleusercontent\.com/g },
  { name: 'GitHub Token',           regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g },
  { name: 'Generic API Key',        regex: /(?:api[_-]?key|apikey|api_secret)[\s:="']+[a-zA-Z0-9_\-]{16,}/gi },
  { name: 'Generic Secret',         regex: /(?:secret|passwd|pwd)[\s]*[=:][\s]*["'][a-zA-Z0-9_\-!@#$%^&*]{8,}["']/gi },
  { name: 'Supabase Service Role',  regex: /eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\.[a-zA-Z0-9_-]{50,}\.[a-zA-Z0-9_-]+/g },
  { name: 'Private Key',            regex: /-----BEGIN (?:RSA |EC )?PRIVATE KEY-----/g },
  { name: 'Bearer Token',           regex: /Bearer\s+[a-zA-Z0-9_\-\.]+/g },
];

export const IP_PATTERN = /(?<!\d)(?:(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d{2}|[1-9]\d|\d)(?::\d{2,5})?(?!\d)/g;

export const SECURITY_HEADERS = [
  { name: 'Strict-Transport-Security', severity: 'ELEVEE' },
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
