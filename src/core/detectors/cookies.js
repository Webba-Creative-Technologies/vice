const SEVERITY_RANK = { INFO: 0, FAIBLE: 1, MOYENNE: 2, ELEVEE: 3, CRITIQUE: 4 };
const SENSITIVE_NAME = /session|token|auth|jwt|sid|csrf|supabase|access|refresh|connect\.sid|laravel_session/i;

function highestSeverity(issues) {
  return issues.reduce((highest, issue) => (
    SEVERITY_RANK[issue.severity] > SEVERITY_RANK[highest] ? issue.severity : highest
  ), 'INFO');
}

export function getSetCookieHeaders(headers) {
  if (typeof headers?.getSetCookie === 'function') {
    const values = headers.getSetCookie();
    if (values.length > 0) return values;
  }

  const combined = headers?.get?.('set-cookie');
  if (!combined) return [];
  return combined.split(/,(?=\s*[^;,=\s]+=[^;,]*)/g).map((value) => value.trim()).filter(Boolean);
}

export function classifySetCookie(header, options = {}) {
  const parts = String(header || '').split(';').map((part) => part.trim()).filter(Boolean);
  const separator = parts[0]?.indexOf('=') ?? -1;
  if (separator <= 0) return null;

  const name = parts[0].slice(0, separator).trim();
  const attributes = new Map();
  for (const part of parts.slice(1)) {
    const index = part.indexOf('=');
    const key = (index === -1 ? part : part.slice(0, index)).trim().toLowerCase();
    const value = index === -1 ? true : part.slice(index + 1).trim();
    attributes.set(key, value);
  }

  const sensitive = SENSITIVE_NAME.test(name);
  const secure = attributes.has('secure');
  const httpOnly = attributes.has('httponly');
  const sameSite = String(attributes.get('samesite') || '').toLowerCase();
  const issues = [];

  if (sensitive && !httpOnly) {
    issues.push({ severity: 'ELEVEE', message: 'sensitive cookie is accessible to client-side JavaScript' });
  }
  if (options.https && !secure) {
    issues.push({ severity: sensitive ? 'ELEVEE' : 'FAIBLE', message: 'cookie can be sent without the Secure requirement' });
  }
  if (sensitive && !sameSite) {
    issues.push({ severity: 'MOYENNE', message: 'sensitive cookie has no SameSite attribute' });
  }
  if (sameSite === 'none' && !secure) {
    issues.push({ severity: 'MOYENNE', message: 'SameSite=None without Secure is rejected by modern browsers' });
  }
  if (name.startsWith('__Secure-') && !secure) {
    issues.push({ severity: 'ELEVEE', message: '__Secure- prefix requirements are not met' });
  }
  if (name.startsWith('__Host-') && (!secure || attributes.has('domain') || attributes.get('path') !== '/')) {
    issues.push({ severity: 'ELEVEE', message: '__Host- prefix requires Secure, Path=/, and no Domain attribute' });
  }

  if (issues.length === 0) return null;
  return {
    name,
    sensitive,
    severity: highestSeverity(issues),
    issues: issues.map((issue) => issue.message),
  };
}
