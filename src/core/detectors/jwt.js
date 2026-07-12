const JWT_PATTERN = /\b[A-Za-z0-9_-]{8,2048}\.[A-Za-z0-9_-]{8,4096}\.[A-Za-z0-9_-]{0,2048}(?=$|[^A-Za-z0-9_-])/g;
const PRIVILEGED_ROLES = new Set(['admin', 'administrator', 'superadmin', 'superuser', 'root']);

function decodeSegment(segment) {
  return JSON.parse(Buffer.from(segment, 'base64url').toString('utf8'));
}

function extractRoles(payload) {
  const values = [payload?.role];
  if (Array.isArray(payload?.roles)) values.push(...payload.roles);
  if (Array.isArray(payload?.realm_access?.roles)) values.push(...payload.realm_access.roles);
  return [...new Set(values.filter(value => typeof value === 'string').map(value => value.toLowerCase()))];
}

export function findJwtCandidates(content, limit = 100) {
  if (typeof content !== 'string' || limit <= 0) return [];
  return [...content.matchAll(JWT_PATTERN)].slice(0, limit).map(match => match[0]);
}

export function analyzeJwt(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;

  let header;
  let payload;
  try {
    header = decodeSegment(parts[0]);
    payload = decodeSegment(parts[1]);
  } catch {
    return null;
  }

  if (!header || typeof header !== 'object' || !payload || typeof payload !== 'object') return null;

  const signals = [];
  const algorithm = typeof header.alg === 'string' ? header.alg : null;
  const roles = extractRoles(payload);

  if (algorithm?.toLowerCase() === 'none' || parts[2].length === 0) {
    signals.push({
      type: 'unsigned',
      severity: 'ELEVEE',
      title: 'Unsigned JWT embedded in client code',
      detail: 'A JWT using alg=none or an empty signature is embedded in a public client resource.',
      recommendation: 'Remove the token and ensure every verifier explicitly rejects unsigned JWTs.',
      classification: 'confirmed',
      confidence: 'high',
    });
  }

  const privilegedRoles = roles.filter(role => PRIVILEGED_ROLES.has(role));
  if (privilegedRoles.length > 0) {
    signals.push({
      type: 'privileged-role',
      severity: 'ELEVEE',
      title: 'Privileged JWT embedded in client code',
      detail: `A signed JWT declares privileged role(s): ${privilegedRoles.join(', ')}. Token validity and server-side acceptance were not assumed.`,
      recommendation: 'Remove static privileged tokens from public resources, rotate their signing context if needed, and verify authorization server-side.',
      classification: 'probable',
      confidence: 'high',
    });
  }

  return { header, payload, roles, signals };
}
