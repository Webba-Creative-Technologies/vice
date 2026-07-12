const ENV_LINE = /^\s*(?:export\s+)?[A-Z][A-Z0-9_]{1,80}\s*=.+$/m;
const PRIVATE_ENV = /(?:DATABASE_URL|PRIVATE_KEY|SECRET|PASSWORD|PASSWD|TOKEN|SERVICE_ROLE|ACCESS_KEY)\s*=/i;
const PRIVATE_JSON_KEY = /["'](?:password|passwd|secret|private_key|service_role|database_url|access_token)["']\s*:/i;

export function classifySensitiveFile(path, body, mediaType = '') {
  const value = String(body || '');
  const type = String(mediaType || '').toLowerCase();
  if (value.length < 10 || type.includes('text/html') && !/phpinfo\(\)|PHP Version/i.test(value)) return null;

  if (/\/\.env(?:\.|$)/i.test(path)) {
    if (!ENV_LINE.test(value)) return null;
    const privateValue = PRIVATE_ENV.test(value);
    return {
      severity: privateValue ? 'CRITIQUE' : 'MOYENNE',
      confidence: 'high',
      classification: privateValue ? 'confirmed' : 'probable',
      kind: privateValue ? 'environment secrets' : 'environment configuration',
    };
  }

  if (/\/\.git\/HEAD$/i.test(path)) {
    if (!/^ref:\s+refs\/(?:heads|tags)\/|^[0-9a-f]{40}\s*$/im.test(value)) return null;
    return { severity: 'ELEVEE', confidence: 'high', classification: 'confirmed', kind: 'Git repository metadata' };
  }

  if (/\/\.git\/config$/i.test(path)) {
    if (!/^\s*\[(?:core|remote\s+"[^"]+")\]/im.test(value)) return null;
    return { severity: 'ELEVEE', confidence: 'high', classification: 'confirmed', kind: 'Git repository configuration' };
  }

  if (/wp-config\.php$/i.test(path)) {
    if (!/DB_(?:NAME|USER|PASSWORD|HOST)|AUTH_KEY|SECURE_AUTH_KEY/i.test(value)) return null;
    return { severity: 'CRITIQUE', confidence: 'high', classification: 'confirmed', kind: 'WordPress private configuration' };
  }

  if (/package\.json$/i.test(path)) {
    try {
      const parsed = JSON.parse(value);
      if (!parsed || typeof parsed !== 'object' || !parsed.name || !('dependencies' in parsed || 'scripts' in parsed)) return null;
      return { severity: 'FAIBLE', confidence: 'high', classification: 'hardening', kind: 'package manifest' };
    } catch {
      return null;
    }
  }

  if (/config\.json$/i.test(path)) {
    if (!PRIVATE_JSON_KEY.test(value)) return null;
    return { severity: 'CRITIQUE', confidence: 'high', classification: 'confirmed', kind: 'private JSON configuration' };
  }

  if (/\.DS_Store$/i.test(path)) {
    if (!value.includes('Bud1')) return null;
    return { severity: 'FAIBLE', confidence: 'high', classification: 'hardening', kind: 'directory metadata' };
  }

  if (/\.htaccess$/i.test(path)) {
    if (!/^\s*(?:RewriteEngine|RewriteRule|Options|Require|AuthType)\b/im.test(value)) return null;
    return { severity: 'MOYENNE', confidence: 'high', classification: 'confirmed', kind: 'web server configuration' };
  }

  if (/server\.js$/i.test(path)) {
    if (!/(?:require\s*\(|\bimport\s.+\bfrom\b|\.listen\s*\()/m.test(value)) return null;
    return { severity: 'ELEVEE', confidence: 'high', classification: 'confirmed', kind: 'server source code' };
  }

  if (/phpinfo\.php$/i.test(path)) {
    if (!/phpinfo\(\)|PHP Version|PHP Credits/i.test(value)) return null;
    return { severity: 'ELEVEE', confidence: 'high', classification: 'confirmed', kind: 'PHP runtime information' };
  }

  return null;
}
