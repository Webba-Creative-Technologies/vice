export function parseDirectives(value, separator = ';') {
  const result = new Map();
  for (const item of String(value || '').split(separator)) {
    const match = /^\s*([\w-]+)(?:\s*=\s*|\s+)?(.*?)\s*$/.exec(item);
    if (!match) continue;
    const name = match[1].toLowerCase();
    if (!result.has(name)) result.set(name, match[2]);
  }
  return result;
}

export function cspScriptPolicy(value, kind = 'element') {
  const directives = parseDirectives(value);
  return (kind === 'element' ? directives.get('script-src-elem') : undefined) ?? directives.get('script-src') ?? directives.get('default-src') ?? '';
}

export function metaCsp(html) {
  for (const tag of String(html).match(/<meta\b[^>]*>/gi) || []) {
    const attributes = new Map([...tag.matchAll(/([\w-]+)\s*=\s*(["'])(.*?)\2/g)].map(match => [match[1].toLowerCase(), match[3]]));
    if (attributes.get('http-equiv')?.toLowerCase() === 'content-security-policy') return attributes.get('content') || '';
  }
  return '';
}

export function hasFrameRestriction(xfo, csp) {
  const ancestors = parseDirectives(csp).get('frame-ancestors');
  if (ancestors !== undefined) return ancestors.trim().length > 0 && !/(?:^|\s)(?:\*|https?:)(?:\s|$)/.test(ancestors);
  return /^(?:DENY|SAMEORIGIN)$/i.test(String(xfo || '').trim());
}

export function dmarcPolicy(value) {
  const directives = parseDirectives(value);
  if (directives.get('v')?.toUpperCase() !== 'DMARC1') return null;
  const entries = String(value).split(';').filter(entry => /^\s*p\s*=/i.test(entry));
  const policy = directives.get('p')?.toLowerCase();
  return entries.length === 1 && ['none', 'quarantine', 'reject'].includes(policy) ? policy : null;
}
