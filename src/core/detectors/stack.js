import { createHash } from 'node:crypto';
import { redactSensitiveText } from '../redaction.js';

const SOURCE_LIMIT = 180;
const CHARACTER_LIMIT = 2 * 1024 * 1024;
const EVIDENCE_LIMIT = 4;

export function stackSourceUrl(value) {
  try {
    const url = new URL(value);
    if (!['http:', 'https:'].includes(url.protocol)) return '[source unavailable]';
    const pathname = decodeURIComponent(url.pathname)
      .replace(/(\/analytics\.js\/v1\/)[^/]+/g, '$1[REDACTED]');
    return redactSensitiveText(`${url.origin}${pathname}`).replace(/[\x00-\x20\x7f]/g, ' ').slice(0, 500);
  } catch {
    return '[source unavailable]';
  }
}

export function recordStackSource(context, content, url, kind = 'JS', observed = false) {
  if (!context) return;
  context.stackSources ||= [];
  if (context.stackSources.length >= SOURCE_LIMIT) return;
  context.stackSources.push({
    content: String(content || '').slice(0, CHARACTER_LIMIT),
    url,
    kind,
    observed,
  });
}

export function stackSourceLocation(source, offset = 0) {
  const content = String(source.content || '').slice(0, CHARACTER_LIMIT);
  const index = Math.max(0, Math.min(offset, content.length));
  const prefix = content.slice(0, index);
  const line = 1 + (prefix.match(/\n/g) || []).length;
  const column = index - prefix.lastIndexOf('\n');
  const hash = createHash('sha256').update(content).digest('hex').slice(0, 12);
  return `${source.kind || 'JS'} ${stackSourceUrl(source.url)}:${line}:${column} (source ${hash})`;
}

function providerForScript(value, baseUrl) {
  try {
    const url = new URL(value, baseUrl);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return null;
    const host = url.hostname.toLowerCase();
    const pathname = url.pathname;
    if (['www.google-analytics.com', 'ssl.google-analytics.com', 'google-analytics.com'].includes(host)
        && /^\/(?:analytics|ga)\.js$/.test(pathname)) return 'Google Analytics';
    if (host === 'www.googletagmanager.com') {
      const id = url.searchParams.get('id') || '';
      if (pathname === '/gtag/js' && /^(?:G-[A-Z0-9]+|UA-\d+-\d+)$/.test(id)) return 'Google Analytics';
      if (pathname === '/gtm.js' && /^GTM-[A-Z0-9]+$/.test(id)) return 'Google Tag Manager';
    }
    if (host === 'cdn.segment.com' && /^\/analytics\.js\/v1\/[^/]+\/analytics(?:\.min)?\.js$/.test(pathname)) return 'Segment';
    if (host === 'client.crisp.chat' && pathname === '/l.js') return 'Crisp';
  } catch {}
  return null;
}

function attributes(source) {
  const result = new Map();
  const pattern = /([^\s=/>]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
  for (const match of source.matchAll(pattern)) {
    const name = match[1].toLowerCase();
    if (!result.has(name)) result.set(name, match[2] ?? match[3] ?? match[4] ?? '');
  }
  return result;
}

function decodeAttribute(value) {
  return value.replace(/&(?:amp|quot|apos|#(\d+)|#x([a-f\d]+));/gi, (match, decimal, hex) => {
    if (decimal || hex) {
      const code = parseInt(decimal || hex, hex ? 16 : 10);
      return code > 0 && code <= 0x10ffff ? String.fromCodePoint(code) : '';
    }
    return { '&amp;': '&', '&quot;': '"', '&apos;': "'" }[match.toLowerCase()] || match;
  });
}

export function detectAnalyticsStack({ html = '', baseUrl, sources = [] } = {}) {
  const detected = new Map();
  const add = (provider, evidence) => {
    const entries = detected.get(provider) || [];
    if (entries.length < EVIDENCE_LIMIT && !entries.includes(evidence)) entries.push(evidence);
    detected.set(provider, entries);
  };
  for (const source of sources.slice(0, SOURCE_LIMIT)) {
    if (source.kind !== 'JS' || source.observed !== true) continue;
    const provider = providerForScript(source.url, baseUrl);
    if (provider) add(provider, `${stackSourceLocation(source)}: provider script response observed; tracking activity not verified`);
  }

  const document = String(html).slice(0, CHARACTER_LIMIT);
  const masked = document.replace(/<!--[\s\S]*?(?:-->|$)|<(template|noscript)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, value => value.replace(/[^\n]/g, ' '));
  const scripts = /<script\b((?:[^>"']|"[^"]*"|'[^']*')*)>([\s\S]*?)(?:<\/script\s*>|$)/gi;
  let count = 0;
  for (const match of masked.matchAll(scripts)) {
    if (++count > SOURCE_LIMIT) break;
    const attrs = attributes(match[1]);
    const type = (attrs.get('type') || '').trim().toLowerCase();
    if (type && !['module', 'text/javascript', 'application/javascript', 'text/ecmascript', 'application/ecmascript'].includes(type)) continue;
    const src = decodeAttribute(attrs.get('src') || '');
    const provider = providerForScript(src, baseUrl);
    if (!provider || detected.has(provider)) continue;
    add(provider, `${stackSourceLocation({ content: document, url: baseUrl, kind: 'HTML' }, match.index)}: provider script declared; execution not verified`);
  }
  return detected;
}
