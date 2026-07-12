import { classifyPublicJson } from './public-json.js';

const AUTH_DENIAL = /\b(?:unauthori[sz]ed|forbidden|authentication\s+required|not\s+authori[sz]ed|invalid\s+(?:auth|token|jwt)|permission\s+denied|access\s+denied|row.level.security|rls)\b/i;
const PROTOCOL = /(?:"event"\s*:\s*"(?:phx_(?:reply|join|close)|system|presence_)|"type"\s*:\s*"(?:connection_ack|ka|ping|pong)"|^\d+\{)/i;
const CREDENTIAL_VALUE = /(?:eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}|\$2[aby]?\$\d{2}\$[./A-Za-z0-9]{53}|\$argon2(?:id|i|d)\$[^"\s]+)/;

function parseMessage(message) {
  const text = String(message || '').trim();
  if (!text || text === '[binary]') return null;
  const candidates = [text];
  const firstJson = text.search(/[\[{]/);
  if (firstJson > 0) candidates.push(text.slice(firstJson));
  for (const candidate of candidates) {
    try { return JSON.parse(candidate); } catch {}
  }
  return null;
}

export function redactWebSocketUrl(value) {
  try {
    const url = new URL(value);
    for (const key of [...url.searchParams.keys()]) {
      if (/^(?:api_?key|apikey|access_?token|auth|authorization|jwt|token)$/i.test(key)) url.searchParams.set(key, '[redacted]');
    }
    return url.toString();
  } catch {
    return String(value || '').replace(/([?&](?:api_?key|apikey|access_?token|auth|authorization|jwt|token)=)[^&\s]+/gi, '$1[redacted]');
  }
}

export function classifyWebSocketMessages(messages) {
  const samples = Array.isArray(messages) ? messages.slice(0, 10) : [];
  if (samples.length === 0) {
    return { state: 'no-messages', severity: 'INFO', confidence: 'high', classification: 'confirmed', paths: [] };
  }

  const text = samples.map(message => String(message || '').slice(0, 2000)).join('\n');
  const parsed = samples.map(parseMessage).filter(value => value !== null);

  if (CREDENTIAL_VALUE.test(text)) {
    return { state: 'credentials', severity: 'CRITIQUE', confidence: 'high', classification: 'confirmed', paths: [] };
  }
  for (const payload of parsed) {
    const exposure = classifyPublicJson(payload);
    if (exposure.kind === 'credentials' || exposure.kind === 'personal-data') {
      return { state: exposure.kind, severity: exposure.severity, confidence: 'high', classification: 'confirmed', paths: exposure.paths };
    }
  }
  if (AUTH_DENIAL.test(text)) {
    return { state: 'auth-rejected', severity: 'INFO', confidence: 'high', classification: 'confirmed', paths: [] };
  }
  if (PROTOCOL.test(text)) {
    return { state: 'protocol-only', severity: 'INFO', confidence: 'high', classification: 'confirmed', paths: [] };
  }
  if (samples.every(message => message === '[binary]')) {
    return { state: 'binary-unclassified', severity: 'INFO', confidence: 'low', classification: 'heuristic', paths: [] };
  }
  return { state: 'application-data-unclassified', severity: 'INFO', confidence: 'medium', classification: 'probable', paths: [] };
}
