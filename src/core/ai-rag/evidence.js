import { createHash } from 'node:crypto';

import { redactSensitiveText } from '../redaction.js';

export function bodyFingerprint(value) {
  return createHash('sha256').update(String(value || '')).digest('hex').slice(0, 16);
}

export function containsMarker(value, marker) {
  return typeof marker === 'string'
    && marker.length >= 8
    && String(value || '').includes(marker);
}

export function sensitiveMatchCount(value) {
  const source = String(value || '');
  const redacted = redactSensitiveText(source);
  if (source === redacted) return 0;
  return (redacted.match(/\[REDACTED:[^\]]+\]/g) || []).length;
}

export function boundedEvidence(result, extra = {}) {
  return {
    probe: result.probe,
    profile: result.profile,
    status_family: result.statusFamily,
    response_hash: result.bodyHash,
    response_length: result.textLength,
    ...extra,
  };
}
