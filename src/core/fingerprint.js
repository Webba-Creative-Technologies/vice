// ──────────────────────────────────────────────
// VICE — Finding fingerprint utilities
// Stable identifiers for findings, used by baselines and rule-grouping.
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import crypto from 'crypto';

// Strip volatile parts from a title so the same finding gets the same key
// across runs even when line numbers shift or the file path changes.
export function normalizeTitle(title) {
  if (!title) return '';
  return String(title)
    .replace(/\s+in\s+[^\s]+(?::\d+)?$/i, '')   // "... in path/to/file.js:42"
    .replace(/:\d+\b/g, '')                      // bare ":42"
    .replace(/\s+at line \d+/gi, '')             // "at line 42"
    .replace(/\(line \d+\)/gi, '')               // "(line 42)"
    .replace(/\s+/g, ' ')
    .trim();
}

// Group key used to cap penalty per rule (module + rule shape, file-agnostic).
export function groupKey(finding) {
  return `${finding.module || ''}|${normalizeTitle(finding.title || '')}`;
}

// Stable fingerprint for baseline matching. Keeps the file location so that
// the same rule firing on different files yields different fingerprints.
export function fingerprintFinding(finding) {
  const file = (finding.location && finding.location.file) || '';
  const titleNorm = normalizeTitle(finding.title || '');
  const module = finding.module || '';
  const detailFirstLine = (finding.detail || '').split('\n')[0].substring(0, 200);
  const key = `${module}|${titleNorm}|${file}|${detailFirstLine}`;
  return crypto.createHash('sha256').update(key).digest('hex').slice(0, 16);
}
