// ──────────────────────────────────────────────
// VICE - Finding fingerprint utilities
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
  if (finding.rule_id || finding.ruleId) return finding.rule_id || finding.ruleId;
  return `${finding.module || ''}|${normalizeTitle(finding.title || '')}`;
}

function normalizeUrlForEvidence(value) {
  try {
    const url = new URL(value);
    return `${url.protocol}//${url.host}${url.pathname}`;
  } catch {
    return value;
  }
}

export function normalizeEvidenceKey(detail) {
  return String(detail || '')
    .split('\n')[0]
    .substring(0, 400)
    .replace(/https?:\/\/[^\s)\]}>,]+/gi, normalizeUrlForEvidence)
    .replace(/\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b/gi, 'uuid')
    .replace(/\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\b/gi, 'timestamp')
    .replace(/\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/gi, 'email')
    .replace(/\b(?:status|http)\s+\d{3}\b/gi, 'status number')
    .replace(/\b\d+\s+(rows?|bytes?|findings?|sources?|paths?|files?)\b/gi, 'number $1')
    .replace(/\s+/g, ' ')
    .trim();
}

// Stable fingerprint for baseline matching. Keeps the file location so that
// the same rule firing on different files yields different fingerprints.
export function fingerprintFinding(finding) {
  const file = (finding.location && finding.location.file) || '';
  const titleNorm = normalizeTitle(finding.title || '');
  const module = finding.rule_id || finding.ruleId || finding.module || '';
  const evidenceKey = normalizeEvidenceKey(finding.detail);
  const key = `${module}|${titleNorm}|${file}|${evidenceKey}`;
  return crypto.createHash('sha256').update(key).digest('hex').slice(0, 16);
}
