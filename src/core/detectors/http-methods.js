const REJECTION = /method\s+not\s+allowed|method\s+not\s+supported|unsupported\s+method|invalid\s+method|not\s+implemented/i;
const MUTATION_WORD = /\b(?:created|deleted|removed|updated|modified)\b/i;
const MUTATION_SUCCESS = /(?:\b(?:created|deleted|removed|updated|modified)\b.{0,40}\b(?:success|successfully|complete|affected)\b|\b(?:success|successfully|complete|affected)\b.{0,40}\b(?:created|deleted|removed|updated|modified)\b)/i;
const COUNT_KEYS = /^(?:affected_?rows?|deleted_?count|removed_?count|updated_?count|modified_?count)$/i;
const BOOLEAN_KEYS = /^(?:created|deleted|removed|updated|modified)$/i;
const TEXT_KEYS = /^(?:action|message|operation|result|status)$/i;

function normalizeBody(body) {
  return String(body || '').trim().replace(/\s+/g, ' ').slice(0, 4000);
}

function hasMutationProof(value, depth = 0, visited = { count: 0 }) {
  if (depth > 6 || visited.count >= 500 || value === null || typeof value !== 'object') return false;
  visited.count++;

  for (const [key, child] of Object.entries(value)) {
    if (BOOLEAN_KEYS.test(key) && child === true) return true;
    if (COUNT_KEYS.test(key) && Number.isFinite(child) && child > 0) return true;
    if (TEXT_KEYS.test(key) && typeof child === 'string' && MUTATION_WORD.test(child)) return true;
    if (hasMutationProof(child, depth + 1, visited)) return true;
  }
  return false;
}

export function classifyHttpMethodResponse({ method, status, body = '', referenceStatus = 0, referenceBody = '' }) {
  const verb = String(method || '').toUpperCase();
  if (!verb) return null;
  const response = normalizeBody(body);
  const reference = normalizeBody(referenceBody);

  if (![200, 201, 202, 204].includes(status)) return null;
  if (REJECTION.test(response)) {
    return { state: 'rejected', severity: 'INFO', confidence: 'high', classification: 'confirmed' };
  }
  if (status === referenceStatus && response === reference) {
    return { state: 'same-as-get', severity: 'INFO', confidence: 'high', classification: 'confirmed' };
  }

  let parsed;
  try { parsed = JSON.parse(response); } catch {}
  if ((parsed && hasMutationProof(parsed)) || MUTATION_SUCCESS.test(response)) {
    return { state: 'mutation-confirmed', severity: 'ELEVEE', confidence: 'high', classification: 'confirmed' };
  }

  return { state: 'success-unproven', severity: 'INFO', confidence: 'low', classification: 'heuristic' };
}

export function classifyTraceResponse(status, body, canary) {
  if (status < 200 || status >= 300 || !canary) return null;
  return String(body || '').includes(canary)
    ? { state: 'reflected', severity: 'ELEVEE', confidence: 'high', classification: 'confirmed' }
    : null;
}
