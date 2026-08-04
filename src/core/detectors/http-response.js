function mediaType(value) {
  return String(value || '').split(';', 1)[0].trim().toLowerCase();
}

function normalizedTokens(value) {
  const normalized = String(value || '')
    .slice(0, 128 * 1024)
    .toLowerCase()
    .replace(/https?:\/\/[^\s"'<>]+/g, ' url ')
    .replace(/\b[0-9a-f]{8}-[0-9a-f-]{27,}\b/g, ' uuid ')
    .replace(/\b\d{4}-\d{2}-\d{2}t\d{2}:\d{2}:\d{2}(?:\.\d+)?z\b/g, ' timestamp ')
    .replace(/\b[0-9a-f]{8,}\b/g, ' hash ')
    .replace(/\b\d{5,}\b/g, ' number ')
    .replace(/[^a-z0-9_/-]+/g, ' ')
    .trim();

  return normalized ? normalized.split(/\s+/).slice(0, 4000) : [];
}

function tokenSimilarity(left, right) {
  const leftSet = new Set(normalizedTokens(left));
  const rightSet = new Set(normalizedTokens(right));
  if (leftSet.size === 0 || rightSet.size === 0) return 0;

  let shared = 0;
  for (const token of leftSet) if (rightSet.has(token)) shared++;
  return (2 * shared) / (leftSet.size + rightSet.size);
}

export function responseSnapshot(status, contentType, body) {
  return {
    status: Number(status) || 0,
    mediaType: mediaType(contentType),
    body: String(body || ''),
  };
}

export function isLikelyCatchAll(candidate, references = []) {
  if (!candidate || candidate.status < 200 || candidate.status >= 300 || candidate.body.length < 40) return false;

  return references.filter(Boolean).some((reference) => {
    if (reference.status < 200 || reference.status >= 300) return false;
    if (candidate.mediaType && reference.mediaType && candidate.mediaType !== reference.mediaType) return false;

    const left = candidate.body.trim();
    const right = reference.body.trim();
    if (left === right) return true;
    if (Math.min(left.length, right.length) < 200) return false;

    const lengthRatio = Math.min(left.length, right.length) / Math.max(left.length, right.length);
    return lengthRatio >= 0.85 && tokenSimilarity(left, right) >= 0.94;
  });
}
