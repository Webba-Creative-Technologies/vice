const USER_INPUT = /\b(?:req|request)\s*(?:\?\.)?\s*(?:\.\s*)?(?:body|query|params|headers|cookies)\b|\b(?:searchParams|urlParams)\s*\.\s*get\s*\(|\b(?:window\.)?location\.(?:search|hash)\b|\bprocess\.argv\b/i;

const SANITIZERS = {
  html: /\b(?:DOMPurify\.sanitize|sanitizeHtml|escapeHtml|xssFilters?\.|htmlEncode)\s*\(/i,
  redirect: /\b(?:validateRedirect|safeRedirect|sanitizeRedirect|isAllowedUrl|allowlisted?Url)\s*\(/i,
};

function staticStringAfterSink(source, kind) {
  const marker = kind === 'html'
    ? /(?:__html\s*:|\.innerHTML\s*=)\s*/i
    : /(?:eval|Function)\s*\(\s*/i;
  const match = marker.exec(source);
  if (!match) return false;
  const value = source.slice(match.index + match[0].length).trimStart();
  if (!/^['"`]/.test(value)) return false;
  if (value[0] === '`') {
    const end = value.indexOf('`', 1);
    return end > 0 && !value.slice(1, end).includes('${');
  }
  return value.indexOf(value[0], 1) > 0;
}

export function containsDirectUserInput(source) {
  return USER_INPUT.test(String(source || ''));
}

export function classifyCodeSink(kind, source) {
  const evidence = String(source || '');
  const tainted = containsDirectUserInput(evidence);

  if (SANITIZERS[kind]?.test(evidence)) return null;
  if (kind === 'html' && staticStringAfterSink(evidence, kind)) return null;

  if (kind === 'sql') {
    return tainted
      ? { severity: 'CRITICAL', confidence: 'high', classification: 'probable', title: 'Request data interpolated into SQL' }
      : { severity: 'MEDIUM', confidence: 'low', classification: 'heuristic', title: 'Potential dynamic SQL construction' };
  }

  if (kind === 'html') {
    return tainted
      ? { severity: 'HIGH', confidence: 'high', classification: 'probable', title: 'Request data assigned to a raw HTML sink' }
      : { severity: 'LOW', confidence: 'low', classification: 'heuristic', title: 'Potential dynamic raw HTML sink' };
  }

  if (kind === 'eval') {
    if (tainted) return { severity: 'CRITICAL', confidence: 'high', classification: 'probable', title: 'Request data passed to dynamic code execution' };
    if (staticStringAfterSink(evidence, kind)) {
      return { severity: 'LOW', confidence: 'high', classification: 'hardening', title: 'Static dynamic-code execution usage' };
    }
    return { severity: 'MEDIUM', confidence: 'low', classification: 'heuristic', title: 'Potential dynamic code execution sink' };
  }

  if (kind === 'command') {
    return tainted
      ? { severity: 'CRITICAL', confidence: 'high', classification: 'probable', title: 'Request data interpolated into a process command' }
      : { severity: 'MEDIUM', confidence: 'low', classification: 'heuristic', title: 'Potential dynamic process command' };
  }

  if (kind === 'redirect') {
    if (!tainted) return null;
    return { severity: 'HIGH', confidence: 'high', classification: 'probable', title: 'Request data used directly as a redirect target' };
  }

  if (kind === 'weak-hash') {
    const securitySensitive = /password|passwd|credential|secret|token|signature|auth|session/i.test(evidence);
    return securitySensitive
      ? { severity: 'MEDIUM', confidence: 'medium', classification: 'probable', title: 'Legacy hash used in a security-sensitive context' }
      : { severity: 'LOW', confidence: 'high', classification: 'hardening', title: 'Legacy hash algorithm usage' };
  }

  return null;
}
