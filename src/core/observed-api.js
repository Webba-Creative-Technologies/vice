import { classifyPublicJson } from './detectors/public-json.js';

function containsCredentials(value, depth = 0) {
  if (!value || typeof value !== 'object') return false;
  if (depth > 12) return true;
  return Object.entries(value).some(([key, child]) => /token|password|secret|authorization|cookie|api[_-]?key/i.test(key)
    || key === 'query' && typeof child === 'string' && /\b(?:\w*token|password|secret|authorization|cookie|api_key)\s*:/i.test(child)
    || containsCredentials(child, depth + 1));
}

export async function auditObservedQueries(inventory, fetch, finding) {
  const requests = [...(inventory?.requests.values() || [])].filter(request => request.method === 'POST').slice(0, 8);
  for (const request of requests) {
    try { if (containsCredentials(JSON.parse(request.body))) continue; } catch { continue; }
    const response = await fetch(request.url, { method: 'POST', body: request.body, readOnly: 'graphql-query', headers: { 'content-type': 'application/json' } });
    if (!response || response.status !== 200) continue;
    let body;
    try { body = await response.json(); } catch { continue; }
    if (!body?.data) continue;
    const exposure = classifyPublicJson(body.data);
    if (exposure.severity === 'INFO') continue;
    finding(exposure.severity, 'GraphQL', 'Observed application query returns sensitive fields anonymously',
      `Route: ${new URL(request.url).pathname}. Sensitive paths: ${exposure.paths.join(', ')}. Values omitted.`,
      'Enforce authorization in resolvers and expose only intended public fields.',
      { rule_id: `vice/graphql/anonymous-${exposure.kind}`, classification: 'probable', confidence: 'medium' });
  }
}
