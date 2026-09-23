import { classifyPublicJson } from './detectors/public-json.js';

export async function auditWordpressRoutes(baseUrl, fetch, finding) {
  const origin = new URL(baseUrl).origin;
  const response = await fetch(`${origin}/wp-json/`);
  if (!response || response.status !== 200) return;
  let index;
  try { index = await response.json(); } catch { return; }
  const routes = Object.entries(index?.routes || {}).filter(([path, definition]) =>
    /^\/[a-z0-9_-]+\/v\d+\//i.test(path) && !/[(){}\\]/.test(path)
    && Array.isArray(definition.methods) && definition.methods.includes('GET'));
  routes.sort(([a], [b]) => Number(a.startsWith('/wp/v2/')) - Number(b.startsWith('/wp/v2/')));
  for (const [path] of routes.slice(0, 12)) {
    const result = await fetch(`${origin}/wp-json${path}`);
    if (!result || result.status !== 200) continue;
    let data;
    try { data = await result.json(); } catch { continue; }
    const exposure = classifyPublicJson(data);
    if (exposure.severity === 'INFO') continue;
    finding(exposure.severity, 'WordPress', 'A registered WordPress REST route returns sensitive fields anonymously',
      `Route: ${path}. Sensitive paths: ${exposure.paths.join(', ')}. Values omitted.`,
      'Verify permission_callback and the fields exposed by this WordPress component.',
      { rule_id: `vice/wordpress/rest-${exposure.kind}`, classification: 'probable', confidence: 'medium' });
  }
}
