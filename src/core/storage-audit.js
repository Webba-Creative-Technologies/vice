import { classifyPublicJson } from './detectors/public-json.js';
import { analyzeBundleExposure } from './detectors/bundle-secrets.js';

export async function inspectPublicObject(response) {
  if (!response || response.status !== 200) return null;
  const type = response.headers.get('content-type') || '';
  if (!/json|text|xml|javascript|octet-stream/.test(type)) return null;
  const text = (await response.text()).slice(0, 65536);
  try {
    const exposure = classifyPublicJson(JSON.parse(text));
    if (exposure.kind !== 'public-json') return { ...exposure, evidence: `Sensitive field paths: ${exposure.paths.join(', ')}` };
  } catch {}
  const secrets = analyzeBundleExposure([text]);
  const confirmed = secrets.observations.filter(item => item.classification === 'confirmed-secret');
  if (confirmed.length) return { severity: 'CRITIQUE', kind: 'credentials', evidence: `Credential types: ${confirmed.map(item => item.kind).join(', ')}` };
  return null;
}

export function objectUrl(projectUrl, bucket, name) {
  const path = String(name).split('/');
  if (path.some(part => !part || part === '.' || part === '..')) return null;
  return `${projectUrl}/storage/v1/object/public/${encodeURIComponent(bucket)}/${path.map(encodeURIComponent).join('/')}`;
}
