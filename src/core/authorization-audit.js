import { createHash } from 'node:crypto';
import { classifyPublicJson } from './detectors/public-json.js';
import { surfaceUrl } from './surfaces.js';

function digest(value) { return createHash('sha256').update(JSON.stringify(value)).digest('hex'); }

export async function auditObjectAuthorization({ inventory, baseUrl, profiles = [], fetch, finding, outcome }) {
  if (profiles.length < 2) return;
  const [owner, other] = profiles;
  if (!owner?.headers || !other?.headers || !owner.userId || !other.userId || owner.userId === other.userId) return;
  const targets = [...(inventory?.requests.values() || [])].filter(request => request.method === 'GET' && /json/i.test(request.contentType)).slice(0, 8);
  for (const target of targets) {
    const url = surfaceUrl(target.url, baseUrl);
    if (!url) continue;
    const read = async profile => {
      const response = await fetch(url.href, { headers: profile.headers, redirect: 'error', cache: 'no-store' });
      if (!response) return { unknown: true };
      if (response.status !== 200) return { denied: response.status === 401 || response.status === 403 };
      try { return { data: await response.json() }; } catch { return { unknown: true }; }
    };
    const original = await read(owner);
    if (original.unknown) { outcome?.('unknown'); continue; }
    const rows = Array.isArray(original.data) ? original.data : [original.data];
    const privateRows = rows.filter(row => row && typeof row === 'object'
      && [row.owner_id, row.user_id, row.ownerId, row.userId].includes(owner.userId)
      && classifyPublicJson(row).severity !== 'INFO');
    if (!privateRows.length) continue;
    const foreign = await read(other);
    if (foreign.unknown) { outcome?.('unknown'); continue; }
    const foreignRows = Array.isArray(foreign.data) ? foreign.data : [foreign.data];
    const overlap = privateRows.some(row => foreignRows.some(otherRow => otherRow && digest(row) === digest(otherRow)));
    if (overlap) finding('ELEVEE', 'Authorization', 'Another identity can read an owner-associated sensitive object',
      `Route: ${url.pathname}. Two distinct configured identities returned the same sensitive object associated with the first identity. Sharing intent must be checked. Values omitted.`,
      'Enforce object authorization and verify whether cross-user sharing is intended.',
      { rule_id: 'vice/auth/cross-user-read', classification: 'probable', confidence: 'high' });
    outcome?.(overlap ? 'fail' : foreign.denied || foreign.data ? 'pass' : 'unknown');
  }
}
