import { classifySupabaseJwt } from '../utils/patterns.js';

export function supabaseHeaders(key, userToken = null) {
  if (!key) return {};
  const token = userToken || (classifySupabaseJwt(key) === 'anon' ? key : null);
  return { apikey: key, ...(token ? { Authorization: `Bearer ${token}` } : {}) };
}

export function discoverSupabase(sources, provided = null) {
  if (provided?.url && provided?.key) return { url: provided.url, key: provided.key };
  const projects = new Map();
  const allKeys = new Set();
  for (const source of sources || []) {
    const text = String(source || '');
    const urls = [...new Set(text.match(/https?:\/\/[a-z0-9-]+\.supabase\.co\b/gi) || [])];
    const keys = [...new Set(text.match(/sb_publishable_[A-Za-z0-9_-]{16,}|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g) || [])]
      .filter(key => key.startsWith('sb_publishable_') || classifySupabaseJwt(key) === 'anon');
    for (const key of keys) allKeys.add(key);
    for (const url of urls) {
      if (!projects.has(url)) projects.set(url, new Set());
      for (const key of keys) {
        let ref = null;
        try { ref = JSON.parse(Buffer.from(key.split('.')[1], 'base64url')).ref; } catch {}
        if (ref ? new URL(url).hostname === `${ref}.supabase.co` : urls.length === 1) projects.get(url).add(key);
      }
    }
  }
  const url = provided?.url || (projects.size === 1 ? projects.keys().next().value : null);
  const keys = projects.get(url) || new Set();
  if (keys.size === 0 && projects.size === 1 && allKeys.size === 1) {
    const candidate = [...allKeys][0];
    let ref = null;
    try { ref = JSON.parse(Buffer.from(candidate.split('.')[1], 'base64url')).ref; } catch {}
    if (!ref || new URL(url).hostname === `${ref}.supabase.co`) keys.add(candidate);
  }
  return { url, key: provided?.key || (keys.size === 1 ? [...keys][0] : null) };
}
