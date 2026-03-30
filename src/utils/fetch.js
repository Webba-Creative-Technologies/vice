// ──────────────────────────────────────────────
// VICE — Safe Fetch Utility
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

export async function safeFetch(url, opts = {}) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    const res = await fetch(url, { ...opts, signal: controller.signal, redirect: 'follow' });
    clearTimeout(timeout);
    return res;
  } catch {
    return null;
  }
}
