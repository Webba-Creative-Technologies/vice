// ──────────────────────────────────────────────
// VICE — Safe Fetch Utility
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

const PRIVATE_IP_RE = /^(localhost|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+|169\.254\.\d+\.\d+|::1|fc[0-9a-f]{2}:|fd[0-9a-f]{2}:)/i;

function isPrivateHost(urlString) {
  try {
    const { hostname } = new URL(urlString);
    return PRIVATE_IP_RE.test(hostname);
  } catch {
    return true;
  }
}

export async function safeFetch(url, opts = {}) {
  if (isPrivateHost(url)) return null;
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 10000);
    const res = await fetch(url, { ...opts, signal: controller.signal, redirect: 'manual' });
    clearTimeout(timeout);

    // Follow redirects only after validating the destination
    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get('location');
      if (!location || isPrivateHost(location)) return null;
      return safeFetch(location, opts);
    }

    return res;
  } catch {
    return null;
  }
}
