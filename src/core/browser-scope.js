const LOCAL_PROTOCOLS = new Set(['about:', 'blob:', 'data:']);
const PASSIVE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE']);

export async function installScopedRequestInterception(page, options = {}) {
  const scope = options.scope;
  if (!scope) return;

  const authHeaders = options.authHeaders || {};
  const signal = options.signal || null;
  const metrics = options.metrics || { allowed: 0, blocked: 0, auth_injected: 0 };
  await page.setRequestInterception(true);

  page.on('request', async request => {
    try {
      if (signal?.aborted) {
        metrics.blocked++;
        await request.abort('aborted');
        return;
      }

      const url = new URL(request.url());
      const method = String(request.method?.() || 'GET').toUpperCase();
      if (!PASSIVE_METHODS.has(method)) {
        metrics.blocked++;
        metrics.mutations_blocked = (metrics.mutations_blocked || 0) + 1;
        await request.abort('blockedbyclient');
        return;
      }
      if (LOCAL_PROTOCOLS.has(url.protocol)) {
        metrics.allowed++;
        await request.continue();
        return;
      }

      if (scope.isHostAllowed(url.hostname)) {
        await scope.assertUrl(url, { reusePinned: true });
      } else {
        await scope.authorizeDiscoveredUrl(url, { reusePinned: true });
      }
      const headers = { ...request.headers() };
      if (scope.isPrimaryOrigin(url) && Object.keys(authHeaders).length > 0) {
        Object.assign(headers, authHeaders);
        metrics.auth_injected++;
      }
      metrics.allowed++;
      await request.continue({ headers });
    } catch {
      metrics.blocked++;
      try { await request.abort('blockedbyclient'); } catch {}
    }
  });
}
