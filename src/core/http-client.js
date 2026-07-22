import { AsyncLocalStorage } from 'node:async_hooks';
import { ScopeError } from './scope.js';

const clientStorage = new AsyncLocalStorage();
const PASSIVE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS', 'TRACE']);

function isApprovedPost(url, options) {
  if (String(options.method || 'GET').toUpperCase() !== 'POST') return false;
  if (options.probe === 'ai-rag') {
    return typeof options.body === 'string' && options.body.length > 0 && options.body.length <= 64 * 1024;
  }
  if (options.readOnly === 'storage-list') {
    try { return new URL(String(url)).pathname.includes('/storage/v1/object/list/'); } catch { return false; }
  }
  if (options.readOnly === 'graphql-query') {
    const body = typeof options.body === 'string' ? options.body : '';
    return body.length > 0 && !/\bmutation\b/i.test(body);
  }
  return false;
}

function responseCacheKey(url, options) {
  const method = String(options.method || 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD') return null;
  if (options.cache === 'no-store') return null;

  const headers = [...new Headers(options.headers || {}).entries()]
    .sort(([left], [right]) => left.localeCompare(right));
  return JSON.stringify([method, String(url), headers]);
}

function concatenate(chunks, total) {
  const body = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    body.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return body;
}

async function readBoundedBody(response, maxBytes) {
  if (!response.body) return { body: new Uint8Array(), truncated: false };

  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  let truncated = false;

  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    const remaining = maxBytes - total;
    if (remaining <= 0) {
      truncated = true;
      await reader.cancel();
      break;
    }
    if (value.byteLength > remaining) {
      chunks.push(value.slice(0, remaining));
      total += remaining;
      truncated = true;
      await reader.cancel();
      break;
    }
    chunks.push(value);
    total += value.byteLength;
  }

  return { body: concatenate(chunks, total), truncated };
}

function materialize(snapshot) {
  const noBody = snapshot.method === 'HEAD' || [204, 205, 304].includes(snapshot.status);
  const headers = new Headers(snapshot.headers);
  if (snapshot.setCookies.length > 0) {
    headers.delete('set-cookie');
    snapshot.setCookies.forEach((cookie) => headers.append('set-cookie', cookie));
  }
  return new Response(noBody ? null : snapshot.body.slice(), {
    status: snapshot.status,
    statusText: snapshot.statusText,
    headers,
  });
}

function isRedirect(response) {
  return [301, 302, 303, 307, 308].includes(response.status) && response.headers.has('location');
}

function redirectedOptions(options, status, from, to) {
  const next = { ...options, headers: new Headers(options.headers || {}) };
  const method = String(next.method || 'GET').toUpperCase();
  if (status === 303 || ((status === 301 || status === 302) && method === 'POST')) {
    next.method = 'GET';
    delete next.body;
    next.headers.delete('content-length');
    next.headers.delete('content-type');
  }
  if (from.origin !== to.origin) {
    for (const name of ['authorization', 'cookie', 'proxy-authorization', 'apikey', 'x-api-key']) next.headers.delete(name);
  }
  return next;
}

function attachAbortSignals(controller, signals) {
  const listeners = [];
  for (const signal of signals.filter(Boolean)) {
    if (signal.aborted) {
      controller.abort(signal.reason);
      continue;
    }
    const abort = () => controller.abort(signal.reason);
    signal.addEventListener('abort', abort, { once: true });
    listeners.push(() => signal.removeEventListener('abort', abort));
  }
  return () => listeners.forEach(remove => remove());
}

export function createHttpClient(options = {}) {
  const timeoutMs = options.timeoutMs ?? 10000;
  const maxResponseBytes = options.maxResponseBytes ?? 2 * 1024 * 1024;
  const maxCacheEntries = options.maxCacheEntries ?? 256;
  const maxRedirects = options.maxRedirects ?? 5;
  const maxNetworkRequests = options.maxNetworkRequests ?? 2500;
  const maxTotalResponseBytes = options.maxTotalResponseBytes ?? 64 * 1024 * 1024;
  const scope = options.scope || null;
  const clientSignal = options.signal || null;
  const cache = new Map();
  const counters = {
    requests: 0,
    network_requests: 0,
    cache_hits: 0,
    failed_requests: 0,
    bytes_received: 0,
    truncated_responses: 0,
    redirects_followed: 0,
    blocked_requests: 0,
    mutations_blocked: 0,
    aborted_requests: 0,
    budget_exhausted: false,
  };

  async function request(url, requestOptions = {}) {
    counters.requests++;
    const requestMethod = String(requestOptions.method || 'GET').toUpperCase();
    const approvedPost = isApprovedPost(url, requestOptions);
    if (!PASSIVE_METHODS.has(requestMethod) && !approvedPost) {
      counters.blocked_requests++;
      counters.mutations_blocked++;
      return null;
    }
    const key = responseCacheKey(url, requestOptions);

    if (key && cache.has(key)) {
      counters.cache_hits++;
      const cached = await cache.get(key);
      return cached ? materialize(cached) : null;
    }

    const requestPromise = (async () => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), requestOptions.timeoutMs ?? timeoutMs);
      const {
        timeoutMs: ignoredTimeout,
        maxResponseBytes: requestMaxBytes,
        signal: requestSignal,
        readOnly: ignoredReadOnly,
        probe: ignoredProbe,
        ...fetchOptions
      } = requestOptions;
      void ignoredTimeout;
      void ignoredReadOnly;
      void ignoredProbe;
      const detachAbortSignals = attachAbortSignals(controller, [clientSignal, requestSignal]);

      try {
        let currentUrl = new URL(String(url));
        let currentOptions = { ...fetchOptions };
        let response;

        for (let redirectCount = 0; ; redirectCount++) {
          await scope?.assertUrl(currentUrl);
          if (counters.network_requests >= maxNetworkRequests) {
            counters.budget_exhausted = true;
            throw new Error('network_request_budget_exhausted');
          }
          counters.network_requests++;
          response = await fetch(currentUrl, {
            ...currentOptions,
            signal: controller.signal,
            redirect: 'manual',
          });

          if (!isRedirect(response) || currentOptions.redirect === 'manual') break;
          if (currentOptions.redirect === 'error' || redirectCount >= maxRedirects) {
            await response.body?.cancel();
            throw new Error('redirect_limit_exceeded');
          }

          const nextUrl = new URL(response.headers.get('location'), currentUrl);
          await scope?.assertUrl(nextUrl);
          await response.body?.cancel();
          currentOptions = redirectedOptions(currentOptions, response.status, currentUrl, nextUrl);
          currentUrl = nextUrl;
          counters.redirects_followed++;
        }

        const remainingBytes = maxTotalResponseBytes - counters.bytes_received;
        if (remainingBytes <= 0) {
          counters.budget_exhausted = true;
          await response.body?.cancel();
          throw new Error('response_byte_budget_exhausted');
        }
        const configuredLimit = requestMaxBytes ?? maxResponseBytes;
        const limit = Math.min(configuredLimit, remainingBytes);
        const { body, truncated } = await readBoundedBody(response, limit);
        const headers = new Headers(response.headers);
        const setCookies = typeof response.headers.getSetCookie === 'function' ? response.headers.getSetCookie() : [];
        if (truncated) headers.set('x-vice-body-truncated', 'true');
        counters.bytes_received += body.byteLength;
        if (truncated) counters.truncated_responses++;
        if (truncated && limit === remainingBytes && remainingBytes < configuredLimit) {
          counters.budget_exhausted = true;
        }

        return {
          method: String(fetchOptions.method || 'GET').toUpperCase(),
          status: response.status,
          statusText: response.statusText,
          headers,
          setCookies,
          body,
        };
      } catch (error) {
        if (error instanceof ScopeError) counters.blocked_requests++;
        if (controller.signal.aborted) counters.aborted_requests++;
        counters.failed_requests++;
        return null;
      } finally {
        clearTimeout(timer);
        detachAbortSignals();
      }
    })();

    if (key) {
      if (cache.size >= maxCacheEntries) cache.delete(cache.keys().next().value);
      cache.set(key, requestPromise);
    }

    const snapshot = await requestPromise;
    if (key && !snapshot) cache.delete(key);
    return snapshot ? materialize(snapshot) : null;
  }

  return {
    fetch: request,
    metrics() {
      return { ...counters, cached_responses: cache.size };
    },
  };
}

const defaultClient = createHttpClient();

export function withHttpClient(client, fn) {
  return clientStorage.run(client, fn);
}

export function safeFetch(url, options) {
  return (clientStorage.getStore() || defaultClient).fetch(url, options);
}
