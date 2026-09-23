import { randomUUID } from 'node:crypto';

import { bodyFingerprint } from './evidence.js';

const COMMON_PATHS = Object.freeze([
  '/api/chat',
  '/api/ai',
  '/api/assistant',
  '/api/ask',
  '/api/rag',
  '/api/query',
  '/api/agent',
  '/api/v1/chat',
  '/v1/chat/completions',
  '/v1/responses',
]);
const OPENAPI_PATHS = Object.freeze([
  '/openapi.json',
  '/api/openapi.json',
]);
const AI_PATH_HINT = /(?:chat|assistant|ai|ask|rag|query|agent|completion|response|message)/i;
const PATH_PATTERN = /["'`](\/(?:api|v1)(?:\/[a-zA-Z0-9._~-]+){1,6})["'`]/g;
const SCRIPT_PATTERN = /<script\b[^>]*\bsrc=["']([^"']+)["'][^>]*>/gi;

function clampInteger(value, minimum, maximum, fallback) {
  const number = Number(value);
  if (!Number.isInteger(number)) return fallback;
  return Math.min(maximum, Math.max(minimum, number));
}

function statusFamily(status) {
  return status > 0 ? `${Math.floor(status / 100)}xx` : 'network-error';
}

function addCandidate(candidates, value, origin, source) {
  try {
    const url = new URL(value, origin);
    url.hash = '';
    url.search = '';
    if (url.origin !== origin || url.username || url.password) return;
    const key = url.toString();
    if (!candidates.has(key)) candidates.set(key, { url: key, source });
  } catch {}
}

function extractPaths(source, candidates, origin, sourceName) {
  for (const match of String(source || '').matchAll(PATH_PATTERN)) {
    if (AI_PATH_HINT.test(match[1])) addCandidate(candidates, match[1], origin, sourceName);
  }
}

function extractScripts(source, origin) {
  const scripts = [];
  for (const match of String(source || '').matchAll(SCRIPT_PATTERN)) {
    try {
      const url = new URL(match[1], origin);
      if (url.origin === origin && !scripts.includes(url.toString())) scripts.push(url.toString());
    } catch {}
    if (scripts.length >= 3) break;
  }
  return scripts;
}

function findMarkerPath(value, marker, path = []) {
  if (typeof value === 'string') return value.includes(marker) ? path.join('.') : null;
  if (!value || typeof value !== 'object') return null;
  for (const [key, child] of Object.entries(value)) {
    const result = findMarkerPath(child, marker, [...path, key]);
    if (result) return result;
  }
  return null;
}

function parseDiscoveryResponse(raw, contentType, marker) {
  if (contentType.includes('text/event-stream')) {
    for (const line of raw.split(/\r?\n/)) {
      if (!line.startsWith('data:')) continue;
      const value = line.slice(5).trim();
      if (!value || value === '[DONE]') continue;
      try {
        const path = findMarkerPath(JSON.parse(value), marker);
        if (path) return { responseField: path, streaming: 'sse' };
      } catch {}
    }
    return null;
  }
  try {
    const path = findMarkerPath(JSON.parse(raw), marker);
    return path ? { responseField: path, streaming: 'json' } : null;
  } catch {
    return raw.includes(marker) ? { responseField: 'answer', streaming: 'json' } : null;
  }
}

function applyAuth(headers, input) {
  const profile = input?.authProfiles?.a;
  const secret = profile?.secret ?? profile?.value;
  if (!profile || typeof secret !== 'string' || !secret || /[\r\n]/.test(secret)) return;
  if (profile.type === 'bearer') headers.set('authorization', `Bearer ${secret}`);
  else if (typeof profile.headerName === 'string' && profile.headerName) headers.set(profile.headerName, secret);
}

function requestVariants(path, prompt) {
  const openAiFirst = /(?:chat\/completions|responses)/i.test(path);
  const variants = [
    { id: 'message', adapter: 'generic-json', messageField: 'message', body: { message: prompt } },
    { id: 'input-message', adapter: 'generic-json', messageField: 'input.message', body: { input: { message: prompt } } },
    { id: 'prompt', adapter: 'generic-json', messageField: 'prompt', body: { prompt } },
    { id: 'query', adapter: 'generic-json', messageField: 'query', body: { query: prompt } },
    { id: 'openai', adapter: 'openai-compatible', messageField: 'message', body: { messages: [{ role: 'user', content: prompt }] } },
  ];
  if (openAiFirst) variants.unshift(variants.pop());
  return variants;
}

export async function discoverAiRagTarget(baseUrl, input, options = {}) {
  if (typeof options.fetch !== 'function') throw new Error('ai_rag_fetch_required');
  const target = new URL(input?.endpoint || baseUrl);
  const maxRequests = clampInteger(input?.discovery?.maxRequests, 4, 12, 10);
  const candidates = new Map();
  for (const url of (options.observedEndpoints || []).slice(0, 40)) {
    if (AI_PATH_HINT.test(new URL(url).pathname)) addCandidate(candidates, url, target.origin, 'observed-request');
  }
  for (const source of (options.observedSources || []).slice(0, 30)) extractPaths(source, candidates, target.origin, 'observed-source');
  const probes = [];
  let requests = 0;
  let inferred = null;

  const request = async (url, probe, requestOptions = {}) => {
    if (requests >= maxRequests) return null;
    requests++;
    const headers = new Headers(requestOptions.headers || {});
    applyAuth(headers, input);
    const response = await options.fetch(url, {
      ...requestOptions,
      headers,
      probe: 'ai-rag',
      redirect: 'follow',
      timeoutMs: 7000,
      maxResponseBytes: 256 * 1024,
    });
    const status = response?.status ?? 0;
    const raw = response ? await response.text() : '';
    probes.push({
      probe,
      profile: 'discovery',
      status_family: statusFamily(status),
      response_hash: bodyFingerprint(raw),
      response_length: raw.length,
    });
    return { status, raw, contentType: response?.headers.get('content-type') || '' };
  };

  options.onPhase?.('discovering');
  if (target.pathname !== '/') addCandidate(candidates, target, target.origin, 'provided-path');
  const landing = await request(target, 'discovery-landing', {
    method: 'GET',
    headers: { accept: 'text/html, application/json' },
  });
  if (landing) {
    extractPaths(landing.raw, candidates, target.origin, 'landing');
    for (const script of extractScripts(landing.raw, target.origin)) {
      const bundle = await request(script, 'discovery-script', {
        method: 'GET',
        headers: { accept: 'text/javascript, application/javascript' },
      });
      if (bundle) extractPaths(bundle.raw, candidates, target.origin, 'script');
    }
  }

  for (const path of OPENAPI_PATHS) {
    const specification = await request(new URL(path, target.origin), 'discovery-openapi', {
      method: 'GET',
      headers: { accept: 'application/json' },
    });
    if (specification?.status === 200) extractPaths(specification.raw, candidates, target.origin, 'openapi');
  }
  for (const path of COMMON_PATHS) addCandidate(candidates, path, target.origin, 'common');

  const marker = `VICE_DISCOVERY_${randomUUID().replaceAll('-', '')}`;
  const prompt = `Reply with exactly ${marker}`;
  for (const candidate of candidates.values()) {
    for (const variant of requestVariants(new URL(candidate.url).pathname, prompt)) {
      const result = await request(candidate.url, `discovery-${variant.id}`, {
        method: 'POST',
        headers: {
          accept: 'application/json, text/event-stream',
          'content-type': 'application/json',
        },
        body: JSON.stringify(variant.body),
      });
      if (!result) break;
      const parsed = result.status >= 200 && result.status < 300
        ? parseDiscoveryResponse(result.raw, result.contentType, marker)
        : null;
      if (parsed) {
        return {
          config: {
            ...input,
            endpoint: candidate.url,
            adapter: variant.adapter,
            messageField: variant.messageField,
            responseField: parsed.responseField,
            streamResponseField: parsed.responseField,
            streaming: parsed.streaming,
            requestTemplate: {},
          },
          requests,
          probes,
          limitations: [],
          summary: { status: 'confirmed', source: candidate.source, candidatesTested: candidates.size },
        };
      }
      if (!inferred && candidate.source !== 'common' && [400, 401, 403, 405, 415, 422].includes(result.status)) {
        inferred = { candidate, variant };
      }
    }
    if (requests >= maxRequests) break;
  }

  if (inferred) {
    return {
      config: {
        ...input,
        endpoint: inferred.candidate.url,
        adapter: inferred.variant.adapter,
        messageField: inferred.variant.messageField,
        responseField: inferred.variant.adapter === 'openai-compatible' ? 'choices.0.message.content' : 'answer',
        streamResponseField: inferred.variant.adapter === 'openai-compatible' ? 'choices.0.delta.content' : 'answer',
        streaming: 'json',
        requestTemplate: {},
      },
      requests,
      probes,
      limitations: ['ai_rag_endpoint_inferred_without_response'],
      summary: { status: 'inferred', source: inferred.candidate.source, candidatesTested: candidates.size },
    };
  }

  return {
    config: null,
    requests,
    probes,
    limitations: ['ai_rag_endpoint_not_discovered'],
    summary: { status: 'not-found', source: null, candidatesTested: candidates.size },
  };
}
