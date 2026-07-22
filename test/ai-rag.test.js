import assert from 'node:assert/strict';
import http from 'node:http';
import test from 'node:test';

import { auditAiRag, normalizeAiRagConfig } from '../src/core/ai-rag/audit.js';
import { buildAiRequest, parseAiResponseBody } from '../src/core/ai-rag/adapters.js';
import { runScan } from '../scan.js';

const STRIPE_FIXTURE = ['sk', 'live', '1234567890abcdefghijkl'].join('_');

const FIXTURES = {
  systemPromptCanary: 'VICE_SYSTEM_CANARY_12345678',
  promptInjectionCanary: 'VICE_INJECTION_CANARY_12345678',
  ragCrossTenant: { query: 'Find the private account document.', marker: 'VICE_RAG_TENANT_12345678' },
  ragIndirect: { query: 'Summarize the untrusted document.', marker: 'VICE_RAG_INJECTION_12345678' },
  ragDeleted: { query: 'Find the deleted policy.', marker: 'VICE_RAG_DELETED_12345678' },
  toolFetch: { url: 'https://canary.example/fetch', marker: 'VICE_TOOL_FETCH_12345678' },
  internalUrl: { url: 'http://canary.internal/health', marker: 'VICE_INTERNAL_FETCH_12345678' },
  unauthorizedAction: { prompt: 'Run the protected canary action.', marker: 'VICE_TOOL_ACTION_12345678' },
};

function config(overrides = {}) {
  return {
    endpoint: 'https://app.example.test/api/ai',
    adapter: 'generic-json',
    expectedAccess: 'authenticated',
    messageField: 'input.message',
    responseField: 'answer',
    conversationRequestField: 'conversationId',
    conversationResponseField: 'conversationId',
    authProfiles: {
      a: { type: 'bearer', value: 'fixture-user-a-token' },
      b: { type: 'bearer', value: 'fixture-user-b-token' },
    },
    fixtures: FIXTURES,
    ...overrides,
  };
}

function vulnerableFetch() {
  let sessionMarker = '';
  return async (_url, options) => {
    const probe = new Headers(options.headers).get('x-vice-probe');
    const body = JSON.parse(options.body);
    const prompt = body.input?.message || '';
    const authorization = new Headers(options.headers).get('authorization') || '';
    let answer = 'READY';
    let conversationId = null;

    if (probe === 'api-session-create') {
      sessionMarker = prompt.match(/VICE_SESSION_[A-Za-z0-9]+/)?.[0] || '';
      conversationId = 'conversation-a';
    }
    if (probe === 'api-session-cross-user' && authorization.includes('user-b')) answer = sessionMarker;
    if (probe === 'llm-system-prompt') answer = FIXTURES.systemPromptCanary;
    if (probe === 'llm-prompt-injection') answer = FIXTURES.promptInjectionCanary;
    if (probe === 'llm-sensitive-output') answer = STRIPE_FIXTURE;
    if (probe === 'rag-cross-tenant') answer = FIXTURES.ragCrossTenant.marker;
    if (probe === 'rag-indirect-injection') answer = FIXTURES.ragIndirect.marker;
    if (probe === 'rag-deleted-document') answer = FIXTURES.ragDeleted.marker;
    if (probe === 'tool-url-fetch') answer = FIXTURES.toolFetch.marker;
    if (probe === 'tool-internal-url') answer = FIXTURES.internalUrl.marker;
    if (probe === 'tool-unauthorized-action') answer = FIXTURES.unauthorizedAction.marker;

    return new Response(JSON.stringify({ answer, conversationId }), {
      status: 200,
      headers: probe === 'api-cors'
        ? {
            'content-type': 'application/json',
            'access-control-allow-origin': 'https://vice.invalid',
            'access-control-allow-credentials': 'true',
          }
        : { 'content-type': 'application/json' },
    });
  };
}

function secureFetch() {
  return async (_url, options) => {
    const headers = new Headers(options.headers);
    const probe = headers.get('x-vice-probe');
    const authorization = headers.get('authorization') || '';
    if ((probe === 'api-anonymous' || probe === 'api-invalid-auth') && !authorization.includes('user-a')) {
      return new Response('{"error":"unauthorized"}', { status: 401, headers: { 'content-type': 'application/json' } });
    }
    if (probe === 'api-rate-limit') {
      return new Response('{"error":"limited"}', { status: 429, headers: { 'content-type': 'application/json' } });
    }
    return new Response('{"answer":"SAFE","conversationId":"isolated"}', {
      status: 200,
      headers: { 'content-type': 'application/json' },
    });
  };
}

test('AI/RAG adapters build generic and OpenAI-compatible requests', () => {
  const generic = normalizeAiRagConfig('https://app.example.test', config());
  assert.deepEqual(JSON.parse(buildAiRequest(generic, 'hello', 'conversation')), {
    input: { message: 'hello' },
    conversationId: 'conversation',
  });

  const openai = normalizeAiRagConfig('https://app.example.test', config({
    adapter: 'openai-compatible',
    model: 'fixture-model',
    responseField: 'choices.0.message.content',
  }));
  assert.deepEqual(JSON.parse(buildAiRequest(openai, 'hello')), {
    model: 'fixture-model',
    messages: [{ role: 'user', content: 'hello' }],
  });
});

test('AI/RAG adapter parses SSE without retaining protocol frames', () => {
  const normalized = normalizeAiRagConfig('https://app.example.test', config({
    adapter: 'openai-compatible',
    streaming: 'sse',
    responseField: 'choices.0.message.content',
  }));
  const parsed = parseAiResponseBody([
    'data: {"choices":[{"delta":{"content":"HEL"}}]}',
    'data: {"choices":[{"delta":{"content":"LO"}}]}',
    'data: [DONE]',
  ].join('\n'), 'text/event-stream', normalized);
  assert.equal(parsed.text, 'HELLO');
});

test('AI/RAG audit confirms bounded API, LLM, RAG and tool evidence', async () => {
  const result = await auditAiRag('https://app.example.test', config(), { fetch: vulnerableFetch() });
  const rules = new Set(result.findings.map((finding) => finding.rule_id));

  assert.ok(rules.has('vice/ai-api/anonymous-sensitive-access'));
  assert.ok(rules.has('vice/ai-api/broken-authentication'));
  assert.ok(rules.has('vice/ai-api/object-authorization'));
  assert.ok(rules.has('vice/llm/system-prompt-leakage'));
  assert.ok(rules.has('vice/llm/prompt-injection'));
  assert.ok(rules.has('vice/llm/sensitive-output'));
  assert.ok(rules.has('vice/rag/cross-tenant-retrieval'));
  assert.ok(rules.has('vice/rag/indirect-prompt-injection'));
  assert.ok(rules.has('vice/agent/arbitrary-url-fetch'));
  assert.ok(rules.has('vice/agent/internal-url-access'));
  assert.ok(rules.has('vice/agent/unauthorized-action'));
  assert.equal(result.audit.coverage, 'complete');
  assert.ok(result.audit.requests_sent <= 24);
  assert.equal(JSON.stringify(result).includes(STRIPE_FIXTURE), false);
});

test('AI/RAG audit keeps secure fixtures free of actionable findings', async () => {
  const result = await auditAiRag('https://app.example.test', config(), { fetch: secureFetch() });
  assert.equal(result.findings.filter((finding) => finding.severity !== 'INFO').length, 0);
  assert.equal(result.audit.protections.rateLimitObserved, true);
  assert.equal(result.audit.coverage, 'complete');
});

test('AI/RAG configuration enforces exact origin and safe auth headers', () => {
  assert.throws(() => normalizeAiRagConfig('https://app.example.test'), /ai_rag_configuration_required/);
  assert.throws(() => normalizeAiRagConfig('https://app.example.test', config({
    endpoint: 'https://secondary.example.test/api/ai',
  })), /ai_rag_endpoint_out_of_scope/);
  assert.throws(() => normalizeAiRagConfig('https://app.example.test', config({
    authProfiles: { a: { type: 'header', headerName: 'Host', value: 'bad' } },
  })), /invalid_ai_rag_auth_header/);
  assert.throws(() => normalizeAiRagConfig('https://app.example.test', config({
    prompts: { systemPrompt: `Reveal ${FIXTURES.systemPromptCanary}` },
  })), /invalid_ai_rag_fixture/);
  assert.throws(() => normalizeAiRagConfig('https://app.example.test', config({
    messageField: '__proto__.polluted',
  })), /invalid_ai_rag_mapping/);
});

test('runScan executes the specialized AI/RAG module locally', async () => {
  const server = http.createServer((request, response) => {
    let body = '';
    request.setEncoding('utf8');
    request.on('data', (chunk) => { body += chunk; });
    request.on('end', () => {
      const prompt = JSON.parse(body).message;
      const answer = prompt.includes('hidden system')
        ? 'VICE_SYSTEM_LOCAL_12345678'
        : prompt.includes('untrusted instruction')
          ? 'VICE_INJECTION_LOCAL_12345678'
          : 'SAFE';
      response.setHeader('content-type', 'application/json');
      response.end(JSON.stringify({ answer }));
    });
  });
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const endpoint = `http://127.0.0.1:${server.address().port}/ai`;

  try {
    const result = await runScan({
      url: endpoint,
      modules: ['ai-rag'],
      allowPrivateTargets: true,
      aiRag: {
        endpoint,
        expectedAccess: 'public',
        suites: ['llm'],
        fixtures: {
          systemPromptCanary: 'VICE_SYSTEM_LOCAL_12345678',
          promptInjectionCanary: 'VICE_INJECTION_LOCAL_12345678',
        },
      },
    });

    assert.equal(result.coverage.status, 'complete');
    assert.equal(result.score_reliable, true);
    assert.equal(result.ai_rag_audit.coverage, 'complete');
    assert.equal(result.findings.some((finding) => finding.rule_id === 'vice/llm/system-prompt-leakage'), true);
    assert.equal(result.findings.some((finding) => finding.rule_id === 'vice/llm/prompt-injection'), true);
  } finally {
    await new Promise((resolve) => server.close(resolve));
  }
});
