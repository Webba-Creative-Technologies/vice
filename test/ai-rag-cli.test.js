import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';

import { loadAiRagCliConfig } from '../src/core/ai-rag/cli-config.js';

function withConfig(config, callback) {
  const directory = mkdtempSync(join(tmpdir(), 'vice-ai-rag-cli-'));
  const filename = join(directory, 'vice.ai-rag.json');
  writeFileSync(filename, JSON.stringify(config));
  try {
    return callback(filename);
  } finally {
    rmSync(directory, { recursive: true, force: true });
  }
}

test('AI/RAG CLI resolves authentication profiles from environment variables', () => {
  withConfig({
    endpoint: 'https://example.test/api/chat',
    authProfiles: {
      a: { type: 'bearer', secretEnv: 'VICE_AI_USER_A_TOKEN' },
    },
  }, (filename) => {
    const config = loadAiRagCliConfig(filename, { VICE_AI_USER_A_TOKEN: 'test-user-token' });
    assert.deepEqual(config.authProfiles.a, { type: 'bearer', secret: 'test-user-token' });
    assert.equal(JSON.stringify(config).includes('VICE_AI_USER_A_TOKEN'), false);
  });
});

test('AI/RAG CLI rejects literal and unavailable secrets', () => {
  withConfig({ authProfiles: { a: { type: 'bearer', secret: 'literal-token' } } }, (filename) => {
    assert.throws(() => loadAiRagCliConfig(filename, {}), /literal_secret_forbidden/);
  });
  withConfig({ authProfiles: { a: { type: 'bearer', secretEnv: 'VICE_AI_USER_A_TOKEN' } } }, (filename) => {
    assert.throws(() => loadAiRagCliConfig(filename, {}), /secret_env_missing/);
  });
});
