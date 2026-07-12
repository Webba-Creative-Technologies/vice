import test from 'node:test';
import assert from 'node:assert/strict';

import { redactSensitiveText, redactSensitiveValue } from '../src/core/redaction.js';
import { decorateFinding } from '../src/core/rules.js';

test('redacts private credentials without retaining their values', () => {
  const stripe = `sk_live_${'a'.repeat(24)}`;
  const github = `ghp_${'b'.repeat(40)}`;
  const result = redactSensitiveText(`Stripe ${stripe}, GitHub ${github}`);

  assert.equal(result.includes(stripe), false);
  assert.equal(result.includes(github), false);
  assert.match(result, /\[REDACTED:Stripe Secret Key\]/);
  assert.match(result, /\[REDACTED:GitHub Token\]/);
});

test('redacts Discord webhook credentials from titles and evidence', () => {
  const webhook = `https://discord.com/api/webhooks/123456789/${'token_'.repeat(12)}`;
  const finding = decorateFinding({
    module: 'API Endpoints',
    severity: 'CRITIQUE',
    title: `Webhook exposed: ${webhook}`,
    detail: webhook,
  });

  assert.equal(JSON.stringify(finding).includes(webhook), false);
  assert.match(finding.title, /\[REDACTED:Discord Webhook\]/);
  assert.equal(finding.detail, '[REDACTED:Discord Webhook]');
});

test('keeps identifiers explicitly designed for public clients', () => {
  const publishable = `pk_test_${'c'.repeat(24)}`;
  const supabaseUrl = 'https://sample-project.supabase.co';

  assert.equal(
    redactSensitiveText(`${publishable} ${supabaseUrl}`),
    `${publishable} ${supabaseUrl}`,
  );
});

test('redacts nested evidence before findings leave the engine', () => {
  const databaseUrl = 'postgresql://admin:very-secret-password@db.example.test/app';
  const finding = decorateFinding({
    module: 'Secrets',
    severity: 'CRITIQUE',
    title: 'Credential exposed',
    detail: `Found ${databaseUrl}`,
    evidence: { samples: [databaseUrl] },
    recommendation: 'Rotate it.',
  });

  assert.equal(JSON.stringify(finding).includes('very-secret-password'), false);
  assert.equal(finding.detail, 'Found [REDACTED:Database Credential URL]');
  assert.deepEqual(finding.evidence.samples, ['[REDACTED:Database Credential URL]']);
});

test('preserves null and scalar evidence values', () => {
  assert.deepEqual(redactSensitiveValue({ count: 2, enabled: true, value: null }), {
    count: 2,
    enabled: true,
    value: null,
  });
});
