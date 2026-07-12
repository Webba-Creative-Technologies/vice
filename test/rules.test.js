import assert from 'node:assert/strict';
import test from 'node:test';

import { decorateFinding, deriveRuleId, inferFindingClassification } from '../src/core/rules.js';
import { ENGINE_VERSION, RULESET_VERSION } from '../src/core/version.js';

test('dynamic values share a stable rule identifier', () => {
  const first = deriveRuleId({ module: 'Supabase RLS', title: 'Table "users" accepts anonymous inserts' });
  const second = deriveRuleId({ module: 'Supabase RLS', title: 'Table "orders" accepts anonymous inserts' });

  assert.equal(first, second);
});

test('different finding shapes keep different identifiers', () => {
  const missing = deriveRuleId({ module: 'CSP', title: 'No Content-Security-Policy' });
  const unsafe = deriveRuleId({ module: 'CSP', title: 'CSP with unsafe-eval' });

  assert.notEqual(missing, unsafe);
});

test('confirmed evidence receives high confidence', () => {
  const finding = decorateFinding({
    severity: 'CRITIQUE',
    module: 'SQL Injection',
    title: 'Blind SQL Injection confirmed (time-based)',
    detail: 'Repeated delay confirmed',
  });

  assert.equal(finding.classification, 'confirmed');
  assert.equal(finding.confidence, 'high');
  assert.equal(finding.engine_version, ENGINE_VERSION);
  assert.equal(finding.ruleset_version, RULESET_VERSION);
  assert.match(finding.rule_id, /^vice\//);
  assert.match(finding.fingerprint, /^[a-f0-9]{16}$/);
});

test('hardening signals stay separate from vulnerabilities', () => {
  assert.equal(inferFindingClassification({ module: 'CSP', title: 'No Content-Security-Policy' }), 'hardening');
});

test('provided confidence is preserved', () => {
  const finding = decorateFinding({ module: 'Code', title: 'Potential sink', confidence: 'low' });

  assert.equal(finding.confidence, 'low');
});
