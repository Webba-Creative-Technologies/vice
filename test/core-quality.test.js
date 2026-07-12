import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { calculateScore } from '../src/core/score.js';
import { fingerprintFinding, normalizeEvidenceKey, normalizeTitle } from '../src/core/fingerprint.js';
import { isPlaceholderSecret, SECRET_PATTERNS } from '../src/utils/patterns.js';

const corpus = JSON.parse(readFileSync(new URL('./fixtures/detection-corpus.json', import.meta.url), 'utf8'));
corpus.positives = corpus.positives
  .map(entry => ({ ...entry, source: entry.source ?? entry.sourceParts?.join('') }));

function matchingPatternNames(source) {
  return SECRET_PATTERNS
    .filter(({ regex, validate }) => {
      regex.lastIndex = 0;
      const match = regex.exec(source);
      return match && !isPlaceholderSecret(match[0]) && (!validate || validate(match[0]));
    })
    .map(({ name }) => name);
}

test('score caps repeated findings from the same rule', () => {
  const findings = Array.from({ length: 4 }, (_, index) => ({
    severity: 'CRITICAL',
    module: 'Secrets',
    title: 'Exposed production credential',
    detail: `credential ${index}`,
    confidence: 'high',
  }));

  const result = calculateScore(findings);

  assert.equal(result.score, 55);
  assert.equal(result.grade, 'D');
});

test('score caps a rule using its strongest actionable findings', () => {
  const findings = [
    { severity: 'INFO', rule_id: 'vice/rls/anonymous-read', confidence: 'high' },
    { severity: 'HIGH', rule_id: 'vice/rls/anonymous-read', confidence: 'high' },
    { severity: 'INFO', rule_id: 'vice/rls/anonymous-read', confidence: 'high' },
    { severity: 'CRITICAL', rule_id: 'vice/rls/anonymous-read', confidence: 'high' },
    { severity: 'HIGH', rule_id: 'vice/rls/anonymous-read', confidence: 'high' },
    { severity: 'HIGH', rule_id: 'vice/rls/anonymous-read', confidence: 'high' },
  ];

  const result = calculateScore(findings);

  assert.equal(result.score, 69);
  assert.equal(result.grade, 'C');
  assert.deepEqual(result.breakdown, [{
    rule_id: 'vice/rls/anonymous-read',
    penalty: 31,
    counted_findings: 3,
    observed_findings: 4,
  }]);
  assert.equal(result.excluded.informational, 2);
});

test('score honors confidence and baseline filters', () => {
  const findings = [
    { severity: 'CRITICAL', module: 'A', title: 'Low confidence', confidence: 'low' },
    { severity: 'HIGH', module: 'B', title: 'Baselined', confidence: 'high', baselined: true },
    { severity: 'MEDIUM', module: 'C', title: 'Confirmed', confidence: 'high' },
  ];

  const result = calculateScore(findings, { minConfidence: 'high' });

  assert.equal(result.score, 97);
  assert.equal(result.grade, 'A');
});

test('fingerprints survive line-number changes', () => {
  const first = {
    module: 'Code',
    title: 'Unsafe eval in src/app.js:42',
    detail: 'eval receives request input',
    location: { file: 'src/app.js' },
  };
  const second = { ...first, title: 'Unsafe eval in src/app.js:87' };

  assert.equal(normalizeTitle(first.title), normalizeTitle(second.title));
  assert.equal(fingerprintFinding(first), fingerprintFinding(second));
  assert.notEqual(
    fingerprintFinding(first),
    fingerprintFinding({ ...second, location: { file: 'src/other.js' } }),
  );
});

test('fingerprints ignore volatile evidence values', () => {
  const first = {
    rule_id: 'vice/supabase/public-read',
    title: 'Public table response',
    detail: 'https://example.com/rest/v1/items?cursor=first returns 3 rows at 2026-07-10T14:00:00Z',
  };
  const second = {
    ...first,
    detail: 'https://example.com/rest/v1/items?cursor=second returns 12 rows at 2026-07-10T15:30:00Z',
  };

  assert.equal(normalizeEvidenceKey(first.detail), normalizeEvidenceKey(second.detail));
  assert.equal(fingerprintFinding(first), fingerprintFinding(second));
});

test('fingerprints preserve distinct endpoint paths', () => {
  const first = { rule_id: 'vice/api/exposure', title: 'Public endpoint', detail: 'https://example.com/api/users' };
  const second = { ...first, detail: 'https://example.com/api/admins' };

  assert.notEqual(fingerprintFinding(first), fingerprintFinding(second));
});

for (const fixture of corpus.positives) {
  test(`secret corpus detects ${fixture.name}`, () => {
    assert.ok(matchingPatternNames(fixture.source).includes(fixture.expectedPattern));
  });
}

for (const fixture of corpus.negatives) {
  test(`secret corpus ignores ${fixture.name}`, () => {
    assert.deepEqual(matchingPatternNames(fixture.source), []);
  });
}
