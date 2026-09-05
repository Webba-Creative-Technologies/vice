import test from 'node:test';
import assert from 'node:assert/strict';
import { gradeForScore, scorePresentation } from '../src/core/score-policy.js';
import { calculateScore } from '../src/core/score.js';

test('score presentation preserves all numeric grade boundaries', () => {
  for (const [score, grade] of [[100,'A'],[90,'A'],[89,'B'],[75,'B'],[74,'C'],[60,'C'],[59,'D'],[40,'D'],[39,'E'],[20,'E'],[19,'F'],[0,'F']]) {
    assert.equal(gradeForScore(score), grade);
  }
  for (const score of [null, undefined, NaN, Infinity, -1, 101, '100']) assert.equal(gradeForScore(score), null);
});

test('a critical finding overrides a reassuring number without changing it', () => {
  const result = calculateScore([{ severity: 'CRITICAL', title: 'Fixture', rule_id: 'fixture/critical', confidence: 'high' }]);
  assert.equal(result.score, 85);
  assert.equal(result.grade, 'B');
  assert.equal(result.presentation.tone, 'error');
});

test('incomplete checks and unverified sessions never present success', () => {
  for (const options of [{reliable:false}, {coverageStatus:'partial'}, {coverageStatus:'incomplete'}, {authStatus:'unverified'}, {authStatus:'unavailable'}, {authStatus:'required'}, {highCount:1}]) {
    assert.equal(scorePresentation(100, options).tone, 'warning');
  }
  const both = scorePresentation(100, {criticalCount:1, reliable:false});
  assert.equal(both.tone, 'error');
  assert.equal(both.provisional, true);
  assert.equal(scorePresentation(100).tone, 'success');
});

