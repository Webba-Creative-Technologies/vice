import test from 'node:test';
import assert from 'node:assert/strict';
import { dnsPolicyOutcome } from '../src/core/check-outcomes.js';

test('DNS recheck proofs require conclusive, unique policy records', () => {
  assert.equal(dnsPolicyOutcome('spf','fixture.example',[['v=spf1 -all']]).outcome,'pass');
  assert.equal(dnsPolicyOutcome('dmarc','fixture.example',[['v=DMARC1; p=reject']]).outcome,'pass');
  assert.equal(dnsPolicyOutcome('spf','fixture.example',[],{code:'ENOTFOUND'}).outcome,'fail');
  assert.equal(dnsPolicyOutcome('spf','fixture.example',null,{code:'ETIMEDOUT'}).outcome,'unknown');
  assert.equal(dnsPolicyOutcome('spf','fixture.example',[['v=spf1 +all']]).outcome,'unknown');
  assert.equal(dnsPolicyOutcome('dmarc','fixture.example',[['v=DMARC1; p=none']]).outcome,'unknown');
  assert.equal(dnsPolicyOutcome('spf','fixture.example',[['v=spf1 -all'],['v=spf1 -all']]).outcome,'unknown');
  assert.equal(dnsPolicyOutcome('spf','fixture.example',[['arbitrary text v=spf1 -all']]).outcome,'fail');
});

test('DNS rechecks carry only opaque resource keys, outcomes and versions', () => {
  const result = dnsPolicyOutcome('spf','fixture.example',[['v=spf1 -all']]);
  assert.deepEqual(Object.keys(result).sort(),['key','outcome','version']);
  assert.match(result.key,/^dns-spf-presence-v1:[a-f0-9]{64}$/);
  assert.equal(result.key,dnsPolicyOutcome('spf','FIXTURE.EXAMPLE',[]).key);
  assert.notEqual(result.key,dnsPolicyOutcome('spf','second.example',[]).key);
  assert.equal(JSON.stringify(result).includes('fixture.example'),false);
});
