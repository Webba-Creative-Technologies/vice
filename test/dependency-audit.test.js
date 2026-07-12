import assert from 'node:assert/strict';
import test from 'node:test';

import { classifyNpmAudit, classifyOutdatedPackages } from '../src/core/detectors/dependency-audit.js';

test('npm audit classifier emits package-level confirmed advisories', () => {
  const results = classifyNpmAudit({
    vulnerabilities: {
      demo: {
        severity: 'high',
        isDirect: false,
        range: '<2.0.0',
        via: [{ title: 'Prototype pollution', url: 'https://example.test/advisory' }],
        fixAvailable: { name: 'parent', version: '3.0.0', isSemVerMajor: true },
      },
    },
  });

  assert.equal(results.length, 1);
  assert.equal(results[0].severity, 'HIGH');
  assert.equal(results[0].classification, 'confirmed');
  assert.match(results[0].detail, /transitive/);
  assert.match(results[0].detail, /major-version change/);
});

test('npm audit classifier retains moderate and low advisories', () => {
  const results = classifyNpmAudit({
    vulnerabilities: {
      moderatePackage: { severity: 'moderate', via: [], fixAvailable: false },
      lowPackage: { severity: 'low', via: [], fixAvailable: false },
    },
  });

  assert.deepEqual(results.map((result) => result.severity), ['MEDIUM', 'LOW']);
});

test('npm audit classifier handles aggregate-only reports', () => {
  const [result] = classifyNpmAudit({ metadata: { vulnerabilities: { critical: 1, high: 2 } } });

  assert.equal(result.severity, 'CRITICAL');
  assert.match(result.detail, /Package-level details were unavailable/);
});

test('outdated packages remain informational maintenance signals', () => {
  const result = classifyOutdatedPackages({ react: {}, vite: {} });

  assert.equal(result.severity, 'INFO');
  assert.equal(result.classification, 'hardening');
  assert.match(result.detail, /not proof of a vulnerability/);
});
