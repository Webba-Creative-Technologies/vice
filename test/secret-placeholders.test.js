import assert from 'node:assert/strict';
import test from 'node:test';

import { extractAssignedSecretValue, isPlaceholderSecret } from '../src/utils/patterns.js';

const stripePlaceholder = ['sk', 'test', 'x'.repeat(24)].join('_');
const stripeExample = ['sk', 'test', '7sQa29Lm4Nx8Pc6Vr2Td5Yw9'].join('_');

const placeholders = [
  'apiKey="VITE_PUBLIC_API_KEY"',
  'Bearer ACCESS_TOKEN',
  stripePlaceholder,
  'ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  'github_pat_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  'glpat-xxxxxxxxxxxxxxxxxxxx',
  'npm_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  'SG.xxxxxxxxxxxxxxxx.xxxxxxxxxxxxxxxxxxxx',
  'AIzaSyxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx',
  'AKIAIOSFODNN7EXAMPLE',
  'aws_secret_key="wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"',
  'DATABASE_URL=postgresql://user:password@db.example.com/app',
  'api_key="abcdabcdabcdabcdabcdabcdabcdabcd"',
];

for (const candidate of placeholders) {
  test(`recognizes credential placeholder: ${candidate.slice(0, 32)}`, () => {
    assert.equal(isPlaceholderSecret(candidate), true);
  });
}

const actionable = [
  stripeExample,
  'ghp_7sQa29Lm4Nx8Pc6Vr2Td5Yw9Kb3Hf8Cj1AzE',
  'api_key="A7f9K2mQ8vX4cN6pR3sT5uW1yZ0bD4eH"',
  'DATABASE_URL=postgresql://admin:A7f9K2mQ8vX4@db.acme-secure.net/app',
];

for (const candidate of actionable) {
  test(`keeps actionable credential: ${candidate.slice(0, 32)}`, () => {
    assert.equal(isPlaceholderSecret(candidate), false);
  });
}

test('extracts complete assigned database URLs', () => {
  assert.equal(
    extractAssignedSecretValue('DATABASE_URL=postgresql://admin:secret@db.acme-secure.net/app'),
    'postgresql://admin:secret@db.acme-secure.net/app',
  );
});
