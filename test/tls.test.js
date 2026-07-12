import assert from 'node:assert/strict';
import test from 'node:test';

import { classifyTlsAuthorization, classifyTlsPublicKey } from '../src/core/detectors/tls.js';

test('authorized TLS chains produce no finding', () => {
  assert.equal(classifyTlsAuthorization(true, null), null);
});

test('TLS hostname mismatches are critical', () => {
  const result = classifyTlsAuthorization(false, 'ERR_TLS_CERT_ALTNAME_INVALID');

  assert.equal(result.severity, 'CRITIQUE');
  assert.match(result.title, /hostname/i);
});

test('untrusted TLS chains are high severity', () => {
  const result = classifyTlsAuthorization(false, 'SELF_SIGNED_CERT_IN_CHAIN');

  assert.equal(result.severity, 'ELEVEE');
});

test('weak RSA keys are detected', () => {
  assert.equal(classifyTlsPublicKey('rsa', { modulusLength: 1024 }).severity, 'ELEVEE');
  assert.equal(classifyTlsPublicKey('rsa', { modulusLength: 2048 }), null);
});

test('weak EC curves are detected', () => {
  assert.equal(classifyTlsPublicKey('ec', { namedCurve: 'secp192r1' }).severity, 'ELEVEE');
  assert.equal(classifyTlsPublicKey('ec', { namedCurve: 'prime256v1' }), null);
});
