import assert from 'node:assert/strict';
import test from 'node:test';

import {
  classifyCsrfEvidence,
  classifyStoredInputSurface,
  isStateChangingForm,
} from '../src/core/detectors/forms.js';

test('GET search forms are not stored XSS evidence', () => {
  const form = { method: 'get', hasTextInput: true };

  assert.equal(isStateChangingForm(form), false);
  assert.equal(classifyStoredInputSurface(form), null);
});

test('POST text forms are informational input surfaces', () => {
  const result = classifyStoredInputSurface({ method: 'post', hasTextInput: true });

  assert.equal(result.severity, 'INFO');
  assert.match(result.detail, /not proof/i);
});

test('missing CSRF field stays low confidence', () => {
  const result = classifyCsrfEvidence({ method: 'POST', hasCSRF: false });

  assert.equal(result.severity, 'FAIBLE');
  assert.match(result.detail, /does not confirm/i);
});

test('explicit CSRF fields remain informational evidence', () => {
  const result = classifyCsrfEvidence({ method: 'POST', hasCSRF: true });

  assert.equal(result.severity, 'INFO');
});

test('GET forms do not need state-changing CSRF classification', () => {
  assert.equal(classifyCsrfEvidence({ method: 'GET', hasCSRF: false }), null);
});
