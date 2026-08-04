const STATE_CHANGING_METHODS = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);

export function isStateChangingForm(form) {
  return STATE_CHANGING_METHODS.has(String(form?.method || 'GET').toUpperCase());
}

export function classifyStoredInputSurface(form) {
  if (!form?.hasTextInput || !isStateChangingForm(form)) return null;

  return {
    severity: 'INFO',
    title: 'State-changing form accepts free text',
    detail: 'This is an input surface, not proof of stored XSS. Confirmation requires submitting a canary and observing unsafe rendering later.',
  };
}

export function classifyCsrfEvidence(form) {
  if (!isStateChangingForm(form)) return null;

  if (form?.hasCSRF) {
    return {
      severity: 'INFO',
      title: 'Explicit CSRF token detected',
      detail: 'The form contains a field whose name indicates an anti-CSRF token.',
    };
  }

  if (form?.usesCookieAuth && form?.crossSiteAccepted) {
    return {
      severity: 'ELEVEE',
      title: 'Cross-site form submission accepted with cookie authentication',
      detail: 'A cross-site state-changing request was accepted while authentication relied on cookies.',
      classification: 'confirmed',
      confidence: 'high',
    };
  }

  return null;
}
