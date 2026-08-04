function headerValue(value) {
  return String(value || '').trim();
}

export function classifyCorsPolicy({ requestOrigin, allowOrigin, allowCredentials }) {
  const requested = headerValue(requestOrigin);
  const allowed = headerValue(allowOrigin);
  const credentials = headerValue(allowCredentials).toLowerCase() === 'true';

  if (!requested || !allowed) return null;

  if (allowed === requested) {
    if (credentials) {
      return {
        kind: 'reflected-origin-with-credentials',
        severity: 'CRITIQUE',
        title: 'Arbitrary CORS origin reflected with credentials',
        detail: `The server reflects ${requested} and allows credentials. A malicious origin can read authenticated responses.`,
      };
    }

    return {
      kind: 'reflected-origin',
      severity: 'INFO',
      title: 'Arbitrary CORS origin reflected',
      detail: `The server reflects ${requested} without credentials. This can be intentional for public responses.`,
    };
  }

  if (allowed === '*') {
    if (credentials) {
      return {
        kind: 'wildcard-with-credentials',
        severity: 'INFO',
        title: 'Invalid wildcard CORS credentials policy',
        detail: 'The response combines Access-Control-Allow-Origin: * with credentials. Browsers reject credentialed access for this combination.',
      };
    }

    return {
      kind: 'public-wildcard',
      severity: 'INFO',
      title: 'Public wildcard CORS policy',
      detail: 'The resource is readable by any origin without credentials. This can be intentional for public content.',
    };
  }

  return null;
}
