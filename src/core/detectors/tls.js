export function classifyTlsAuthorization(authorized, authorizationError) {
  if (authorized) return null;
  const error = String(authorizationError || 'certificate validation failed');

  if (/ALTNAME|HOSTNAME|IP address does not match/i.test(error)) {
    return {
      severity: 'CRITIQUE',
      title: 'Certificate hostname validation failed',
      error,
    };
  }

  if (/EXPIRED|NOT_YET_VALID/i.test(error)) {
    return {
      severity: 'CRITIQUE',
      title: 'Certificate validity check failed',
      error,
    };
  }

  return {
    severity: 'ELEVEE',
    title: 'Certificate chain is not trusted',
    error,
  };
}

export function classifyTlsPublicKey(keyType, keyDetails = {}) {
  if (keyType === 'rsa' && Number(keyDetails.modulusLength) < 2048) {
    return {
      severity: 'ELEVEE',
      title: `Weak RSA certificate key (${keyDetails.modulusLength} bits)`,
    };
  }

  if (keyType === 'ec' && /(?:192|224)/.test(String(keyDetails.namedCurve || ''))) {
    return {
      severity: 'ELEVEE',
      title: `Weak EC certificate curve (${keyDetails.namedCurve})`,
    };
  }

  return null;
}
