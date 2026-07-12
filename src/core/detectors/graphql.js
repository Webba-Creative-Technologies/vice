export function classifyGraphqlDepthResponse(payload, status) {
  if (!payload || typeof payload !== 'object' || status >= 400) return null;

  if (Array.isArray(payload.errors) && payload.errors.length > 0) {
    const messages = payload.errors.map((error) => error?.message || '').join(' ');
    if (/depth|complexity|maximum|too\s+deep|cost\s+limit/i.test(messages)) {
      return { kind: 'protected', severity: 'INFO' };
    }
    return null;
  }

  if (payload.data && typeof payload.data === 'object') {
    return { kind: 'accepted', severity: 'MOYENNE' };
  }

  return null;
}

function errorMessages(payload) {
  const responses = Array.isArray(payload) ? payload : [payload];
  return responses
    .flatMap(response => Array.isArray(response?.errors) ? response.errors : [])
    .map(error => String(error?.message || ''))
    .join(' ');
}

export function classifyGraphqlBatchResponse(payload, status, expectedResponses = 2) {
  const messages = errorMessages(payload);
  if (/batch(?:ing|ed)?\s+(?:is\s+)?(?:disabled|not\s+(?:allowed|supported))|array\s+(?:body|request).*(?:not\s+allowed|unsupported)/i.test(messages)) {
    return { kind: 'protected', severity: 'INFO' };
  }
  if (status < 200 || status >= 300 || !Array.isArray(payload) || payload.length !== expectedResponses) return null;
  const graphqlResponses = payload.every(response => response && typeof response === 'object' && (response.data !== undefined || Array.isArray(response.errors)));
  return graphqlResponses ? { kind: 'supported', severity: 'INFO' } : null;
}

export function classifyGraphqlAliasResponse(payload, status, expectedAliases = 20) {
  if (!payload || typeof payload !== 'object') return null;
  const messages = errorMessages(payload);
  if (/complexity|cost\s+limit|too\s+(?:complex|expensive)|maximum\s+(?:aliases|complexity|cost)|alias\s+limit/i.test(messages)) {
    return { kind: 'protected', severity: 'INFO' };
  }
  if (status < 200 || status >= 300 || !payload.data || typeof payload.data !== 'object') return null;
  const aliases = Object.keys(payload.data).filter(key => /^viceAlias\d+$/.test(key));
  return aliases.length === expectedAliases ? { kind: 'accepted', severity: 'INFO' } : null;
}
