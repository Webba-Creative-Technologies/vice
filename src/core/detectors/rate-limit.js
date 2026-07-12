const LIMIT_MESSAGE = /rate.?limit|too many|trop (?:de )?(?:requ[eê]tes|tentatives)|try again later|r[eé]essayez plus tard|temporarily locked|compte (?:est )?bloqu[eé]|captcha/i;
const LIMIT_HEADERS = [
  'retry-after',
  'ratelimit-limit',
  'ratelimit-remaining',
  'ratelimit-reset',
  'x-ratelimit-limit',
  'x-ratelimit-remaining',
  'x-ratelimit-reset',
];

function headerValue(headers, name) {
  if (!headers) return null;
  if (typeof headers.get === 'function') return headers.get(name);

  const key = Object.keys(headers).find(candidate => candidate.toLowerCase() === name);
  return key ? String(headers[key]) : null;
}

export function classifyRateLimitEvidence(samples) {
  const attempts = Array.isArray(samples) ? samples.filter(Boolean) : [];

  for (let index = 0; index < attempts.length; index++) {
    const sample = attempts[index];
    const body = String(sample.body || '');
    const retryAfter = headerValue(sample.headers, 'retry-after');
    const challenged = LIMIT_MESSAGE.test(body);

    if (sample.status === 429 || challenged || (sample.status === 403 && retryAfter)) {
      return {
        state: 'enforced',
        attempt: index + 1,
        reason: sample.status === 429 ? 'HTTP 429' : retryAfter ? 'Retry-After' : 'blocking challenge',
      };
    }
  }

  const advertised = LIMIT_HEADERS.filter(name =>
    attempts.some(sample => headerValue(sample.headers, name) !== null),
  );

  if (advertised.length > 0) {
    return {
      state: 'advertised',
      attempts: attempts.length,
      headers: advertised,
    };
  }

  return {
    state: 'inconclusive',
    attempts: attempts.length,
    reason: attempts.length === 0
      ? 'No comparable response was captured.'
      : 'A short probe cannot prove that no higher-threshold or upstream limit exists.',
  };
}
