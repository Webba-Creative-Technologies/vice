export function classifySignupResponse(status, body = {}) {
  if (status === 429) {
    return { severity: 'INFO', confidence: 'high', classification: 'confirmed', kind: 'rate-limited', title: 'Signup rate limiting is active' };
  }
  if (status === 400 || status === 401 || status === 403 || status === 422) {
    return { severity: 'INFO', confidence: 'high', classification: 'confirmed', kind: 'restricted', title: 'Signup request was rejected or validated' };
  }
  if (![200, 201].includes(status)) return null;

  const user = body.user || (body.id ? body : null);
  const accessToken = body.access_token || body.session?.access_token;
  if (accessToken) {
    return { severity: 'INFO', confidence: 'high', classification: 'confirmed', kind: 'immediate-session', title: 'Public signup returns an immediate user session', user };
  }
  if (user || body.confirmation_sent_at) {
    return { severity: 'INFO', confidence: 'high', classification: 'confirmed', kind: 'confirmation', title: 'Public signup creates a user without an immediate session', user };
  }
  return { severity: 'INFO', confidence: 'medium', classification: 'probable', kind: 'accepted', title: 'Public signup request was accepted', user: null };
}
