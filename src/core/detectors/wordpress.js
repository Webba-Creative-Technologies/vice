const SIGNALS = {
  'author-enumeration': { severity: 'MOYENNE', confidence: 'medium', classification: 'probable' },
  'rest-users': { severity: 'MOYENNE', confidence: 'high', classification: 'confirmed' },
  xmlrpc: { severity: 'MOYENNE', confidence: 'medium', classification: 'probable' },
  'default-login': { severity: 'INFO', confidence: 'high', classification: 'hardening' },
  'http-cron': { severity: 'FAIBLE', confidence: 'low', classification: 'heuristic' },
};

export function classifyWordpressSurface(kind) {
  const signal = SIGNALS[kind];
  return signal ? { ...signal } : null;
}
