const SIGNALS = {
  'author-enumeration': { severity: 'INFO', confidence: 'high', classification: 'exposure' },
  'rest-users': { severity: 'INFO', confidence: 'high', classification: 'exposure' },
  xmlrpc: { severity: 'INFO', confidence: 'high', classification: 'hardening' },
  'default-login': { severity: 'INFO', confidence: 'high', classification: 'hardening' },
  'http-cron': { severity: 'INFO', confidence: 'low', classification: 'heuristic' },
};

export function classifyWordpressSurface(kind) {
  const signal = SIGNALS[kind];
  return signal ? { ...signal } : null;
}
