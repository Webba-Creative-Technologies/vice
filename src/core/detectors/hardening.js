const SIGNALS = Object.freeze({
  'missing-csp': {
    severity: 'FAIBLE',
    category: 'hardening',
  },
  'missing-sri': {
    severity: 'FAIBLE',
    category: 'hardening',
  },
  'public-source-map': {
    severity: 'FAIBLE',
    category: 'exposure',
  },
  'public-api-docs': {
    severity: 'INFO',
    category: 'exposure',
  },
  'graphql-introspection': {
    severity: 'INFO',
    category: 'exposure',
  },
  'graphql-suggestions': {
    severity: 'INFO',
    category: 'exposure',
  },
});

export function classifyHardeningSignal(name) {
  const signal = SIGNALS[name];
  return signal ? { ...signal } : null;
}
