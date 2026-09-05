import { AsyncLocalStorage } from 'node:async_hooks';

const scanStorage = new AsyncLocalStorage();

export function createScanContext(options = {}) {
  return {
    findings: [],
    checkOutcomes: [],
    discoveredIps: new Set(),
    authContext: options.authContext || null,
    scope: options.scope || null,
    signal: options.signal || null,
    browsers: new Set(),
    limitations: new Set(),
    browserMetrics: { allowed: 0, blocked: 0, auth_injected: 0, mutations_blocked: 0 },
  };
}

export function withScanContext(context, fn) {
  return scanStorage.run(context, fn);
}

export function getScanContext() {
  return scanStorage.getStore() || null;
}
