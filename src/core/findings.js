// ──────────────────────────────────────────────
// VICE — Findings Manager
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

const findings = [];
const discoveredIps = new Set();

export function addFinding(severity, module, title, detail, recommendation, location) {
  findings.push({ severity, module, title, detail, recommendation, location });
}

export function getFindings() {
  return findings;
}

export function clearFindings() {
  findings.length = 0;
}

export function loadFindings(data) {
  findings.length = 0;
  findings.push(...data);
}

export function addDiscoveredIp(ip) {
  discoveredIps.add(ip);
}

export function getDiscoveredIps() {
  return [...discoveredIps];
}
