// ──────────────────────────────────────────────
// VICE - Findings Manager
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import { decorateFinding } from './rules.js';

const findings = [];
const discoveredIps = new Set();
const findingIndexes = new WeakMap();

const SEVERITY_RANK = {
  INFO: 1,
  LOW: 2,
  FAIBLE: 2,
  MEDIUM: 3,
  MOYENNE: 3,
  HIGH: 4,
  ELEVEE: 4,
  CRITICAL: 5,
  CRITIQUE: 5,
};
const CONFIDENCE_RANK = { low: 1, medium: 2, high: 3 };

function indexFor(target) {
  const current = findingIndexes.get(target);
  if (current?.length === target.length) return current;

  const byFingerprint = new Map();
  target.forEach((finding, index) => {
    if (finding?.fingerprint && !byFingerprint.has(finding.fingerprint)) {
      byFingerprint.set(finding.fingerprint, index);
    }
  });
  const rebuilt = { byFingerprint, length: target.length };
  findingIndexes.set(target, rebuilt);
  return rebuilt;
}

function strongerValue(first, second, ranks) {
  return (ranks[second] || 0) > (ranks[first] || 0) ? second : first;
}

export function appendFinding(target, finding) {
  const decorated = decorateFinding(finding);
  const state = indexFor(target);
  const duplicateIndex = state.byFingerprint.get(decorated.fingerprint);

  if (duplicateIndex !== undefined) {
    const existing = target[duplicateIndex];
    target[duplicateIndex] = {
      ...existing,
      severity: strongerValue(existing.severity, decorated.severity, SEVERITY_RANK),
      confidence: strongerValue(existing.confidence, decorated.confidence, CONFIDENCE_RANK),
      occurrences: (existing.occurrences || 1) + 1,
    };
    return target[duplicateIndex];
  }

  target.push(decorated);
  state.byFingerprint.set(decorated.fingerprint, target.length - 1);
  state.length = target.length;
  return decorated;
}

export function addFinding(severity, module, title, detail, recommendation, location, confidence, metadata = {}) {
  return appendFinding(findings, {
    severity,
    module,
    title,
    detail,
    recommendation,
    location,
    confidence,
    ...metadata,
  });
}

export function getFindings() {
  return findings;
}

export function clearFindings() {
  findings.length = 0;
  discoveredIps.clear();
  findingIndexes.delete(findings);
}

export function loadFindings(data) {
  findings.length = 0;
  findingIndexes.delete(findings);
  for (const finding of data || []) appendFinding(findings, finding);
}

export function setFindings(data) {
  loadFindings(data);
}

export function addDiscoveredIp(ip) {
  discoveredIps.add(ip);
}

export function getDiscoveredIps() {
  return [...discoveredIps];
}
