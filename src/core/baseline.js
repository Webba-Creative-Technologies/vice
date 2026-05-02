// ──────────────────────────────────────────────
// VICE — Baseline file management
// Suppress pre-existing findings on adoption so only new issues block CI.
// File: .vice-baseline.json at project root.
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import { fingerprintFinding } from './fingerprint.js';

const BASELINE_FILENAME = '.vice-baseline.json';

export function getBaselinePath(projectPath) {
  return path.join(projectPath, BASELINE_FILENAME);
}

export function loadBaseline(projectPath) {
  const file = getBaselinePath(projectPath);
  if (!fs.existsSync(file)) return null;
  try {
    return JSON.parse(fs.readFileSync(file, 'utf-8'));
  } catch (err) {
    process.stderr.write(`VICE: ${file} is corrupted (${err.message}) - baseline ignored. Re-run "vice baseline" to regenerate.\n`);
    return null;
  }
}

export function writeBaseline(projectPath, findings, viceVersion) {
  const file = getBaselinePath(projectPath);
  const entries = {};
  for (const f of findings) {
    if (f.severity === 'INFO') continue;
    const fp = fingerprintFinding(f);
    if (!entries[fp]) {
      entries[fp] = {
        module: f.module,
        title: f.title,
        file: (f.location && f.location.file) || null,
        severity: f.severity,
      };
    }
  }
  const baseline = {
    version: 1,
    created: new Date().toISOString(),
    vice_version: viceVersion || 'unknown',
    findings: entries,
  };
  fs.writeFileSync(file, JSON.stringify(baseline, null, 2) + '\n');
  return file;
}

// Mutates findings in place: sets `baselined: true` on entries already
// present in the baseline. Returns the same array for chaining.
export function applyBaseline(findings, baseline) {
  if (!baseline || !baseline.findings) return findings;
  const fingerprints = new Set(Object.keys(baseline.findings));
  for (const f of findings) {
    const fp = fingerprintFinding(f);
    if (fingerprints.has(fp)) f.baselined = true;
  }
  return findings;
}
