// ──────────────────────────────────────────────
// VICE - Badge Generator (shields.io endpoint format)
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import { scorePresentation } from './score-policy.js';

const TONE_COLORS = { success: 'brightgreen', warning: 'yellow', error: 'critical', default: 'lightgrey' };

export function generateBadge(score, grade, options = {}) {
  const presentation = scorePresentation(score, options);
  const suffix = presentation.critical ? ' - critical' : presentation.provisional ? ' - provisional' : '';
  return {
    schemaVersion: 1,
    label: 'vice security',
    message: presentation.grade === null ? 'no score' : `${presentation.grade} - ${score}/100${suffix}`,
    color: TONE_COLORS[presentation.tone],
  };
}

export function writeBadgeFile(score, grade, outputPath, options = {}) {
  const badge = generateBadge(score, grade, options);
  const dir = path.dirname(path.resolve(outputPath));
  if (dir && !fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(outputPath, JSON.stringify(badge, null, 2) + '\n');
  return outputPath;
}

export function readReportFile(inputPath) {
  const resolved = path.resolve(inputPath);
  if (!fs.existsSync(resolved)) {
    throw new Error(`Report file not found: ${resolved}`);
  }
  const data = JSON.parse(fs.readFileSync(resolved, 'utf-8'));
  if (typeof data.score !== 'number' || !data.grade) {
    throw new Error(`Invalid report file: missing score or grade`);
  }
  const findings = Array.isArray(data.findings) ? data.findings.filter(f => f && !f.baselined) : [];
  return { score: data.score, grade: data.grade, options: {
    criticalCount: findings.filter(f => ['critical', 'critique'].includes(String(f.severity).toLowerCase())).length,
    highCount: findings.filter(f => ['high', 'elevee'].includes(String(f.severity).toLowerCase())).length,
    reliable: data.score_reliable,
    coverageStatus: data.coverage?.status,
    authStatus: data.authentication?.status,
  } };
}

export function findLatestReport(scansDir) {
  if (!fs.existsSync(scansDir)) return null;
  const files = fs.readdirSync(scansDir)
    .filter(f => f.startsWith('vice-report-') && f.endsWith('.json'))
    .map(f => ({ name: f, mtime: fs.statSync(path.join(scansDir, f)).mtime.getTime() }))
    .sort((a, b) => b.mtime - a.mtime);
  return files.length > 0 ? path.join(scansDir, files[0].name) : null;
}
