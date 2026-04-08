// ──────────────────────────────────────────────
// VICE — Badge Generator (shields.io endpoint format)
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'fs';
import path from 'path';

const GRADE_COLORS = {
  A: 'brightgreen',
  B: 'green',
  C: 'yellow',
  D: 'orange',
  E: 'red',
  F: 'critical',
};

export function generateBadge(score, grade) {
  return {
    schemaVersion: 1,
    label: 'vice security',
    message: `${grade} — ${score}/100`,
    color: GRADE_COLORS[grade] || 'lightgrey',
  };
}

export function writeBadgeFile(score, grade, outputPath) {
  const badge = generateBadge(score, grade);
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
  return { score: data.score, grade: data.grade };
}

export function findLatestReport(scansDir) {
  if (!fs.existsSync(scansDir)) return null;
  const files = fs.readdirSync(scansDir)
    .filter(f => f.startsWith('vice-report-') && f.endsWith('.json'))
    .map(f => ({ name: f, mtime: fs.statSync(path.join(scansDir, f)).mtime.getTime() }))
    .sort((a, b) => b.mtime - a.mtime);
  return files.length > 0 ? path.join(scansDir, files[0].name) : null;
}
