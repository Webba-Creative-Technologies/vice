// ──────────────────────────────────────────────
// VICE Action — Set GitHub Action outputs from JSON report
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'node:fs';

const reportPath = process.argv[2];
const githubOutput = process.env.GITHUB_OUTPUT;

if (!reportPath) {
  console.error('vice-action: missing report path argument');
  process.exit(1);
}

if (!githubOutput) {
  console.error('vice-action: GITHUB_OUTPUT env var not set (running outside Actions?)');
  process.exit(1);
}

function writeOutputs(outputs) {
  const content = Object.entries(outputs).map(([k, v]) => `${k}=${v}`).join('\n') + '\n';
  fs.appendFileSync(githubOutput, content);
}

if (!fs.existsSync(reportPath)) {
  console.error(`vice-action: report file not found: ${reportPath}`);
  writeOutputs({
    score: 0,
    grade: 'F',
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    'report-path': reportPath,
  });
  process.exit(0);
}

let report;
try {
  report = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
} catch (err) {
  console.error(`vice-action: failed to parse report: ${err.message}`);
  writeOutputs({
    score: 0,
    grade: 'F',
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    'report-path': reportPath,
  });
  process.exit(0);
}

if (report.error) {
  console.error(`vice-action: scan failed: ${report.error}`);
  writeOutputs({
    score: 0,
    grade: 'F',
    total: 0,
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    'report-path': reportPath,
  });
  process.exit(0);
}

const summary = report.summary || {};
writeOutputs({
  score: report.score ?? 0,
  grade: report.grade || 'F',
  total: summary.total || 0,
  critical: summary.critical || 0,
  high: summary.high || 0,
  medium: summary.medium || 0,
  low: summary.low || 0,
  'report-path': reportPath,
});

console.log(`VICE: score ${report.score}/100 (${report.grade}) — ${summary.total || 0} findings`);
