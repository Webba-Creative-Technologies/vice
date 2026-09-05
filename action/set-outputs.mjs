// ──────────────────────────────────────────────
// VICE Action - Set GitHub Action outputs from JSON report
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'node:fs';
import { gradeForScore } from '../src/core/score-policy.js';

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
  const content = Object.entries(outputs).map(([k, v]) => `${k}=${String(v).replace(/[\r\n]/g, '')}`).join('\n') + '\n';
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
  console.error('vice-action: failed to parse report');
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
  console.error('vice-action: scan failed');
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
const count = value => Number.isSafeInteger(value) && value >= 0 ? value : 0;
const grade = gradeForScore(report.score);
writeOutputs({
  score: grade ? report.score : '',
  grade: grade || '',
  total: count(summary.total),
  critical: count(summary.critical),
  high: count(summary.high),
  medium: count(summary.medium),
  low: count(summary.low),
  'report-path': reportPath,
});

console.log(grade ? `VICE: score ${report.score}/100 (${grade}) - ${count(summary.total)} findings` : 'VICE: score unavailable');
