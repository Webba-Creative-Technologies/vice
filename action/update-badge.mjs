// ──────────────────────────────────────────────
// VICE Action — Generate badge JSON and commit it via Contents API
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'node:fs';
import path from 'node:path';
import { execSync } from 'node:child_process';

const GRADE_COLORS = {
  A: 'brightgreen',
  B: 'green',
  C: 'yellow',
  D: 'orange',
  E: 'red',
  F: 'critical',
};

const reportPath = process.argv[2];
const badgePath = process.argv[3] || '.github/vice-badge.json';
const repo = process.env.GITHUB_REPOSITORY;
const branch = process.env.GITHUB_REF_NAME;
const tmpDir = process.env.RUNNER_TEMP || process.env.TMPDIR || '/tmp';

if (!reportPath || !fs.existsSync(reportPath)) {
  console.error(`vice-action: report not found: ${reportPath}`);
  process.exit(0);
}

if (!repo || !branch) {
  console.error('vice-action: missing GITHUB_REPOSITORY or GITHUB_REF_NAME');
  process.exit(0);
}

let report;
try {
  report = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
} catch (err) {
  console.error(`vice-action: failed to parse report: ${err.message}`);
  process.exit(0);
}

if (report.error || typeof report.score !== 'number' || !report.grade) {
  console.error('vice-action: invalid report (no score), skipping badge update');
  process.exit(0);
}

const badge = {
  schemaVersion: 1,
  label: 'vice security',
  message: `${report.grade} \u2014 ${report.score}/100`,
  color: GRADE_COLORS[report.grade] || 'lightgrey',
};

const newContent = JSON.stringify(badge, null, 2) + '\n';
const newContentBase64 = Buffer.from(newContent, 'utf-8').toString('base64');

// Fetch the existing file from the API to get its SHA and content
let existingSha = null;
let existingBase64 = null;
try {
  const result = execSync(
    `gh api "repos/${repo}/contents/${badgePath}?ref=${branch}"`,
    { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] }
  );
  const parsed = JSON.parse(result);
  existingSha = parsed.sha || null;
  existingBase64 = (parsed.content || '').replace(/\s/g, '') || null;
} catch {
  // File does not exist on this branch yet — will be created
}

if (existingBase64 === newContentBase64) {
  console.log(`vice-action: badge unchanged (${badge.message}), no commit needed`);
  process.exit(0);
}

const payload = {
  message: `chore: update vice security badge [skip ci]`,
  content: newContentBase64,
  branch,
};
if (existingSha) payload.sha = existingSha;

const payloadFile = path.join(tmpDir, `vice-badge-${Date.now()}.json`);
fs.writeFileSync(payloadFile, JSON.stringify(payload));

try {
  execSync(
    `gh api "repos/${repo}/contents/${badgePath}" --input "${payloadFile}" -X PUT`,
    { stdio: 'inherit' }
  );
  console.log(`vice-action: badge committed to ${branch}: ${badge.message}`);
} catch (err) {
  console.error('vice-action: failed to commit badge.');
  console.error('Make sure the workflow has `contents: write` permission.');
  console.error(`Error: ${err.message}`);
  // Best-effort: do not fail the action
} finally {
  try { fs.unlinkSync(payloadFile); } catch {}
}
