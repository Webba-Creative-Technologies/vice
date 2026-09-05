// ──────────────────────────────────────────────
// VICE Action - Post or update PR comment via gh CLI
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'node:fs';
import path from 'node:path';
import { contentsEndpoint, githubApi } from './api.mjs';
import { formatPrComment, formatErrorComment } from './format.mjs';

const MARKER = '<!-- vice-action-comment -->';

const reportPath = process.argv[2];
const repo = process.env.GITHUB_REPOSITORY;
const prNumber = process.env.PR_NUMBER;
const baseRef = process.env.GITHUB_BASE_REF;
const badgePath = process.env.BADGE_PATH || '.github/vice-badge.json';
const tmpDir = process.env.RUNNER_TEMP || process.env.TMPDIR || '/tmp';

if (!reportPath || !fs.existsSync(reportPath)) {
  console.error(`vice-action: report file not found: ${reportPath}`);
  process.exit(0);
}

if (!/^[\w.-]+\/[\w.-]+$/.test(repo || '') || !/^\d+$/.test(prNumber || '')) {
  console.error('vice-action: missing GITHUB_REPOSITORY or PR_NUMBER (not running in a PR context?)');
  process.exit(0);
}

let report;
try {
  report = JSON.parse(fs.readFileSync(reportPath, 'utf-8'));
} catch (err) {
  console.error(`vice-action: failed to parse report: ${err.message}`);
  process.exit(0);
}

let body;
if (report.error) {
  body = `${MARKER}\n\n${formatErrorComment(report.error)}`;
} else {
  const previousScore = baseRef ? readPreviousScore(baseRef) : null;
  body = `${MARKER}\n\n${formatPrComment(report, { previousScore })}`;
}

postOrUpdateComment(body);

function readPreviousScore(ref) {
  try {
    const result = githubApi([contentsEndpoint(repo, badgePath, ref), '--jq', '.content']).trim();
    if (!result) return null;
    const decoded = Buffer.from(result, 'base64').toString('utf-8');
    const badge = JSON.parse(decoded);
    const match = badge.message && badge.message.match(/(\d+)\s*\/\s*100/);
    return match ? parseInt(match[1], 10) : null;
  } catch {
    // Badge doesn't exist on base ref yet - no diff to show
    return null;
  }
}

function postOrUpdateComment(commentBody) {
  const payloadFile = path.join(tmpDir, `vice-comment-${Date.now()}.json`);
  fs.writeFileSync(payloadFile, JSON.stringify({ body: commentBody }));

  let existingId = null;
  try {
    const raw = githubApi([`repos/${repo}/issues/${prNumber}/comments`, '--paginate', '--slurp']);
    const comments = JSON.parse(raw).flat();
    const existing = Array.isArray(comments)
      ? comments.find(c => c && c.user?.type === 'Bot' && Number.isSafeInteger(c.id) && typeof c.body === 'string' && c.body.startsWith(MARKER))
      : null;
    if (existing) existingId = existing.id;
  } catch (err) {
    console.error('vice-action: failed to list comments');
  }

  try {
    if (existingId) {
      githubApi([`repos/${repo}/issues/comments/${existingId}`, '--input', payloadFile, '-X', 'PATCH']);
      console.log(`vice-action: updated comment #${existingId}`);
    } else {
      githubApi([`repos/${repo}/issues/${prNumber}/comments`, '--input', payloadFile, '-X', 'POST']);
      console.log('vice-action: created new PR comment');
    }
  } catch (err) {
    console.error('vice-action: failed to post comment.');
    console.error('Make sure the workflow has `pull-requests: write` permission.');
    // Best-effort: do not fail the action
  } finally {
    try { fs.unlinkSync(payloadFile); } catch {}
  }
}
