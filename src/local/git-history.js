// ──────────────────────────────────────────────
// VICE LOCAL — Git History Secret Scan
// Scans recent commits for previously committed secrets that may still be
// recoverable from git history even after being removed from current files.
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import { spawn } from 'child_process';
import { addFinding } from '../core/findings.js';
import { SECRET_PATTERNS } from '../utils/patterns.js';

// Async spawn wrapper: collects stdout, returns { code, stdout, error }.
// No shell, args are passed directly so there's no command-injection surface.
function spawnAsync(cmd, args, opts = {}) {
  return new Promise((resolve) => {
    let proc;
    try {
      proc = spawn(cmd, args, { ...opts, stdio: ['ignore', 'pipe', 'ignore'] });
    } catch (err) {
      resolve({ code: -1, stdout: '', error: err });
      return;
    }
    let chunks = [];
    let totalSize = 0;
    const maxBuffer = opts.maxBuffer || 50 * 1024 * 1024;
    let killed = false;
    proc.stdout.on('data', (chunk) => {
      if (killed) return;
      totalSize += chunk.length;
      if (totalSize > maxBuffer) {
        killed = true;
        chunks = []; // release accumulated buffers, let GC reclaim them
        proc.kill('SIGKILL');
        return;
      }
      chunks.push(chunk);
    });
    proc.on('error', (err) => resolve({ code: -1, stdout: killed ? '' : Buffer.concat(chunks).toString('utf-8'), error: err }));
    proc.on('close', (code) => resolve({ code, stdout: killed ? '' : Buffer.concat(chunks).toString('utf-8'), error: killed ? new Error('output exceeded maxBuffer') : null }));
  });
}

// Only the patterns confident enough to scan history without noise.
// Generic API Key / Generic Secret / Bearer Token are too loose for this.
const HIGH_CONF_PATTERN_NAMES = new Set([
  'Stripe Secret Key',
  'Stripe Publishable Key',
  'AWS Access Key',
  'AWS Secret Key',
  'Firebase API Key',
  'GitHub Token',
  'Supabase Service Role',
  'Supabase Anon Key',
  'Private Key',
  'Google OAuth',
]);

const PLACEHOLDER_REGEX = /your_|example|placeholder|xxx|yyy|zzz|changeme|replace_|INSERT_|TODO|FIXME|sk_test_|pk_test_/i;
const ENV_REF_REGEX = /process\.env\.|import\.meta\.env\.|os\.environ|getenv\(|System\.getenv/i;

export async function auditGitHistory(projectPath, spinner) {
  const gitDir = path.join(projectPath, '.git');
  if (!fs.existsSync(gitDir)) {
    addFinding('INFO', 'Git History', 'Not a git repository - history scan skipped', '', '');
    return;
  }

  if (process.env.VICE_SKIP_GIT_HISTORY === '1') {
    addFinding('INFO', 'Git History', 'Skipped via VICE_SKIP_GIT_HISTORY=1', '', '');
    return;
  }

  const maxCommits = parseInt(process.env.VICE_GIT_HISTORY_DEPTH || '500');
  spinner.text = `Scanning last ${maxCommits} commits for committed secrets...`;

  // Async spawn: lets other modules run while git log streams its (potentially huge) patch output
  const result = await spawnAsync('git', ['log', '--all', '-p', `--max-count=${maxCommits}`], {
    cwd: projectPath,
    maxBuffer: 200 * 1024 * 1024,
    windowsHide: true,
  });

  if (result.error || result.code !== 0) {
    addFinding('INFO', 'Git History', 'Unable to read git history',
      String((result.error && result.error.message) || `exit code ${result.code}`).substring(0, 200),
      'Verify git is installed and the directory is a valid repository');
    return;
  }

  const logOutput = result.stdout;

  if (!logOutput || logOutput.trim().length === 0) {
    addFinding('INFO', 'Git History', 'Empty git history', '', '');
    return;
  }

  // Split on `commit <40-hex>` boundaries. With capture group, parts alternate:
  // ['', sha1, content1, sha2, content2, ...]
  const parts = logOutput.split(/^commit ([a-f0-9]{40})\s*$/m);
  const seenSecrets = new Map();
  let secretsFound = 0;
  let commitCount = 0;

  for (let i = 1; i < parts.length; i += 2) {
    const sha = parts[i];
    const content = parts[i + 1] || '';
    commitCount++;

    const authorMatch = content.match(/^Author:\s*(.+)$/m);
    const dateMatch = content.match(/^Date:\s*(.+)$/m);
    const author = authorMatch ? authorMatch[1].trim() : 'unknown';
    const date = dateMatch ? dateMatch[1].trim() : 'unknown';

    for (const pattern of SECRET_PATTERNS) {
      if (!HIGH_CONF_PATTERN_NAMES.has(pattern.name)) continue;

      const matches = content.match(pattern.regex);
      if (!matches) continue;

      for (const match of matches) {
        if (PLACEHOLDER_REGEX.test(match)) continue;
        if (ENV_REF_REGEX.test(match)) continue;
        if (seenSecrets.has(match)) continue;

        seenSecrets.set(match, { sha: sha.slice(0, 7), author, date });

        let sev = 'HIGH';
        if (pattern.name === 'Stripe Secret Key' || pattern.name === 'AWS Secret Key' ||
            pattern.name === 'Supabase Service Role' || pattern.name.includes('Private')) sev = 'CRITICAL';
        else if (pattern.name.includes('Publishable') || pattern.name === 'Supabase Anon Key' ||
                 pattern.name === 'Firebase API Key' || pattern.name === 'Google OAuth') sev = 'INFO';

        const confidence = sev === 'CRITICAL' || sev === 'HIGH' ? 'high' : 'medium';

        addFinding(
          sev,
          'Git History',
          `${pattern.name} found in commit ${sha.slice(0, 7)}`,
          `Value: ${match}\nCommit: ${sha.slice(0, 7)} by ${author} on ${date}\nThis secret was committed and remains recoverable from git history even if removed from current files.`,
          `Rotate this credential immediately. To purge from history, use git-filter-repo or BFG Repo Cleaner, then force-push (after coordinating with the team).`,
          undefined,
          confidence
        );
        secretsFound++;
      }
    }
  }

  if (secretsFound === 0) {
    addFinding('INFO', 'Git History', `No secrets in last ${commitCount} commits`, 'Increase VICE_GIT_HISTORY_DEPTH to scan further back, or set VICE_SKIP_GIT_HISTORY=1 to skip this module.', '');
  } else {
    addFinding('INFO', 'Git History', `${secretsFound} unique secret(s) across ${commitCount} commits scanned`, '', '');
  }
}
