// ──────────────────────────────────────────────
// VICE LOCAL — Secrets in Source Code
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import { addFinding } from '../core/findings.js';
import { SECRET_PATTERNS } from '../utils/patterns.js';

const BINARY_EXT = new Set(['.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.zip', '.gz', '.tar', '.pdf', '.lock']);

function walkDir(dir, ignore = []) {
  const results = [];
  const defaultIgnore = ['node_modules', '.git', '.next', '.nuxt', '.output', 'dist', 'build', '.cache', 'coverage', 'scans'];
  const allIgnore = [...defaultIgnore, ...ignore];
  function walk(currentDir) {
    let entries;
    try { entries = fs.readdirSync(currentDir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      if (allIgnore.includes(entry.name)) continue;
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) walk(fullPath);
      else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (!BINARY_EXT.has(ext) && fs.statSync(fullPath).size < 500000) results.push(fullPath);
      }
    }
  }
  walk(dir);
  return results;
}

export async function auditSecrets(projectPath, spinner, isIgnored = () => false) {
  spinner.text = 'Scanning source code for secrets...';
  const files = walkDir(projectPath);
  let found = 0;
  const seenValues = new Set();

  for (const filePath of files) {
    spinner.text = `Secrets: ${path.relative(projectPath, filePath)}`;
    let content;
    try { content = fs.readFileSync(filePath, 'utf-8'); } catch { continue; }
    const relativePath = path.relative(projectPath, filePath);
    if (isIgnored(relativePath)) continue;

    for (const pattern of SECRET_PATTERNS) {
      const matches = content.match(pattern.regex);
      if (!matches) continue;

      for (const match of matches) {
        if (/your_|example|placeholder|xxx|yyy|zzz|changeme|replace_|INSERT_|TODO|FIXME|sk_test_|pk_test_/i.test(match)) continue;
        if (/Bearer\s+(xxx|token|your|example|test)/i.test(match)) continue;

        // Filter out environment variable references (not actual secrets)
        if (/process\.env\.|import\.meta\.env\.|os\.environ|getenv\(|ENV\[|System\.getenv/i.test(match)) continue;

        // For Generic patterns, check the full line for env var context
        if (pattern.name === 'Generic API Key' || pattern.name === 'Generic Secret') {
          const matchIndex = content.indexOf(match);
          if (matchIndex !== -1) {
            const lineStart = content.lastIndexOf('\n', matchIndex) + 1;
            const lineEnd = content.indexOf('\n', matchIndex + match.length);
            const line = content.substring(lineStart, lineEnd === -1 ? undefined : lineEnd);
            if (/process\.env|import\.meta\.env|os\.environ|getenv|ENV\[|System\.getenv|config\(|Config\./i.test(line)) continue;
          }
        }

        if (seenValues.has(match)) continue;
        seenValues.add(match);

        const lines = content.split('\n');
        let lineNum = 0;
        for (let i = 0; i < lines.length; i++) {
          if (lines[i].includes(match.substring(0, 30))) { lineNum = i + 1; break; }
        }

        let sev = 'HIGH';
        if (pattern.name.includes('Private') || pattern.name === 'Stripe Secret Key' || pattern.name === 'AWS Secret Key') sev = 'CRITICAL';
        else if (pattern.name.includes('Publishable') || pattern.name === 'Supabase URL' || pattern.name === 'Firebase API Key') sev = 'INFO';
        else if (pattern.name === 'Supabase Service Role') sev = 'CRITICAL';

        const isEnvFile = /\.env/.test(relativePath);
        if (isEnvFile && sev !== 'CRITICAL') continue;

        const fix = sev === 'CRITICAL'
          ? `Move to .env.local and use process.env.${pattern.name.toUpperCase().replace(/\s+/g, '_')}`
          : 'Verify this value should not be in environment variables';

        const location = lineNum > 0 ? { file: relativePath, line: lineNum } : { file: relativePath };
        addFinding(sev, 'Code Secrets', `${pattern.name} in ${relativePath}:${lineNum}`, `Value: ${match}`, fix, location);
        found++;
      }
    }
  }

  if (found === 0) {
    addFinding('INFO', 'Code Secrets', 'No secrets found in source code', `${files.length} files scanned`, '');
  }
}
