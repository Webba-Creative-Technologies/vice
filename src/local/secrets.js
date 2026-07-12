// ──────────────────────────────────────────────
// VICE LOCAL - Secrets in Source Code
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import { addFinding } from '../core/findings.js';
import { isPlaceholderSecret, SECRET_PATTERNS } from '../utils/patterns.js';
import { isInComment, isMarkdownFile } from '../utils/comments.js';

const BINARY_EXT = new Set(['.png', '.jpg', '.jpeg', '.gif', '.ico', '.woff', '.woff2', '.ttf', '.eot', '.mp4', '.mp3', '.zip', '.gz', '.tar', '.pdf', '.lock']);

async function walkDir(dir, ignore = []) {
  const results = [];
  const defaultIgnore = ['node_modules', '.git', '.next', '.nuxt', '.output', 'dist', 'build', '.cache', 'coverage', 'scans'];
  const allIgnore = [...defaultIgnore, ...ignore];
  async function walk(currentDir) {
    let entries;
    try { entries = await fs.promises.readdir(currentDir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      if (allIgnore.includes(entry.name)) continue;
      const fullPath = path.join(currentDir, entry.name);
      if (entry.isDirectory()) await walk(fullPath);
      else if (entry.isFile()) {
        const ext = path.extname(entry.name).toLowerCase();
        if (BINARY_EXT.has(ext)) continue;
        try {
          const stat = await fs.promises.stat(fullPath);
          if (stat.size < 500000) results.push(fullPath);
        } catch {}
      }
    }
  }
  await walk(dir);
  return results;
}

export async function auditSecrets(projectPath, spinner, isIgnored = () => false) {
  spinner.text = 'Scanning source code for secrets...';
  const files = await walkDir(projectPath);
  let found = 0;
  const seenValues = new Set();

  for (const filePath of files) {
    spinner.text = `Secrets: ${path.relative(projectPath, filePath)}`;
    let content;
    try { content = await fs.promises.readFile(filePath, 'utf-8'); } catch { continue; }
    const relativePath = path.relative(projectPath, filePath);
    if (isIgnored(relativePath)) continue;

    for (const pattern of SECRET_PATTERNS) {
      pattern.regex.lastIndex = 0;
      let matchResult;

      while ((matchResult = pattern.regex.exec(content)) !== null) {
        const match = matchResult[0];
        const matchIndex = matchResult.index;
        if (match.length === 0) pattern.regex.lastIndex++;
        if (pattern.validate && !pattern.validate(match)) continue;
        if (isPlaceholderSecret(match)) continue;
        if (/Bearer\s+(xxx|token|your|example|test)/i.test(match)) continue;

        // Filter out environment variable references (not actual secrets)
        if (/process\.env\.|import\.meta\.env\.|os\.environ|getenv\(|ENV\[|System\.getenv/i.test(match)) continue;

        // Skip generic patterns in Markdown (high false-positive rate from doc snippets)
        if (isMarkdownFile(relativePath) && (pattern.name === 'Generic API Key' || pattern.name === 'Generic Secret' || pattern.name === 'Bearer Token')) continue;

        // Locate the match in source and skip if inside a comment
        if (isInComment(content, matchIndex, relativePath)) continue;

        // Generic patterns: skip if the line references an env var or config getter
        if (pattern.name === 'Generic API Key' || pattern.name === 'Generic Secret') {
          const lineStart = content.lastIndexOf('\n', matchIndex) + 1;
          const lineEnd = content.indexOf('\n', matchIndex);
          const lineContent = content.substring(lineStart, lineEnd === -1 ? content.length : lineEnd);
          if (/process\.env|import\.meta\.env|os\.environ|getenv|ENV\[|System\.getenv|config\(|Config\./i.test(lineContent)) continue;
        }

        if (seenValues.has(match)) continue;
        seenValues.add(match);

        const lineNum = content.substring(0, matchIndex).split('\n').length;

        let sev = 'HIGH';
        if (pattern.name.includes('Private') || pattern.name === 'Stripe Secret Key' || pattern.name === 'AWS Secret Key' || pattern.name === 'Database Credential URL') sev = 'CRITICAL';
        else if (pattern.name.includes('Publishable') || pattern.name === 'Firebase API Key') sev = 'INFO';
        else if (pattern.name === 'Supabase Service Role') sev = 'CRITICAL';

        const isEnvFile = /\.env/.test(relativePath);
        if (isEnvFile && sev !== 'CRITICAL') continue;

        const fix = sev === 'CRITICAL'
          ? `Move to .env.local and use process.env.${pattern.name.toUpperCase().replace(/\s+/g, '_')}`
          : 'Verify this value should not be in environment variables';

        const location = lineNum > 0 ? { file: relativePath, line: lineNum } : { file: relativePath };

        // Confidence: heuristic patterns are low, specific high-entropy keys are high
        let confidence = 'medium';
        if (pattern.name === 'Generic API Key' || pattern.name === 'Generic Secret' || pattern.name === 'Bearer Token') {
          confidence = 'low';
        } else if (sev === 'CRITICAL') {
          confidence = 'high';
        }

        addFinding(sev, 'Code Secrets', `${pattern.name} in ${relativePath}:${lineNum}`, `Value: ${match}`, fix, location, confidence);
        found++;
      }
    }
  }

  if (found === 0) {
    addFinding('INFO', 'Code Secrets', 'No secrets found in source code', `${files.length} files scanned`, '');
  }
}
