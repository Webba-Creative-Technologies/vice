// ──────────────────────────────────────────────
// VICE LOCAL - Auth & Middleware Audit
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import { addFinding } from '../core/findings.js';
import { isInComment } from '../utils/comments.js';
import { isLikelyGenericSecret, isPlaceholderSecret } from '../utils/patterns.js';

function isNonProductionFile(relativePath) {
  return /(^|[\\/])(?:__tests__|test|tests|spec|specs|fixtures?|mocks?|examples?|samples?|demos?|docs?|stories|storybook|cypress|playwright|e2e|seeds?|i18n|locales?|translations?|lang|languages)([\\/]|$)|\.(?:test|spec|cy|pw)\.[^.]+$/i.test(relativePath);
}

async function findFiles(dir, extensions, ignore = ['node_modules', '.git', '.next', '.nuxt', 'dist', 'build', '.output', 'coverage', 'scans']) {
  const results = [];
  async function walk(d) {
    let entries;
    try { entries = await fs.promises.readdir(d, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      if (ignore.includes(entry.name)) continue;
      const full = path.join(d, entry.name);
      if (entry.isDirectory()) await walk(full);
      else if (extensions.some(ext => entry.name.endsWith(ext))) results.push(full);
    }
  }
  await walk(dir);
  return results;
}

export async function auditAuth(projectPath, spinner, isIgnored = () => false) {
  spinner.text = 'Auditing auth & middleware configuration...';
  const codeFiles = await findFiles(projectPath, ['.js', '.ts', '.jsx', '.tsx', '.vue', '.svelte']);

  for (const filePath of codeFiles) {
    let content;
    try { content = await fs.promises.readFile(filePath, 'utf-8'); } catch { continue; }
    const rel = path.relative(projectPath, filePath);
    if (isIgnored(rel) || isNonProductionFile(rel)) continue;

    if (/cors\(|Access-Control-Allow-Origin|allowedOrigins/i.test(content)) {
      const credentialsEnabled = /credentials\s*:\s*true|Access-Control-Allow-Credentials[^\n]*true/i.test(content);
      const reflectsAnyOrigin = /origin\s*:\s*true/i.test(content);
      if (reflectsAnyOrigin && credentialsEnabled) {
        addFinding('HIGH', 'Auth & Middleware', `Credentialed CORS reflects every origin in ${rel}`, 'The CORS configuration reflects arbitrary origins and permits credentials.', `Replace origin: true with an explicit origin allowlist.`, { file: rel }, 'high');
      }
    }

    if (/session\s*\(\s*\{/i.test(content)) {
      if (/secure\s*:\s*false/i.test(content)) {
        addFinding('MEDIUM', 'Auth & Middleware', `Session cookie explicitly allows HTTP in ${rel}`, 'The session cookie is configured with secure: false.', 'Enable secure cookies in production.', { file: rel }, 'high');
      }
      if (/httpOnly\s*:\s*false/i.test(content)) {
        addFinding('HIGH', 'Auth & Middleware', `Session cookie is accessible to scripts in ${rel}`, 'The session cookie is explicitly configured with httpOnly: false.', 'Set httpOnly: true for the session cookie.', { file: rel }, 'high');
      }
    }

    const inlineJwtCalls = content.match(/jwt\.sign\s*\([^;\n]{0,800}\)/gi) || [];
    for (const call of inlineJwtCalls) {
      const hasInlineOptions = /,\s*\{[\s\S]*\}\s*\)$/.test(call);
      if (hasInlineOptions && !/\b(?:expiresIn|exp)\s*:/i.test(call)) {
        const index = content.indexOf(call);
        if (index >= 0 && !isInComment(content, index, rel)) {
          const line = content.substring(0, index).split('\n').length;
          addFinding('MEDIUM', 'Auth & Middleware', `JWT has inline options without an expiration in ${rel}:${line}`, 'The token options are visible and do not set an expiration.', 'Set expiresIn in the jwt.sign options.', { file: rel, line }, 'medium');
        }
      }
    }

    const pwRegex = /password\s*[:=]\s*["']([^"']{4,})["']/gi;
    let pwMatch;
    while ((pwMatch = pwRegex.exec(content)) !== null) {
      if (isInComment(content, pwMatch.index, rel)) continue;
      const value = pwMatch[1];
      if (/\s/.test(value) || isPlaceholderSecret(`password=${value}`) || !isLikelyGenericSecret(value)) continue;
      const pwLine = content.substring(0, pwMatch.index).split('\n').length;
      addFinding('CRITICAL', 'Auth & Middleware', `Hardcoded password in ${rel}`, 'A password is hardcoded in source code.', 'Move the value to a secret store or environment variable.', { file: rel, line: pwLine }, 'high');
      break;
    }
  }
}
