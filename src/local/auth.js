// ──────────────────────────────────────────────
// VICE LOCAL — Auth & Middleware Audit
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import { addFinding } from '../core/findings.js';
import { isInComment } from '../utils/comments.js';

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

  let hasRateLimit = false, hasCors = false, hasCsrf = false, hasHelmet = false, hasAuthMiddleware = false;

  const pkgPath = path.join(projectPath, 'package.json');
  let deps = {};
  try {
    const pkg = JSON.parse(await fs.promises.readFile(pkgPath, 'utf-8'));
    deps = { ...pkg.dependencies, ...pkg.devDependencies };
  } catch {}

  if (deps['helmet']) hasHelmet = true;
  if (deps['express-rate-limit'] || deps['rate-limiter-flexible'] || deps['limiter']) hasRateLimit = true;
  if (deps['cors']) hasCors = true;
  if (deps['csurf'] || deps['csrf']) hasCsrf = true;

  for (const filePath of codeFiles) {
    let content;
    try { content = await fs.promises.readFile(filePath, 'utf-8'); } catch { continue; }
    const rel = path.relative(projectPath, filePath);

    if (/rateLimit|rate.?limit|throttle|RateLimiter/i.test(content)) hasRateLimit = true;

    if (/cors\(|Access-Control-Allow-Origin|allowedOrigins/i.test(content)) {
      hasCors = true;
      if (!isIgnored(rel) && /origin:\s*['"]?\*['"]?|Access-Control-Allow-Origin.*\*/i.test(content)) {
        addFinding('HIGH', 'Auth & Middleware', `CORS wildcard origin:'*' in ${rel}`, 'Allowing all origins lets any website call your API with user cookies', `Replace with a whitelist:\n  origin: ['https://your-domain.com']`, { file: rel });
      }
    }

    if (/csrf|csrfToken|_token|x-csrf/i.test(content)) hasCsrf = true;
    if (/auth.*middleware|middleware.*auth|isAuthenticated|requireAuth|verifyToken|jwt\.verify/i.test(content)) hasAuthMiddleware = true;

    if (/session\s*\(\s*\{/i.test(content)) {
      if (/secure\s*:\s*false/i.test(content)) {
        addFinding('HIGH', 'Auth & Middleware', `Insecure session cookie in ${rel}`, 'secure: false — session cookie sent over plain HTTP', 'Set secure: true in production');
      }
      if (!/httpOnly/i.test(content)) {
        addFinding('HIGH', 'Auth & Middleware', `Session without httpOnly in ${rel}`, 'Session cookie accessible via JavaScript (XSS risk)', 'Add httpOnly: true to session config');
      }
    }

    if (/jwt\.sign\s*\(/i.test(content) && !/expiresIn|exp/i.test(content)) {
      addFinding('HIGH', 'Auth & Middleware', `JWT without expiration in ${rel}`, 'A JWT without expiration is valid forever if stolen', 'Add expiresIn: \'1h\' or \'7d\' to jwt.sign() options');
    }

    if (!/test|spec|example|sample|placeholder|mock|fixture|e2e|cypress|playwright|seed|seeds|demo|stories|storybook|i18n|locales?|translations?|lang|languages|\.cy\.|\.pw\./i.test(rel) && !isIgnored(rel)) {
      const pwRegex = /password\s*[:=]\s*["']([^"']{4,})["']/gi;
      let pwMatch;
      while ((pwMatch = pwRegex.exec(content)) !== null) {
        if (isInComment(content, pwMatch.index, rel)) continue;
        const val = pwMatch[1];
        if (/\s/.test(val)) continue;
        if (/^password$/i.test(val)) continue;
        if (/^[\p{Lu}][\p{Ll}]+$/u.test(val)) continue;
        const pwLine = content.substring(0, pwMatch.index).split('\n').length;
        addFinding('CRITICAL', 'Auth & Middleware', `Hardcoded password in ${rel}`, 'A password is hardcoded in source code', 'Move to environment variables', { file: rel, line: pwLine });
        break;
      }
    }
  }

  if (!hasRateLimit) addFinding('HIGH', 'Auth & Middleware', 'No rate limiting detected', 'No rate limiting package or code found.\nEndpoints are vulnerable to brute force attacks.', 'Install express-rate-limit or equivalent:\n  npm install express-rate-limit');
  if (!hasCsrf) addFinding('MEDIUM', 'Auth & Middleware', 'No CSRF protection detected', 'Forms may be vulnerable to CSRF attacks.', 'Implement CSRF protection or verify your framework handles it (Nuxt/Next validate Origin headers)');
  if (!hasHelmet && deps['express']) addFinding('MEDIUM', 'Auth & Middleware', 'Helmet not installed (Express project)', 'Helmet automatically sets security headers', 'npm install helmet && app.use(helmet())');
  if (!hasAuthMiddleware) addFinding('INFO', 'Auth & Middleware', 'No auth middleware detected in code', 'Auth may be handled by Supabase/Auth0/external service', '');
}
