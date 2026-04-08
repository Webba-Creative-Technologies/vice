// ──────────────────────────────────────────────
// VICE LOCAL — Auth & Middleware Audit
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import { addFinding } from '../core/findings.js';

function findFiles(dir, extensions, ignore = ['node_modules', '.git', '.next', '.nuxt', 'dist', 'build', '.output', 'coverage', 'scans']) {
  const results = [];
  function walk(d) {
    let entries;
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      if (ignore.includes(entry.name)) continue;
      const full = path.join(d, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (extensions.some(ext => entry.name.endsWith(ext))) results.push(full);
    }
  }
  walk(dir);
  return results;
}

export async function auditAuth(projectPath, spinner, isIgnored = () => false) {
  spinner.text = 'Auditing auth & middleware configuration...';
  const codeFiles = findFiles(projectPath, ['.js', '.ts', '.jsx', '.tsx', '.vue', '.svelte']);

  let hasRateLimit = false, hasCors = false, hasCsrf = false, hasHelmet = false, hasAuthMiddleware = false;

  const pkgPath = path.join(projectPath, 'package.json');
  let deps = {};
  if (fs.existsSync(pkgPath)) {
    try {
      const pkg = JSON.parse(fs.readFileSync(pkgPath, 'utf-8'));
      deps = { ...pkg.dependencies, ...pkg.devDependencies };
    } catch {}
  }

  if (deps['helmet']) hasHelmet = true;
  if (deps['express-rate-limit'] || deps['rate-limiter-flexible'] || deps['limiter']) hasRateLimit = true;
  if (deps['cors']) hasCors = true;
  if (deps['csurf'] || deps['csrf']) hasCsrf = true;

  for (const filePath of codeFiles) {
    let content;
    try { content = fs.readFileSync(filePath, 'utf-8'); } catch { continue; }
    const rel = path.relative(projectPath, filePath);

    if (/rateLimit|rate.?limit|throttle|RateLimiter/i.test(content)) hasRateLimit = true;

    if (/cors\(|Access-Control-Allow-Origin|allowedOrigins/i.test(content)) {
      hasCors = true;
      if (!isIgnored(rel) && /origin:\s*['"]?\*['"]?|Access-Control-Allow-Origin.*\*/i.test(content)) {
        addFinding('HIGH', 'Auth & Middleware', `CORS wildcard origin:'*' in ${rel}`, 'Allowing all origins lets any website call your API with user cookies', `Replace with a whitelist:\n  origin: ['https://your-domain.com']`);
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

    if (!/test|example|placeholder|mock|fixture|i18n|locales?|translations?|lang|languages/i.test(rel) && !isIgnored(rel)) {
      const pwRegex = /password\s*[:=]\s*["']([^"']{4,})["']/gi;
      let pwMatch;
      while ((pwMatch = pwRegex.exec(content)) !== null) {
        const val = pwMatch[1];
        if (/\s/.test(val)) continue;
        if (/^password$/i.test(val)) continue;
        if (/^[\p{Lu}][\p{Ll}]+$/u.test(val)) continue;
        addFinding('CRITICAL', 'Auth & Middleware', `Hardcoded password in ${rel}`, 'A password is hardcoded in source code', 'Move to environment variables');
        break;
      }
    }
  }

  if (!hasRateLimit) addFinding('HIGH', 'Auth & Middleware', 'No rate limiting detected', 'No rate limiting package or code found.\nEndpoints are vulnerable to brute force attacks.', 'Install express-rate-limit or equivalent:\n  npm install express-rate-limit');
  if (!hasCsrf) addFinding('MEDIUM', 'Auth & Middleware', 'No CSRF protection detected', 'Forms may be vulnerable to CSRF attacks.', 'Implement CSRF protection or verify your framework handles it (Nuxt/Next validate Origin headers)');
  if (!hasHelmet && deps['express']) addFinding('MEDIUM', 'Auth & Middleware', 'Helmet not installed (Express project)', 'Helmet automatically sets security headers', 'npm install helmet && app.use(helmet())');
  if (!hasAuthMiddleware) addFinding('INFO', 'Auth & Middleware', 'No auth middleware detected in code', 'Auth may be handled by Supabase/Auth0/external service', '');
}
