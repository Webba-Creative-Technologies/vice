// ──────────────────────────────────────────────
// VICE LOCAL - Security Headers Config Audit
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import { addFinding } from '../core/findings.js';

export async function auditHeadersConfig(projectPath, spinner) {
  spinner.text = 'Checking security headers configuration...';

  const configFiles = {
    'nuxt.config.ts': 'nuxt', 'nuxt.config.js': 'nuxt',
    'next.config.js': 'next', 'next.config.mjs': 'next', 'next.config.ts': 'next',
    'vercel.json': 'vercel', 'netlify.toml': 'netlify',
    'nginx.conf': 'nginx', '_headers': 'netlify',
    'server.js': 'express', 'server.ts': 'express',
    'app.js': 'express', 'app.ts': 'express',
  };

  let cspFound = false, hstsFound = false, headerLayerFound = false;

  for (const [filename, framework] of Object.entries(configFiles)) {
    const searchPaths = [
      path.join(projectPath, filename),
      path.join(projectPath, 'server', filename),
      path.join(projectPath, 'config', filename),
    ];

    for (const filePath of searchPaths) {
      let content;
      try { content = await fs.promises.readFile(filePath, 'utf-8'); } catch { continue; }
      const rel = path.relative(projectPath, filePath);

      if (/Content-Security-Policy|contentSecurityPolicy|csp/i.test(content)) cspFound = true;
      if (/Strict-Transport-Security|hsts/i.test(content)) hstsFound = true;
      if (framework === 'nginx' || framework === 'netlify' || /(?:headers\s*[:(]|setHeader\s*\(|helmet\s*\()/i.test(content)) {
        headerLayerFound = true;
      }

      if (/next\.config/i.test(filename) && !/poweredByHeader\s*:\s*false/i.test(content)) {
        addFinding('INFO', 'Headers Config', `Next.js framework header is enabled in ${rel}`, 'The default X-Powered-By header reveals the framework.', 'Set poweredByHeader: false if this disclosure is not useful.', { file: rel }, 'high', { rule_id: 'vice/headers/framework-disclosure', classification: 'hardening' });
      }
    }
  }

  // .htaccess files (Apache)
  const htaccessPaths = ['', 'public', 'dist'].map(d => path.join(projectPath, d, '.htaccess'));
  for (const filePath of htaccessPaths) {
    let content;
    try { content = await fs.promises.readFile(filePath, 'utf-8'); } catch { continue; }
    headerLayerFound = true;
    if (/Header\s+(set|always\s+set)\s+Content-Security-Policy/i.test(content)) cspFound = true;
    if (/Header\s+(set|always\s+set)\s+Strict-Transport-Security/i.test(content)) hstsFound = true;
  }

  // <meta http-equiv> in HTML files
  const htmlPaths = ['', 'public', 'dist', 'src'].map(d => path.join(projectPath, d, 'index.html'));
  for (const filePath of htmlPaths) {
    let content;
    try { content = await fs.promises.readFile(filePath, 'utf-8'); } catch { continue; }
    if (/<meta\s+http-equiv\s*=\s*["']Content-Security-Policy["']/i.test(content)) cspFound = true;
    if (/<meta\s+http-equiv\s*=\s*["']Strict-Transport-Security["']/i.test(content)) hstsFound = true;
  }

  if (headerLayerFound && !cspFound) {
    addFinding('INFO', 'Headers Config', 'CSP not found in the inspected header layer', 'A server or deployment header configuration was found, but it does not define Content-Security-Policy.', 'Consider adding CSP after validating the application resource policy.', undefined, 'high', { rule_id: 'vice/headers/local-csp-hardening', classification: 'hardening' });
  }
  if (headerLayerFound && !hstsFound) {
    addFinding('INFO', 'Headers Config', 'HSTS not found in the inspected header layer', 'A server or deployment header configuration was found, but it does not define Strict-Transport-Security.', 'If HTTPS is enforced at this layer, consider adding HSTS.', undefined, 'high', { rule_id: 'vice/headers/local-hsts-hardening', classification: 'hardening' });
  }
}
