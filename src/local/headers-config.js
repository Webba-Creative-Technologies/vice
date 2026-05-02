// ──────────────────────────────────────────────
// VICE LOCAL — Security Headers Config Audit
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

  let cspFound = false, hstsFound = false;

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

      if (/next\.config/i.test(filename) && !/poweredByHeader\s*:\s*false/i.test(content)) {
        addFinding('MEDIUM', 'Headers Config', `X-Powered-By not disabled in ${rel}`, 'Next.js exposes X-Powered-By header by default', 'Add to next.config.js:\n  poweredByHeader: false');
      }

      if (/nuxt\.config/i.test(filename) && !cspFound) {
        addFinding('HIGH', 'Headers Config', `No CSP configured in ${rel}`, 'Nuxt does not add Content-Security-Policy by default', 'Add to nuxt.config:\n  routeRules: { \'/**\': { headers: { \'Content-Security-Policy\': "default-src \'self\'" } } }');
      }

      if (filename === 'vercel.json' && !/headers/i.test(content)) {
        addFinding('MEDIUM', 'Headers Config', 'No security headers in vercel.json', '', 'Add a headers section in vercel.json');
      }
    }
  }

  // .htaccess files (Apache)
  const htaccessPaths = ['', 'public', 'dist'].map(d => path.join(projectPath, d, '.htaccess'));
  for (const filePath of htaccessPaths) {
    let content;
    try { content = await fs.promises.readFile(filePath, 'utf-8'); } catch { continue; }
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

  if (!cspFound) addFinding('HIGH', 'Headers Config', 'No CSP configuration found in project', 'Content-Security-Policy is not configured anywhere', 'Add CSP in your server or framework configuration');
  if (!hstsFound) addFinding('HIGH', 'Headers Config', 'No HSTS configuration found in project', 'Strict-Transport-Security is not configured anywhere', 'Add HSTS in your server configuration');
}
