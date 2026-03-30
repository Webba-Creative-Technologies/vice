// ──────────────────────────────────────────────
// VICE LOCAL — Code Vulnerability Scanner
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

function getLineNum(content, position) {
  return content.substring(0, position).split('\n').length;
}

export async function auditCodeVulnerabilities(projectPath, spinner) {
  spinner.text = 'Scanning code for vulnerabilities...';
  const codeFiles = findFiles(projectPath, ['.js', '.ts', '.jsx', '.tsx', '.vue', '.svelte']);

  for (const filePath of codeFiles) {
    let content;
    try { content = fs.readFileSync(filePath, 'utf-8'); } catch { continue; }
    const rel = path.relative(projectPath, filePath);
    if (/test|spec|mock|fixture|__test__|\.test\.|\.spec\./i.test(rel)) continue;

    // SQL Injection
    const sqlPatterns = [
      { regex: /(?:query|execute|raw|sql)\s*\(\s*`[^`]*\$\{/gi, name: 'Template literal in SQL query' },
      { regex: /(?:query|execute|raw)\s*\(\s*['"][^'"]*['"]\s*\+/gi, name: 'String concatenation in SQL query' },
      { regex: /(?:WHERE|AND|OR)\s+\w+\s*=\s*['"]?\s*\$\{/gi, name: 'Interpolated variable in WHERE clause' },
    ];

    for (const { regex, name } of sqlPatterns) {
      let match;
      while ((match = regex.exec(content)) !== null) {
        const line = getLineNum(content, match.index);
        const context = content.substring(match.index, match.index + 80).replace(/\n/g, ' ');
        addFinding('CRITICAL', 'Code Vulnerabilities', `SQL Injection: ${name}`, `${rel}:${line}\n  ${context}`, 'Use prepared statements with parameters ($1, ?) instead of concatenation/interpolation');
      }
    }

    // XSS — dangerouslySetInnerHTML
    let match;
    const dangerousHtml = /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/g;
    while ((match = dangerousHtml.exec(content)) !== null) {
      addFinding('HIGH', 'Code Vulnerabilities', `dangerouslySetInnerHTML in ${rel}:${getLineNum(content, match.index)}`, 'Raw HTML injection — XSS risk if data comes from user input', 'Use DOMPurify to sanitize:\n  dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(data) }}');
    }

    // XSS — v-html
    const vHtml = /v-html\s*=\s*["']([^"']+)["']/g;
    while ((match = vHtml.exec(content)) !== null) {
      addFinding('HIGH', 'Code Vulnerabilities', `v-html in ${rel}:${getLineNum(content, match.index)}`, `Variable: ${match[1]}\nv-html injects raw HTML — XSS risk if data comes from user input`, 'Use {{ }} for text content, or sanitize:\n  v-html="DOMPurify.sanitize(data)"');
    }

    // innerHTML
    const innerHtml = /\.innerHTML\s*=(?!=)/g;
    while ((match = innerHtml.exec(content)) !== null) {
      addFinding('HIGH', 'Code Vulnerabilities', `innerHTML in ${rel}:${getLineNum(content, match.index)}`, 'Direct DOM manipulation via innerHTML — XSS risk', 'Use textContent instead of innerHTML, or sanitize the HTML');
    }

    // eval / new Function
    const evalPattern = /\beval\s*\(|new\s+Function\s*\(/g;
    while ((match = evalPattern.exec(content)) !== null) {
      addFinding('HIGH', 'Code Vulnerabilities', `eval() or new Function() in ${rel}:${getLineNum(content, match.index)}`, 'eval/Function executes arbitrary code — injection vector', 'Refactor to avoid eval(). Use JSON.parse() for data, named functions for logic.');
    }

    // Command Injection
    const cmdInjection = /(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+)/g;
    while ((match = cmdInjection.exec(content)) !== null) {
      addFinding('CRITICAL', 'Code Vulnerabilities', `Command injection in ${rel}:${getLineNum(content, match.index)}`, 'User input potentially injected into shell command', 'Use execFile() with separate arguments instead of exec() with concatenation');
    }

    // Open Redirect
    const openRedirect = /(?:redirect|location\.href|window\.location)\s*=\s*(?:req\.query|req\.params|req\.body|searchParams|params)/g;
    while ((match = openRedirect.exec(content)) !== null) {
      addFinding('HIGH', 'Code Vulnerabilities', `Open redirect in ${rel}:${getLineNum(content, match.index)}`, 'Redirect based on user parameter without validation', 'Validate redirect URL:\n  const url = new URL(redirect, baseUrl);\n  if (url.origin !== baseUrl) throw new Error(\'Invalid redirect\');');
    }

    // Weak crypto
    const weakCrypto = /createHash\s*\(\s*['"](?:md5|sha1)['"]|crypto\.(?:MD5|SHA1)/g;
    while ((match = weakCrypto.exec(content)) !== null) {
      addFinding('MEDIUM', 'Code Vulnerabilities', `Weak hash algorithm in ${rel}:${getLineNum(content, match.index)}`, 'MD5/SHA1 are not considered secure for hashing sensitive data', 'Use SHA-256 or bcrypt/argon2 for passwords');
    }

    // ReDoS
    const regexPattern = /new\s+RegExp\s*\(\s*(?:req\.|params\.|query\.|body\.)/g;
    while ((match = regexPattern.exec(content)) !== null) {
      addFinding('HIGH', 'Code Vulnerabilities', `Potential ReDoS in ${rel}:${getLineNum(content, match.index)}`, 'RegExp built from user input — denial of service risk', 'Never build RegExp from user input. Use escape-string-regexp library.');
    }
  }
}
