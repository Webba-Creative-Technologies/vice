// ──────────────────────────────────────────────
// VICE LOCAL - Code Vulnerability Scanner
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import { addFinding } from '../core/findings.js';
import { classifyCodeSink } from '../core/detectors/code-sinks.js';
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

function getLineNum(content, position) {
  return content.substring(0, position).split('\n').length;
}

function statementAround(content, position, maxLength = 600) {
  const previousSemicolon = content.lastIndexOf(';', position);
  const previousBlock = content.lastIndexOf('\n\n', position);
  const start = Math.max(previousSemicolon, previousBlock, position - 120) + 1;
  const nextSemicolon = content.indexOf(';', position);
  const end = nextSemicolon === -1 ? position + maxLength : nextSemicolon + 1;
  return content.slice(start, Math.min(content.length, end, position + maxLength));
}

export async function auditCodeVulnerabilities(projectPath, spinner, isIgnored = () => false) {
  spinner.text = 'Scanning code for vulnerabilities...';
  const codeFiles = await findFiles(projectPath, ['.js', '.ts', '.jsx', '.tsx', '.vue', '.svelte']);

  for (const filePath of codeFiles) {
    let content;
    try { content = await fs.promises.readFile(filePath, 'utf-8'); } catch { continue; }
    const rel = path.relative(projectPath, filePath);
    if (/test|spec|mock|fixture|e2e|cypress|playwright|seed|seeds|demo|stories|storybook|\.test\.|\.spec\.|\.story\.|\.stories\.|\.cy\.|\.pw\./i.test(rel)) continue;
    if (isIgnored(rel)) continue;

    const seen = new Set();
    const reportOnce = (signal, ruleId, line, detail, recommendation) => {
      if (!signal || signal.classification === 'heuristic' || signal.classification === 'hardening') return;
      const family = ruleId.startsWith('sqli-') ? 'sqli' : ruleId;
      const key = `${family}:${line}`;
      if (seen.has(key)) return;
      seen.add(key);
      addFinding(
        signal.severity,
        'Code Vulnerabilities',
        `${signal.title} in ${rel}:${line}`,
        detail,
        recommendation,
        { file: rel, line },
        signal.confidence,
        { rule_id: `vice/code/${ruleId}`, classification: signal.classification },
      );
    };

    // SQL construction: direct request sources stay critical, while an
    // unproven dynamic identifier is kept as a low-confidence review signal.
    const sqlPatterns = [
      { regex: /(?:query|execute|raw|sql)\s*\(\s*`[^`]*\$\{/gi, name: 'Template literal in SQL query', id: 'sqli-template' },
      { regex: /(?:query|execute|raw)\s*\(\s*['"][^'"]*['"]\s*\+/gi, name: 'String concatenation in SQL query', id: 'sqli-concat' },
      { regex: /(?:WHERE|AND|OR)\s+\w+\s*=\s*['"]?\s*\$\{/gi, name: 'Interpolated variable in WHERE clause', id: 'sqli-where' },
    ];

    for (const { regex, name, id } of sqlPatterns) {
      let match;
      while ((match = regex.exec(content)) !== null) {
        if (isInComment(content, match.index, rel)) continue;
        const line = getLineNum(content, match.index);
        const statement = statementAround(content, match.index);
        const signal = classifyCodeSink('sql', statement);
        if (!signal) continue;
        const context = statement.slice(0, 240).replace(/\s+/g, ' ').trim();
        reportOnce(signal, id, line, `${name}\n${rel}:${line}\n  ${context}`, 'Use prepared statements with parameters ($1, ?) instead of concatenation/interpolation');
      }
    }

    // XSS - dangerouslySetInnerHTML
    let match;
    const dangerousHtml = /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:/g;
    while ((match = dangerousHtml.exec(content)) !== null) {
      if (isInComment(content, match.index, rel)) continue;
      const line = getLineNum(content, match.index);
      const signal = classifyCodeSink('html', statementAround(content, match.index));
      if (!signal) continue;
      reportOnce(signal, 'xss-react', line, 'React raw HTML sink without an observed sanitizer', 'Use DOMPurify to sanitize:\n  dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(data) }}');
    }

    // XSS - v-html
    const vHtml = /v-html\s*=\s*["']([^"']+)["']/g;
    while ((match = vHtml.exec(content)) !== null) {
      if (isInComment(content, match.index, rel)) continue;
      const line = getLineNum(content, match.index);
      const signal = classifyCodeSink('html', statementAround(content, match.index));
      if (!signal) continue;
      reportOnce(signal, 'xss-vue', line, `Variable: ${match[1]}\nVue raw HTML sink without an observed sanitizer`, 'Use {{ }} for text content, or sanitize the value before binding it.');
    }

    // innerHTML
    const innerHtml = /\.innerHTML\s*=(?!=)/g;
    while ((match = innerHtml.exec(content)) !== null) {
      if (isInComment(content, match.index, rel)) continue;
      const line = getLineNum(content, match.index);
      const signal = classifyCodeSink('html', statementAround(content, match.index));
      if (!signal) continue;
      reportOnce(signal, 'xss-dom', line, 'DOM raw HTML sink without an observed sanitizer', 'Use textContent instead of innerHTML, or sanitize the HTML');
    }

    // eval / new Function
    const evalPattern = /\beval\s*\(|new\s+Function\s*\(/g;
    while ((match = evalPattern.exec(content)) !== null) {
      if (isInComment(content, match.index, rel)) continue;
      const line = getLineNum(content, match.index);
      const signal = classifyCodeSink('eval', statementAround(content, match.index));
      if (!signal) continue;
      reportOnce(signal, 'eval', line, 'eval/Function executes code in the current process', 'Refactor to avoid eval(). Use JSON.parse() for data and named functions for logic.');
    }

    // Command Injection
    const cmdInjection = /(?:exec|execSync|spawn|spawnSync)\s*\(\s*(?:`[^`]*\$\{|['"][^'"]*['"]\s*\+)/g;
    while ((match = cmdInjection.exec(content)) !== null) {
      if (isInComment(content, match.index, rel)) continue;
      const line = getLineNum(content, match.index);
      const signal = classifyCodeSink('command', statementAround(content, match.index));
      if (!signal) continue;
      reportOnce(signal, 'cmd-injection', line, 'A process command is constructed dynamically', 'Use execFile() with a fixed executable and separate validated arguments.');
    }

    // Open Redirect
    const openRedirect = /(?:\b(?:res|reply|response)\.redirect\s*\(|\b(?:window\.)?location(?:\.href)?\s*=)[^;\n]+/g;
    while ((match = openRedirect.exec(content)) !== null) {
      if (isInComment(content, match.index, rel)) continue;
      const line = getLineNum(content, match.index);
      const signal = classifyCodeSink('redirect', statementAround(content, match.index));
      if (!signal) continue;
      reportOnce(signal, 'open-redirect', line, 'Redirect target comes directly from request-controlled data', 'Parse the URL and enforce an explicit same-origin or destination allowlist.');
    }

    // Weak crypto
    const weakCrypto = /createHash\s*\(\s*['"](?:md5|sha1)['"]|crypto\.(?:MD5|SHA1)/g;
    while ((match = weakCrypto.exec(content)) !== null) {
      if (isInComment(content, match.index, rel)) continue;
      const line = getLineNum(content, match.index);
      const signal = classifyCodeSink('weak-hash', statementAround(content, match.index));
      reportOnce(signal, 'weak-crypto', line, 'MD5/SHA1 usage requires context-specific review', 'Use SHA-256 for integrity or Argon2/scrypt for passwords.');
    }

    // ReDoS
    const regexPattern = /new\s+RegExp\s*\(\s*(?:req\.|params\.|query\.|body\.)/g;
    while ((match = regexPattern.exec(content)) !== null) {
      if (isInComment(content, match.index, rel)) continue;
      const line = getLineNum(content, match.index);
      reportOnce(
        { severity: 'HIGH', confidence: 'high', classification: 'probable', title: 'Request data used to construct a regular expression' },
        'redos',
        line,
        'A RegExp pattern is built directly from request-controlled data',
        'Escape request data before constructing a RegExp and cap input length.',
      );
    }
  }
}
