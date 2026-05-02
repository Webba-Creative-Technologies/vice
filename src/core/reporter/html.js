// ──────────────────────────────────────────────
// VICE — HTML Reporter
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import { getFindings } from '../findings.js';
import { calculateScore } from '../score.js';
import { enrichWithTaxonomy } from './sarif.js';

export async function exportHtml(url, baseDir) {
  const { score, grade } = calculateScore();
  const findings = enrichWithTaxonomy(getFindings());
  const hostname = url.startsWith('http') ? new URL(url).hostname : path.basename(url);
  const dir = path.join(baseDir, 'scans');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const filename = path.join(dir, `vice-report-${hostname}-${Date.now()}.html`);

  const allSevs = ['CRITICAL', 'CRITIQUE', 'HIGH', 'ELEVEE', 'MEDIUM', 'MOYENNE', 'LOW', 'FAIBLE', 'INFO'];
  const sevOrder = { CRITICAL: 0, CRITIQUE: 0, HIGH: 1, ELEVEE: 1, MEDIUM: 2, MOYENNE: 2, LOW: 3, FAIBLE: 3, INFO: 4 };
  const counts = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;
  const sorted = [...findings].sort((a, b) => (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5));

  const sevColors = {
    CRITICAL: '#c0392b', CRITIQUE: '#c0392b',
    HIGH: '#d35400', ELEVEE: '#d35400',
    MEDIUM: '#b8860b', MOYENNE: '#b8860b',
    LOW: '#5b7ea1', FAIBLE: '#5b7ea1',
    INFO: '#8e99a4',
  };
  const sevLabels = {
    CRITICAL: 'Critical', CRITIQUE: 'Critical',
    HIGH: 'High', ELEVEE: 'High',
    MEDIUM: 'Medium', MOYENNE: 'Medium',
    LOW: 'Low', FAIBLE: 'Low',
    INFO: 'Info',
  };
  const gradeColors = { A: '#27ae60', B: '#2e86c1', C: '#b8860b', D: '#c0392b', E: '#7b241c', F: '#4a1410' };

  // Build findings HTML
  let findingsHtml = '';
  let currentModule = '';
  for (const f of sorted) {
    if (f.module !== currentModule) {
      currentModule = f.module;
      findingsHtml += `<div class="module-title">${currentModule}</div>`;
    }
    const detail = (f.detail || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const reco = (f.recommendation || '').replace(/</g, '&lt;').replace(/>/g, '&gt;');
    const cweTag = f.cwe ? `<span class="taxo-tag taxo-cwe">${f.cwe}</span>` : '';
    const owaspTag = f.owasp ? `<span class="taxo-tag taxo-owasp">${f.owasp}</span>` : '';
    findingsHtml += `
      <div class="finding">
        <div class="finding-header">
          <span class="badge" style="background:${sevColors[f.severity] || '#888'}">${sevLabels[f.severity] || f.severity}</span>
          <span class="finding-title">${f.title}</span>
          ${cweTag}${owaspTag}
        </div>
        ${detail ? `<pre class="finding-detail">${detail}</pre>` : ''}
        ${reco ? `<div class="finding-reco">${reco}</div>` : ''}
      </div>`;
  }

  // Stats pills
  const statsHtml = allSevs
    .filter(sev => counts[sev])
    .map(sev => `<span class="stat-pill" style="background:${sevColors[sev]}">${sevLabels[sev]} ${counts[sev]}</span>`)
    .join('');

  const dateStr = new Date().toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
  const timeStr = new Date().toLocaleTimeString('en-US', { hour: '2-digit', minute: '2-digit' });

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>VICE Report — ${hostname}</title>
  <style>
    :root {
      --primary: #995ff6;
      --accent: #ee967a;
      --bg: #fafafa;
      --card: #ffffff;
      --text: #2c2c2c;
      --text-light: #6b6b6b;
      --text-muted: #9a9a9a;
      --border: #e8e8e8;
    }

    * { margin: 0; padding: 0; box-sizing: border-box; }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.6;
      -webkit-font-smoothing: antialiased;
    }

    .container {
      max-width: 780px;
      margin: 0 auto;
      padding: 48px 24px 64px;
    }

    /* Header */
    .header {
      margin-bottom: 48px;
    }

    .header-top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 32px;
    }

    .logo {
      font-size: 14px;
      font-weight: 600;
      color: var(--primary);
      letter-spacing: 2px;
      text-transform: uppercase;
    }

    .date {
      font-size: 13px;
      color: var(--text-muted);
    }

    .target {
      font-size: 28px;
      font-weight: 700;
      color: var(--text);
      margin-bottom: 4px;
      word-break: break-all;
    }

    .target-url {
      font-size: 14px;
      color: var(--text-light);
      margin-bottom: 32px;
    }

    /* Score */
    .score-section {
      display: flex;
      align-items: center;
      gap: 24px;
      padding: 28px 32px;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      margin-bottom: 24px;
    }

    .grade-circle {
      width: 72px;
      height: 72px;
      border-radius: 50%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 32px;
      font-weight: 800;
      color: white;
      flex-shrink: 0;
    }

    .score-info {
      flex: 1;
    }

    .score-number {
      font-size: 20px;
      font-weight: 700;
      color: var(--text);
    }

    .score-label {
      font-size: 13px;
      color: var(--text-muted);
      margin-top: 2px;
    }

    /* Stats */
    .stats {
      display: flex;
      flex-wrap: wrap;
      gap: 8px;
      margin-bottom: 40px;
    }

    .stat-pill {
      display: inline-block;
      padding: 4px 14px;
      border-radius: 100px;
      font-size: 12px;
      font-weight: 600;
      color: white;
      letter-spacing: 0.3px;
    }

    /* Findings */
    .module-title {
      font-size: 16px;
      font-weight: 700;
      color: var(--text);
      margin-top: 36px;
      margin-bottom: 16px;
      padding-bottom: 8px;
      border-bottom: 1px solid var(--border);
    }

    .module-title:first-child {
      margin-top: 0;
    }

    .finding {
      padding: 16px 20px;
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 10px;
    }

    .finding-header {
      display: flex;
      align-items: flex-start;
      gap: 10px;
      margin-bottom: 6px;
    }

    .badge {
      display: inline-block;
      padding: 2px 10px;
      border-radius: 4px;
      font-size: 11px;
      font-weight: 700;
      color: white;
      text-transform: uppercase;
      letter-spacing: 0.5px;
      flex-shrink: 0;
      margin-top: 2px;
    }

    .finding-title {
      font-size: 14px;
      font-weight: 600;
      color: var(--text);
      line-height: 1.4;
    }

    .finding-detail {
      font-family: 'SF Mono', 'Fira Code', 'Consolas', monospace;
      font-size: 12px;
      line-height: 1.5;
      color: var(--text-light);
      background: #f5f5f5;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: 12px 14px;
      margin: 8px 0;
      white-space: pre-wrap;
      word-break: break-word;
      overflow-x: auto;
    }

    .finding-reco {
      font-size: 13px;
      color: #27ae60;
      margin-top: 8px;
      padding-left: 2px;
      line-height: 1.5;
    }

    .finding-reco::before {
      content: "\\2192  ";
    }

    /* Footer */
    .footer {
      margin-top: 56px;
      padding-top: 24px;
      border-top: 1px solid var(--border);
      text-align: center;
      font-size: 12px;
      color: var(--text-muted);
      line-height: 1.8;
    }

    .footer a {
      color: var(--primary);
      text-decoration: none;
    }

    .footer a:hover {
      text-decoration: underline;
    }

    @media (max-width: 600px) {
      .container { padding: 24px 16px 48px; }
      .header-top { flex-direction: column; align-items: flex-start; gap: 8px; }
      .target { font-size: 22px; }
      .score-section { flex-direction: column; text-align: center; padding: 24px; }
      .finding-header { flex-direction: column; gap: 6px; }
    }
    .taxo-tag {
      display: inline-block;
      padding: 2px 8px;
      border-radius: 4px;
      font-size: 10px;
      font-weight: 600;
      letter-spacing: 0.3px;
      margin-left: 4px;
      vertical-align: middle;
    }
    .taxo-cwe { background: #2c3e50; color: #fff; }
    .taxo-owasp { background: #c0392b; color: #fff; }
  </style>
</head>
<body>
  <div class="container">
    <div class="header">
      <div class="header-top">
        <div class="logo">VICE</div>
        <div class="date">${dateStr} at ${timeStr}</div>
      </div>
      <div class="target">${hostname}</div>
      <div class="target-url">${url}</div>
    </div>

    <div class="score-section">
      <div class="grade-circle" style="background:${gradeColors[grade] || '#888'}">${grade}</div>
      <div class="score-info">
        <div class="score-number">${score} / 100</div>
        <div class="score-label">${findings.length} finding${findings.length !== 1 ? 's' : ''} detected</div>
      </div>
    </div>

    <div class="stats">${statsHtml}</div>

    ${findingsHtml}

    <div class="footer">
      Generated by <a href="https://github.com/Webba-Creative-Technologies/vice">VICE</a> v3.0<br>
      <a href="https://webba-creative.com">Webba Creative Technologies</a> &copy; 2026<br>
      This tool is intended for authorized security testing only.
    </div>
  </div>
</body>
</html>`;

  fs.writeFileSync(filename, html);
  console.log(chalk.gray(`  HTML report exported: ${filename}\n`));
  return filename;
}
