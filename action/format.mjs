// ──────────────────────────────────────────────
// VICE Action — Markdown formatter for PR comments
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

const SEVERITY_LABELS = {
  CRITICAL: 'Critical', CRITIQUE: 'Critical',
  HIGH: 'High', ELEVEE: 'High',
  MEDIUM: 'Medium', MOYENNE: 'Medium',
  LOW: 'Low', FAIBLE: 'Low',
  INFO: 'Info',
};

const SEVERITY_DISPLAY_ORDER = ['Critical', 'High', 'Medium', 'Low'];
const MAX_FINDINGS_PER_SEVERITY = 10;

function normalizeSeverity(sev) {
  return SEVERITY_LABELS[sev] || sev || 'Unknown';
}

function escapeMarkdown(s) {
  if (s === undefined || s === null) return '';
  return String(s)
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/\|/g, '\\|');
}

function diffString(current, previous) {
  if (previous === null || previous === undefined || previous === current) return '';
  const diff = current - previous;
  const sign = diff > 0 ? '+' : '';
  return ` (${sign}${diff} vs base)`;
}

export function formatPrComment(report, options = {}) {
  const { previousScore = null, repoUrl = 'https://github.com/Webba-Creative-Technologies/vice' } = options;
  const lines = [];

  lines.push('## VICE Security Scan');
  lines.push('');

  // Score and grade
  lines.push(`**Score: ${report.grade}** &mdash; ${report.score}/100${diffString(report.score, previousScore)}`);
  lines.push('');

  // Summary table
  const summary = report.summary || {};
  if (summary.total > 0) {
    lines.push('| Severity | Count |');
    lines.push('|---|---|');
    if (summary.critical > 0) lines.push(`| Critical | ${summary.critical} |`);
    if (summary.high > 0) lines.push(`| High | ${summary.high} |`);
    if (summary.medium > 0) lines.push(`| Medium | ${summary.medium} |`);
    if (summary.low > 0) lines.push(`| Low | ${summary.low} |`);
    if (summary.info > 0) lines.push(`| Info | ${summary.info} |`);
    lines.push('');
  } else {
    lines.push('No vulnerabilities detected. Good job.');
    lines.push('');
  }

  // Findings detail (skip Info)
  if (Array.isArray(report.findings) && report.findings.length > 0) {
    const grouped = {};
    for (const f of report.findings) {
      const sev = normalizeSeverity(f.severity);
      if (!grouped[sev]) grouped[sev] = [];
      grouped[sev].push(f);
    }

    for (const sev of SEVERITY_DISPLAY_ORDER) {
      const items = grouped[sev];
      if (!items || items.length === 0) continue;

      const expanded = sev === 'Critical' || sev === 'High' ? ' open' : '';
      lines.push(`<details${expanded}>`);
      lines.push(`<summary><strong>${items.length} ${sev}</strong></summary>`);
      lines.push('');

      const display = items.slice(0, MAX_FINDINGS_PER_SEVERITY);
      for (const f of display) {
        const title = escapeMarkdown(f.title || 'Untitled finding');
        const module = f.module ? ` (${escapeMarkdown(f.module)})` : '';
        lines.push(`- **${title}**${module}`);
        if (f.detail) lines.push(`  ${escapeMarkdown(f.detail)}`);
        if (f.recommendation) lines.push(`  Fix: ${escapeMarkdown(f.recommendation)}`);
      }
      if (items.length > display.length) {
        lines.push(`- ...and ${items.length - display.length} more`);
      }
      lines.push('');
      lines.push('</details>');
      lines.push('');
    }
  }

  lines.push('---');
  lines.push(`Scanned with [VICE](${repoUrl})${report.version ? ` v${report.version}` : ''}`);

  return lines.join('\n');
}

export function formatErrorComment(errorMessage, options = {}) {
  const { repoUrl = 'https://github.com/Webba-Creative-Technologies/vice' } = options;
  return [
    '## VICE Security Scan',
    '',
    `**Scan failed:** ${escapeMarkdown(errorMessage)}`,
    '',
    'Check the action logs for details.',
    '',
    '---',
    `Scanned with [VICE](${repoUrl})`,
  ].join('\n');
}
