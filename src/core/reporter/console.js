// ──────────────────────────────────────────────
// VICE — Console Reporter
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import chalk from 'chalk';
import { getFindings } from '../findings.js';
import { calculateScore, severityColor } from '../score.js';

export function printReport(title = 'Security Audit Report', options = {}) {
  const allFindings = getFindings();
  const { score, grade, color } = calculateScore(undefined, options);

  // Findings suppressed by baseline are kept in the array but not displayed
  // by default, to keep the report focused on what actually needs action.
  const baselinedCount = allFindings.filter(f => f.baselined).length;
  const findings = options.showBaselined ? allFindings : allFindings.filter(f => !f.baselined);

  console.log('\n');
  console.log(chalk.bold('━'.repeat(60)));
  console.log(chalk.hex('#995ff6').bold('  VICE') + chalk.gray(` — ${title}`));
  console.log(chalk.gray('  Webba Creative Technologies'));
  console.log(chalk.bold('━'.repeat(60)));
  console.log('');
  console.log(`  Security Score: ${color(` ${grade} `)} ${chalk.gray(`(${score}/100)`)}`);
  if (baselinedCount > 0) {
    console.log(chalk.gray(`  ${baselinedCount} finding(s) suppressed by baseline`));
  }

  if (findings.length === 0) {
    if (allFindings.length === 0) {
      console.log(chalk.green('\n  No vulnerabilities detected. Good job!\n'));
    } else {
      console.log(chalk.green('\n  No new findings beyond the baseline.\n'));
    }
    return;
  }

  // Collect all unique severity levels
  const allSevs = ['CRITICAL', 'CRITIQUE', 'HIGH', 'ELEVEE', 'MEDIUM', 'MOYENNE', 'LOW', 'FAIBLE', 'INFO'];
  const counts = {};
  for (const f of findings) counts[f.severity] = (counts[f.severity] || 0) + 1;

  console.log('');
  for (const sev of allSevs) {
    if (counts[sev]) console.log(`  ${severityColor(sev)} ${counts[sev]} finding(s)`);
  }
  console.log('');
  console.log(chalk.bold('─'.repeat(60)));

  // Sort by severity weight
  const sevOrder = { CRITICAL: 0, CRITIQUE: 0, HIGH: 1, ELEVEE: 1, MEDIUM: 2, MOYENNE: 2, LOW: 3, FAIBLE: 3, INFO: 4 };
  const sorted = [...findings].sort((a, b) => (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5));

  let currentModule = '';
  for (const f of sorted) {
    if (f.module !== currentModule) {
      currentModule = f.module;
      console.log(chalk.bold.underline(`\n  ${currentModule}`));
    }
    const confTag = f.confidence && f.confidence !== 'medium' ? chalk.gray(` [${f.confidence}]`) : '';
    console.log(`\n  ${severityColor(f.severity)}${confTag} ${chalk.bold(f.title)}`);
    console.log(chalk.gray(`    ${f.detail}`));
    if (f.recommendation) console.log(chalk.green(`    → ${f.recommendation}`));
  }

  console.log('\n' + chalk.bold('━'.repeat(60)));
  console.log(`  Score: ${color(` ${grade} `)} (${score}/100) — Total: ${findings.length} finding(s)`);
  console.log(chalk.gray('  VICE v3.0 — Webba Creative Technologies (c) 2026'));
  console.log(chalk.bold('━'.repeat(60)) + '\n');
}
