#!/usr/bin/env node

// ──────────────────────────────────────────────
// VICE — CLI Entry Point
// Vulnerability Inspector & Code Examiner v3.0
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import chalk from 'chalk';
import ora from 'ora';
import inquirer from 'inquirer';
import fs from 'fs';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { getViceDataDir } from '../src/utils/paths.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PKG_DIR = path.resolve(__dirname, '..');
const DATA_DIR = getViceDataDir();
const DISCLAIMER_FILE = path.join(DATA_DIR, '.vice-accepted');

import { LOCAL_MODULES, runLocalAudit } from '../src/local/index.js';
import { getFindings, clearFindings, loadFindings } from '../src/core/findings.js';
import { calculateScore, severityColor } from '../src/core/score.js';
import { printReport } from '../src/core/reporter/console.js';
import { exportJson } from '../src/core/reporter/json.js';
import { exportHtml } from '../src/core/reporter/html.js';
import { writeBadgeFile, readReportFile, findLatestReport } from '../src/core/badge.js';

// ──────────── BANNER ────────────

function printBanner() {
  console.clear();
  console.log('');
  console.log(chalk.hex('#995ff6').bold('  ██╗   ██╗██╗ ██████╗███████╗'));
  console.log(chalk.hex('#995ff6').bold('  ██║   ██║██║██╔════╝██╔════╝'));
  console.log(chalk.hex('#995ff6').bold('  ██║   ██║██║██║     █████╗  '));
  console.log(chalk.hex('#995ff6').bold('  ╚██╗ ██╔╝██║██║     ██╔══╝  '));
  console.log(chalk.hex('#995ff6').bold('   ╚████╔╝ ██║╚██████╗███████╗'));
  console.log(chalk.hex('#995ff6').bold('    ╚═══╝  ╚═╝ ╚═════╝╚══════╝'));
  console.log(chalk.gray('  Vulnerability Inspector & Code Examiner'));
  console.log(chalk.gray('  Black-Box & White-Box Security Auditor v3.0'));
  console.log('');
  console.log(chalk.hex('#6366f1').bold('  ┌─────────────────────────────────────────┐'));
  console.log(chalk.hex('#6366f1').bold('  │') + chalk.white.bold('  Webba Creative Technologies') + chalk.gray('  (c) 2026') + chalk.hex('#6366f1').bold('  │'));
  console.log(chalk.hex('#6366f1').bold('  └─────────────────────────────────────────┘\n'));
}

// ──────────── LEGAL DISCLAIMER ────────────

async function checkDisclaimer(isCi = false) {
  if (fs.existsSync(DISCLAIMER_FILE)) return true;

  // Auto-accept via environment variable (used by GitHub Action and other CI integrations)
  if (process.env.VICE_ACCEPT_TERMS === '1') {
    fs.writeFileSync(DISCLAIMER_FILE, `Accepted on ${new Date().toISOString()} via VICE_ACCEPT_TERMS\n`);
    process.stderr.write('VICE: terms accepted via VICE_ACCEPT_TERMS environment variable.\n');
    process.stderr.write('VICE must only be used on systems you own or are authorized to test.\n');
    return true;
  }

  console.log(chalk.red.bold('\n  ┌─────────────────────────────────────────────────────────┐'));
  console.log(chalk.red.bold('  │                    LEGAL DISCLAIMER                     │'));
  console.log(chalk.red.bold('  └─────────────────────────────────────────────────────────┘'));
  console.log('');
  console.log(chalk.yellow('  VICE is a security auditing tool designed EXCLUSIVELY for'));
  console.log(chalk.yellow('  testing systems that you OWN or have EXPLICIT WRITTEN'));
  console.log(chalk.yellow('  AUTHORIZATION to test.\n'));
  console.log(chalk.white('  By using this tool, you acknowledge that:\n'));
  console.log(chalk.white('  1. You will ONLY scan websites, servers, and infrastructure'));
  console.log(chalk.white('     that you own or have written permission to audit.'));
  console.log(chalk.white('  2. Unauthorized scanning of third-party systems is ILLEGAL'));
  console.log(chalk.white('     under computer fraud and abuse laws (CFAA, EU Directive'));
  console.log(chalk.white('     2013/40/EU, and similar laws worldwide).'));
  console.log(chalk.white('  3. You accept FULL RESPONSIBILITY for how you use this tool.'));
  console.log(chalk.white('  4. Webba Creative Technologies and VICE contributors are'));
  console.log(chalk.white('     NOT LIABLE for any misuse, damage, or legal consequences'));
  console.log(chalk.white('     resulting from the use of this software.\n'));
  console.log(chalk.red.bold('  Violations may result in criminal prosecution, fines,'));
  console.log(chalk.red.bold('  and imprisonment.\n'));

  if (isCi) {
    console.log(chalk.red('  CI mode requires prior acceptance. Run vice interactively first.\n'));
    process.exit(1);
  }

  const { accepted } = await inquirer.prompt([{
    type: 'confirm',
    name: 'accepted',
    message: chalk.bold('I understand and agree to use VICE only on systems I own or am authorized to test.'),
    default: false,
  }]);

  if (!accepted) {
    console.log(chalk.red('\n  You must accept the terms to use VICE.\n'));
    process.exit(1);
  }

  fs.writeFileSync(DISCLAIMER_FILE, `Accepted on ${new Date().toISOString()}\n`);
  console.log(chalk.green('\n  Terms accepted. This prompt will not appear again.\n'));
  return true;
}

// ──────────── HISTORY ────────────

async function viewHistory() {
  const dir = path.join(DATA_DIR, 'scans');
  if (!fs.existsSync(dir)) {
    console.log(chalk.yellow('\n  No saved scans found.\n'));
    return;
  }

  const files = fs.readdirSync(dir).filter(f => f.endsWith('.json')).sort().reverse();
  if (files.length === 0) {
    console.log(chalk.yellow('\n  No saved scans found.\n'));
    return;
  }

  const scans = [];
  for (const file of files) {
    try {
      const data = JSON.parse(fs.readFileSync(path.join(dir, file), 'utf-8'));
      const date = new Date(data.date).toLocaleDateString('en-US', { day: '2-digit', month: '2-digit', year: 'numeric', hour: '2-digit', minute: '2-digit' });
      const target = data.url.startsWith('http') ? new URL(data.url).hostname : path.basename(data.url);
      const grade = data.grade || '?';
      const score = data.score ?? '?';
      const nbFindings = data.findings?.length || 0;
      const criticals = data.findings?.filter(f => f.severity === 'CRITICAL').length || 0;
      scans.push({ file, date, target, grade, score, nbFindings, criticals, data });
    } catch {}
  }

  const gradeColor = (g) => {
    const map = { A: chalk.green, B: chalk.hex('#995ff6'), C: chalk.yellow, D: chalk.red, E: chalk.bgRed.white, F: chalk.bgRed.white };
    return (map[g] || chalk.white)(`[${g}]`);
  };

  const { selectedScan } = await inquirer.prompt([{
    type: 'list', name: 'selectedScan',
    message: chalk.bold('Select a scan:'),
    choices: [
      ...scans.map((s, i) => ({
        name: `${gradeColor(s.grade)} ${s.score}/100 — ${s.target} — ${s.date} — ${s.nbFindings} findings`,
        value: i,
      })),
      new inquirer.Separator(),
      { name: 'Back to main menu', value: -1 },
    ],
    pageSize: 15,
  }]);

  if (selectedScan === -1) return;

  const scan = scans[selectedScan];
  clearFindings();
  loadFindings(scan.data.findings);
  printReport(`Saved scan — ${scan.target} — ${scan.date}`);

  const { postAction } = await inquirer.prompt([{
    type: 'list', name: 'postAction', message: 'Action:',
    choices: [
      { name: 'View another scan', value: 'another' },
      { name: 'Export to HTML', value: 'html' },
      { name: 'Delete this scan', value: 'delete' },
      { name: 'Back to main menu', value: 'menu' },
    ],
  }]);

  if (postAction === 'html') {
    await exportHtml(scan.data.url, DATA_DIR);
    await viewHistory();
  } else if (postAction === 'delete') {
    const { ok } = await inquirer.prompt([{ type: 'confirm', name: 'ok', message: `Delete ${scan.file}?`, default: false }]);
    if (ok) { fs.unlinkSync(path.join(dir, scan.file)); console.log(chalk.green('  Deleted.\n')); }
    await viewHistory();
  } else if (postAction === 'another') {
    await viewHistory();
  }
  // 'menu' just returns, mainMenu() loop handles the rest
}

// ──────────── AUDIT MODE ────────────

async function runAuditMode() {
  const { projectPath } = await inquirer.prompt([{
    type: 'input', name: 'projectPath',
    message: chalk.bold('Project path to audit:'),
    default: '.',
    validate: (input) => {
      const resolved = path.resolve(input);
      return fs.existsSync(resolved) ? true : `Path ${resolved} does not exist`;
    },
  }]);

  const resolved = path.resolve(projectPath);

  const { modules } = await inquirer.prompt([{
    type: 'checkbox', name: 'modules',
    message: chalk.bold('Modules to run:'),
    choices: LOCAL_MODULES.map(m => ({ name: m.name, value: m.value, checked: true })),
  }]);

  clearFindings();
  await runLocalAudit(resolved, modules);
  printReport(`Local audit — ${path.basename(resolved)}`);

  await exportJson(resolved, DATA_DIR);
  const { wantHtml } = await inquirer.prompt([{ type: 'confirm', name: 'wantHtml', message: 'Export HTML report?', default: false }]);
  if (wantHtml) await exportHtml(resolved, DATA_DIR);
  console.log(chalk.hex('#6366f1')('  Webba Creative Technologies') + chalk.gray(' — Audit complete.\n'));
}

// ──────────── SCAN MODE ────────────

async function runScanMode() {
  const scanPath = path.join(PKG_DIR, 'scan.js');
  if (!fs.existsSync(scanPath)) {
    console.log(chalk.red('  scan.js not found. Place it in the VICE root directory.'));
    return;
  }
  const { main: scanMain } = await import(pathToFileURL(scanPath).href);
  await scanMain();
}

// ──────────── CI MODE ────────────

async function runCiMode(target, minScore = 70) {
  clearFindings();
  const resolved = path.resolve(target);
  if (!fs.existsSync(resolved)) {
    console.log(chalk.red(`  Path not found: ${resolved}`));
    process.exit(1);
  }

  const allModules = LOCAL_MODULES.map(m => m.value);
  await runLocalAudit(resolved, allModules);
  printReport(`CI Audit — ${path.basename(resolved)}`);
  await exportJson(resolved, DATA_DIR);

  const { score, grade } = calculateScore();
  if (score < minScore) {
    console.log(chalk.red(`\n  CI FAILED: Score ${score}/100 (${grade}) < minimum ${minScore}\n`));
    process.exit(1);
  } else {
    console.log(chalk.green(`\n  CI PASSED: Score ${score}/100 (${grade}) >= ${minScore}\n`));
    process.exit(0);
  }
}

// ──────────── JSON AUDIT MODE (for CI / GitHub Action) ────────────

function buildSummary(findings) {
  const summary = { total: findings.length, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    const sev = f.severity;
    if (sev === 'CRITICAL' || sev === 'CRITIQUE') summary.critical++;
    else if (sev === 'HIGH' || sev === 'ELEVEE') summary.high++;
    else if (sev === 'MEDIUM' || sev === 'MOYENNE') summary.medium++;
    else if (sev === 'LOW' || sev === 'FAIBLE') summary.low++;
    else if (sev === 'INFO') summary.info++;
  }
  return summary;
}

function readPkgVersion() {
  try {
    const pkg = JSON.parse(fs.readFileSync(path.join(PKG_DIR, 'package.json'), 'utf-8'));
    return pkg.version || 'unknown';
  } catch {
    return 'unknown';
  }
}

async function runJsonAuditMode(target, minScore) {
  // Redirect all stdout writes to stderr during the audit so the final JSON
  // is the only thing written to stdout. Spinner output (ora) and console.log
  // calls from modules will all land on stderr.
  const originalWrite = process.stdout.write.bind(process.stdout);
  process.stdout.write = (chunk, encoding, cb) => process.stderr.write(chunk, encoding, cb);

  const finish = (data, exitCode = 0) => {
    process.stdout.write = originalWrite;
    process.stdout.write(JSON.stringify(data, null, 2) + '\n');
    process.exit(exitCode);
  };

  try {
    const accepted = await checkDisclaimer(true);
    if (!accepted) {
      finish({ error: 'Terms not accepted. Set VICE_ACCEPT_TERMS=1 to bypass.' }, 1);
      return;
    }

    const resolved = path.resolve(target);
    if (!fs.existsSync(resolved)) {
      finish({ error: `Path not found: ${resolved}` }, 1);
      return;
    }

    clearFindings();
    const allModules = LOCAL_MODULES.map(m => m.value);
    await runLocalAudit(resolved, allModules);

    const findings = getFindings();
    const { score, grade } = calculateScore();

    // Best-effort: still save to history so the file is available locally
    try { await exportJson(resolved, DATA_DIR); } catch {}

    const output = {
      version: readPkgVersion(),
      target: resolved,
      timestamp: new Date().toISOString(),
      score,
      grade,
      summary: buildSummary(findings),
      findings,
    };

    const exitCode = (minScore !== null && score < minScore) ? 1 : 0;
    finish(output, exitCode);
  } catch (err) {
    finish({ error: err.message, stack: err.stack }, 1);
  }
}

// ──────────── BADGE COMMAND ────────────

async function runBadgeCommand(args) {
  const inputIdx = args.indexOf('--input');
  const outputIdx = args.indexOf('--output');

  let inputPath = inputIdx !== -1 ? args[inputIdx + 1] : null;
  const outputPath = outputIdx !== -1 ? args[outputIdx + 1] : '.github/vice-badge.json';

  if (!inputPath) {
    inputPath = findLatestReport(path.join(DATA_DIR, 'scans'));
    if (!inputPath) {
      console.error(chalk.red('  No scan report found. Run "vice audit ." first or specify --input <path>.'));
      process.exit(1);
    }
  }

  try {
    const { score, grade } = readReportFile(inputPath);
    const written = writeBadgeFile(score, grade, outputPath);
    console.log(chalk.green(`  Badge written to ${written}`));
    console.log(chalk.gray(`  Score: ${grade} (${score}/100)`));
    console.log(chalk.gray(`  Source: ${inputPath}`));
  } catch (err) {
    console.error(chalk.red(`  Failed to generate badge: ${err.message}`));
    process.exit(1);
  }
}

// ──────────── MAIN ────────────

async function main() {
  const args = process.argv.slice(2);

  // CLI argument mode
  if (args.length > 0) {
    const command = args[0];

    if (command === 'audit') {
      const jsonMode = args.includes('--json');
      const ciMode = args.includes('--ci');
      const target = args[1] && !args[1].startsWith('--') ? args[1] : '.';

      // JSON mode: clean stdout output for machine consumption
      if (jsonMode) {
        const minIdx = args.indexOf('--min-score');
        const minScore = minIdx !== -1 ? parseInt(args[minIdx + 1]) : (ciMode ? 70 : null);
        await runJsonAuditMode(target, minScore);
        return;
      }

      printBanner();
      await checkDisclaimer(ciMode);

      if (ciMode) {
        const minIdx = args.indexOf('--min-score');
        const minScore = minIdx !== -1 ? parseInt(args[minIdx + 1]) : 70;
        await runCiMode(target, minScore);
        return;
      }
      clearFindings();
      const resolved = path.resolve(target);
      const allModules = LOCAL_MODULES.map(m => m.value);
      await runLocalAudit(resolved, allModules);
      printReport(`Local audit — ${path.basename(resolved)}`);
      await exportJson(resolved, DATA_DIR);
      console.log(chalk.hex('#6366f1')('  Webba Creative Technologies') + chalk.gray(' — Audit complete.\n'));
      return;
    }

    if (command === 'scan') {
      printBanner();
      await checkDisclaimer();
      await runScanMode();
      return;
    }

    if (command === 'history') {
      printBanner();
      await viewHistory();
      return;
    }

    if (command === 'badge') {
      await runBadgeCommand(args);
      return;
    }

    // Help
    console.log(chalk.bold('\n  VICE — Vulnerability Inspector & Code Examiner\n'));
    console.log('  Usage:');
    console.log('    vice scan                            Remote scan (black-box, URL)');
    console.log('    vice audit [path]                    Local audit (white-box, source code)');
    console.log('    vice audit [path] --ci               CI mode (exits 0 if score >= threshold)');
    console.log('    vice audit [path] --ci --json        Machine-readable JSON output to stdout');
    console.log('    vice audit . --ci --min-score 80');
    console.log('    vice badge --input <report.json>     Generate shields.io badge from a report');
    console.log('         [--output .github/vice-badge.json]');
    console.log('    vice history                         View saved scan reports\n');
    return;
  }

  // Interactive mode
  printBanner();
  await checkDisclaimer();
  await mainMenu();
}

async function mainMenu() {
  const { action } = await inquirer.prompt([{
    type: 'list', name: 'action',
    message: chalk.bold('What would you like to do?'),
    choices: [
      { name: 'Remote scan (black-box) — enter a URL', value: 'scan' },
      { name: 'Local audit (white-box) — scan a project', value: 'audit' },
      { name: 'View scan history', value: 'history' },
      new inquirer.Separator(),
      { name: 'Exit', value: 'exit' },
    ],
  }]);

  if (action === 'exit') return;
  if (action === 'scan') await runScanMode();
  else if (action === 'audit') await runAuditMode();
  else if (action === 'history') await viewHistory();

  // Return to main menu after action
  await mainMenu();
}

main().catch(console.error);
