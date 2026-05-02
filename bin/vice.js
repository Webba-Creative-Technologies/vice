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
import { getFindings, clearFindings, loadFindings, setFindings } from '../src/core/findings.js';
import { calculateScore, severityColor } from '../src/core/score.js';
import { printReport } from '../src/core/reporter/console.js';
import { exportJson } from '../src/core/reporter/json.js';
import { exportHtml } from '../src/core/reporter/html.js';
import { buildSarif, enrichWithTaxonomy } from '../src/core/reporter/sarif.js';
import { writeBadgeFile, readReportFile, findLatestReport } from '../src/core/badge.js';
import { loadBaseline, writeBaseline, applyBaseline, getBaselinePath } from '../src/core/baseline.js';
import { loadConfig, applyTransform, loadCustomModules } from '../src/core/config.js';
import { fingerprintFinding } from '../src/core/fingerprint.js';

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

  // Load config + custom modules first so they appear in the inquirer choices
  const config = await loadConfig(resolved);
  const extraModules = config && config.moduleFiles.length
    ? await loadCustomModules(resolved, config.moduleFiles)
    : [];
  const allChoices = [...LOCAL_MODULES, ...extraModules];
  const enabledChoices = config && config.disabledModules.length
    ? allChoices.filter(m => !config.disabledModules.includes(m.value))
    : allChoices;

  const { modules } = await inquirer.prompt([{
    type: 'checkbox', name: 'modules',
    message: chalk.bold('Modules to run:'),
    choices: enabledChoices.map(m => ({ name: m.name, value: m.value, checked: true })),
  }]);

  clearFindings();
  await runLocalAudit(resolved, modules, { parallel: false, extraModules });
  applyConfigTransform(config);
  applyProjectBaseline(resolved);
  printReport(`Local audit — ${path.basename(resolved)}`);

  await exportJson(resolved, DATA_DIR);
  const { wantHtml } = await inquirer.prompt([{ type: 'confirm', name: 'wantHtml', message: 'Export HTML report?', default: false }]);
  if (wantHtml) await exportHtml(resolved, DATA_DIR);
  console.log(chalk.hex('#6366f1')('  Webba Creative Technologies') + chalk.gray(' — Audit complete.\n'));
}

// ──────────── SCAN MODE ────────────

async function runScanMode(options = {}) {
  const scanPath = path.join(PKG_DIR, 'scan.js');
  if (!fs.existsSync(scanPath)) {
    console.log(chalk.red('  scan.js not found. Place it in the VICE root directory.'));
    return;
  }
  const { main: scanMain } = await import(pathToFileURL(scanPath).href);
  await scanMain(options);
}

// ──────────── CI MODE ────────────

async function runCiMode(target, minScore = 70, options = {}) {
  clearFindings();
  const resolved = path.resolve(target);
  if (!fs.existsSync(resolved)) {
    console.log(chalk.red(`  Path not found: ${resolved}`));
    process.exit(1);
  }

  const { modules, extraModules, config } = await prepareModules(resolved);
  await runLocalAudit(resolved, modules, { parallel: true, extraModules });
  applyConfigTransform(config);
  applyProjectBaseline(resolved, options);
  printReport(`CI Audit — ${path.basename(resolved)}`, { minConfidence: options.minConfidence });
  await exportJson(resolved, DATA_DIR);

  const { score, grade } = calculateScore(undefined, { minConfidence: options.minConfidence, minSeverity: options.minSeverity });
  if (score < minScore) {
    console.log(chalk.red(`\n  CI FAILED: Score ${score}/100 (${grade}) < minimum ${minScore}\n`));
    process.exit(1);
  } else {
    console.log(chalk.green(`\n  CI PASSED: Score ${score}/100 (${grade}) >= ${minScore}\n`));
    process.exit(0);
  }
}

// Apply .vice-baseline.json to the in-memory findings, unless --no-baseline.
// Logs a single line to stderr so it shows up in CI logs without polluting JSON output.
function applyProjectBaseline(resolved, options = {}) {
  if (options.useBaseline === false) return;
  const baseline = loadBaseline(resolved);
  if (!baseline) return;
  applyBaseline(getFindings(), baseline);
  const total = Object.keys(baseline.findings || {}).length;
  process.stderr.write(`VICE: baseline applied (${total} finding(s) suppressed) from ${getBaselinePath(resolved)}\n`);
}

// Resolve which modules to run, honoring vice.config.js disabledModules
// and merging custom modules declared in cfg.modules.
// Returns { modules, extraModules, config } - call before runLocalAudit.
async function prepareModules(resolved) {
  const config = await loadConfig(resolved);
  let modules = LOCAL_MODULES.map(m => m.value);
  let extraModules = [];

  if (config) {
    if (config.disabledModules.length) {
      modules = modules.filter(v => !config.disabledModules.includes(v));
      process.stderr.write(`VICE: ${config.disabledModules.length} module(s) disabled by ${config.sourcePath}\n`);
    }
    if (config.moduleFiles.length) {
      extraModules = await loadCustomModules(resolved, config.moduleFiles);
      if (extraModules.length > 0) {
        modules.push(...extraModules.map(m => m.value));
        process.stderr.write(`VICE: ${extraModules.length} custom module(s) loaded from ${config.sourcePath}\n`);
      }
    }
  }

  return { modules, extraModules, config };
}

// Apply config.transformFinding to the global findings array (mutates in place).
// Call after runLocalAudit, before applyProjectBaseline.
function applyConfigTransform(config) {
  if (!config || !config.transformFinding) return;
  const before = getFindings().length;
  const transformed = applyTransform(getFindings(), config.transformFinding);
  setFindings(transformed);
  const dropped = before - transformed.length;
  if (dropped > 0) process.stderr.write(`VICE: transformFinding dropped ${dropped} finding(s)\n`);
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

async function runJsonAuditMode(target, minScore, options = {}) {
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
    const { modules, extraModules, config } = await prepareModules(resolved);
    await runLocalAudit(resolved, modules, { parallel: true, extraModules });
    applyConfigTransform(config);
    applyProjectBaseline(resolved, options);

    const findings = getFindings();
    const { score, grade } = calculateScore(undefined, { minConfidence: options.minConfidence, minSeverity: options.minSeverity });

    // Best-effort: still save to history so the file is available locally
    try { await exportJson(resolved, DATA_DIR); } catch {}

    const output = {
      version: readPkgVersion(),
      target: resolved,
      timestamp: new Date().toISOString(),
      score,
      grade,
      summary: buildSummary(findings),
      findings: enrichWithTaxonomy(findings),
    };

    const exitCode = (minScore !== null && score < minScore) ? 1 : 0;
    finish(output, exitCode);
  } catch (err) {
    finish({ error: err.message, stack: err.stack }, 1);
  }
}

// ──────────── SARIF AUDIT MODE (for CI / GitHub code scanning) ────────────

async function runSarifMode(target, minScore, outputPath, options = {}) {
  // Redirect all stdout writes to stderr during the audit so the final SARIF
  // is the only thing written to stdout (when no outputPath is given).
  const originalWrite = process.stdout.write.bind(process.stdout);
  process.stdout.write = (chunk, encoding, cb) => process.stderr.write(chunk, encoding, cb);

  const finish = (doc, exitCode = 0) => {
    process.stdout.write = originalWrite;
    const json = JSON.stringify(doc, null, 2) + '\n';
    if (outputPath) {
      try {
        const resolvedOut = path.resolve(outputPath);
        fs.mkdirSync(path.dirname(resolvedOut), { recursive: true });
        fs.writeFileSync(resolvedOut, json);
        process.stderr.write(`VICE: SARIF report written to ${resolvedOut}\n`);
      } catch (err) {
        process.stderr.write(`VICE: failed to write SARIF to ${outputPath}: ${err.message}\n`);
        process.exit(1);
      }
    } else {
      process.stdout.write(json);
    }
    process.exit(exitCode);
  };

  const finishError = (message, exitCode = 1) => {
    // On error, produce a minimal but valid SARIF document so consumers don't choke.
    const doc = buildSarif([], readPkgVersion());
    process.stderr.write(`VICE: ${message}\n`);
    finish(doc, exitCode);
  };

  try {
    const accepted = await checkDisclaimer(true);
    if (!accepted) {
      finishError('Terms not accepted. Set VICE_ACCEPT_TERMS=1 to bypass.', 1);
      return;
    }

    const resolved = path.resolve(target);
    if (!fs.existsSync(resolved)) {
      finishError(`Path not found: ${resolved}`, 1);
      return;
    }

    clearFindings();
    const { modules, extraModules, config } = await prepareModules(resolved);
    await runLocalAudit(resolved, modules, { parallel: true, extraModules });
    applyConfigTransform(config);
    applyProjectBaseline(resolved, options);

    const findings = getFindings();
    const { score } = calculateScore(undefined, { minConfidence: options.minConfidence, minSeverity: options.minSeverity });

    // Best-effort: still save the JSON history locally
    try { await exportJson(resolved, DATA_DIR); } catch {}

    const sarif = buildSarif(findings, readPkgVersion());
    const exitCode = (minScore !== null && score < minScore) ? 1 : 0;
    finish(sarif, exitCode);
  } catch (err) {
    finishError(`${err.message}\n${err.stack}`, 1);
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

// ──────────── DIFF COMMAND ────────────

async function runDiffCommand(args) {
  const oldPath = args[1];
  const newPath = args[2];
  const jsonMode = args.includes('--json');
  const markdownMode = args.includes('--markdown') || args.includes('--md');

  if (!oldPath || !newPath || oldPath.startsWith('--') || newPath.startsWith('--')) {
    console.error(chalk.red('  Usage: vice diff <old.json> <new.json> [--json|--markdown]'));
    process.exit(1);
  }

  if (!fs.existsSync(oldPath)) {
    console.error(chalk.red(`  File not found: ${oldPath}`));
    process.exit(1);
  }
  if (!fs.existsSync(newPath)) {
    console.error(chalk.red(`  File not found: ${newPath}`));
    process.exit(1);
  }

  let oldReport, newReport;
  try { oldReport = JSON.parse(fs.readFileSync(oldPath, 'utf-8')); }
  catch (err) { console.error(chalk.red(`  Failed to parse ${oldPath}: ${err.message}`)); process.exit(1); }
  try { newReport = JSON.parse(fs.readFileSync(newPath, 'utf-8')); }
  catch (err) { console.error(chalk.red(`  Failed to parse ${newPath}: ${err.message}`)); process.exit(1); }

  const oldFps = new Map();
  for (const f of oldReport.findings || []) oldFps.set(fingerprintFinding(f), f);
  const newFps = new Map();
  for (const f of newReport.findings || []) newFps.set(fingerprintFinding(f), f);

  const added = [];
  const removed = [];
  let unchanged = 0;
  for (const [fp, f] of newFps) {
    if (oldFps.has(fp)) unchanged++;
    else added.push(f);
  }
  for (const [fp, f] of oldFps) {
    if (!newFps.has(fp)) removed.push(f);
  }

  const scoreOld = oldReport.score ?? 0;
  const scoreNew = newReport.score ?? 0;
  const delta = scoreNew - scoreOld;

  // Sort by severity (severest first)
  const sevOrder = { CRITICAL: 0, CRITIQUE: 0, HIGH: 1, ELEVEE: 1, MEDIUM: 2, MOYENNE: 2, LOW: 3, FAIBLE: 3, INFO: 4 };
  const sortBySev = (a, b) => (sevOrder[a.severity] ?? 5) - (sevOrder[b.severity] ?? 5);
  added.sort(sortBySev);
  removed.sort(sortBySev);

  if (jsonMode) {
    process.stdout.write(JSON.stringify({
      scoreOld,
      scoreNew,
      scoreDelta: delta,
      gradeOld: oldReport.grade || null,
      gradeNew: newReport.grade || null,
      added,
      removed,
      unchangedCount: unchanged,
    }, null, 2) + '\n');
    return;
  }

  if (markdownMode) {
    const lines = [];
    lines.push(`## VICE Diff`);
    lines.push('');
    lines.push(`**Score:** ${scoreOld} (${oldReport.grade || '?'}) → ${scoreNew} (${newReport.grade || '?'}) (${delta >= 0 ? '+' : ''}${delta})`);
    lines.push('');
    if (added.length) {
      lines.push(`### Added (${added.length})`);
      lines.push('');
      for (const f of added) lines.push(`- **${f.severity}** ${f.module}: ${f.title}`);
      lines.push('');
    }
    if (removed.length) {
      lines.push(`### Removed (${removed.length})`);
      lines.push('');
      for (const f of removed) lines.push(`- **${f.severity}** ${f.module}: ${f.title}`);
      lines.push('');
    }
    lines.push(`Unchanged: ${unchanged}`);
    process.stdout.write(lines.join('\n') + '\n');
    return;
  }

  // Human-readable
  console.log('');
  console.log(chalk.bold('━'.repeat(60)));
  console.log(chalk.hex('#995ff6').bold('  VICE Diff'));
  console.log(chalk.gray(`  ${oldPath} → ${newPath}`));
  console.log(chalk.bold('━'.repeat(60)));
  console.log('');
  const deltaStr = delta > 0 ? chalk.green(`+${delta}`) : delta < 0 ? chalk.red(`${delta}`) : chalk.gray('0');
  console.log(`  Score: ${scoreOld} (${oldReport.grade || '?'}) → ${scoreNew} (${newReport.grade || '?'})  (${deltaStr})`);
  console.log('');

  if (added.length === 0 && removed.length === 0) {
    console.log(chalk.green('  No findings changed.\n'));
    return;
  }

  if (added.length) {
    console.log(chalk.red.bold(`  Added (${added.length}):`));
    for (const f of added) {
      console.log(`    ${severityColor(f.severity)} ${chalk.bold(f.module)} — ${f.title}`);
    }
    console.log('');
  }
  if (removed.length) {
    console.log(chalk.green.bold(`  Removed (${removed.length}):`));
    for (const f of removed) {
      console.log(`    ${severityColor(f.severity)} ${chalk.bold(f.module)} — ${f.title}`);
    }
    console.log('');
  }
  console.log(chalk.gray(`  Unchanged: ${unchanged}\n`));
}

// ──────────── BASELINE COMMAND ────────────

async function runBaselineCommand(target) {
  printBanner();
  await checkDisclaimer();
  const resolved = path.resolve(target || '.');
  if (!fs.existsSync(resolved)) {
    console.log(chalk.red(`  Path not found: ${resolved}`));
    process.exit(1);
  }

  const existing = loadBaseline(resolved);
  if (existing) {
    console.log(chalk.yellow(`  An existing baseline was found at ${getBaselinePath(resolved)}`));
    console.log(chalk.gray(`  Created: ${existing.created || 'unknown'} (vice ${existing.vice_version || 'unknown'})`));
    const { overwrite } = await inquirer.prompt([{
      type: 'confirm', name: 'overwrite',
      message: 'Overwrite with current scan?', default: false,
    }]);
    if (!overwrite) {
      console.log(chalk.gray('  Aborted.\n'));
      return;
    }
  }

  console.log(chalk.gray('\n  Running audit to capture current findings...\n'));
  clearFindings();
  const { modules, extraModules, config } = await prepareModules(resolved);
  await runLocalAudit(resolved, modules, { parallel: false, extraModules });
  applyConfigTransform(config);

  const findings = getFindings();
  const blocking = findings.filter(f => f.severity !== 'INFO');
  const file = writeBaseline(resolved, findings, readPkgVersion());

  console.log(chalk.green(`\n  Baseline written: ${file}`));
  console.log(chalk.gray(`  ${blocking.length} finding(s) snapshotted as known.`));
  console.log(chalk.gray(`  Commit ${path.basename(file)} to git: future scans will only flag NEW issues.\n`));
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

      const formatIdx = args.indexOf('--format');
      const formatValue = formatIdx !== -1 ? args[formatIdx + 1] : null;
      const sarifMode = formatValue === 'sarif';

      const outputIdx = args.indexOf('--output');
      const outputPath = outputIdx !== -1 ? args[outputIdx + 1] : null;

      // Phase 2 flags: baseline & confidence filtering
      const useBaseline = !args.includes('--no-baseline');
      const confIdx = args.indexOf('--min-confidence');
      const minConfidence = confIdx !== -1 ? args[confIdx + 1] : 'low';
      const sevIdx = args.indexOf('--severity-min');
      const minSeverity = sevIdx !== -1 ? args[sevIdx + 1] : null;
      const options = { useBaseline, minConfidence, minSeverity };

      // SARIF mode: clean stdout SARIF output for machine consumption / GitHub code scanning
      if (sarifMode) {
        const minIdx = args.indexOf('--min-score');
        const minScore = minIdx !== -1 ? parseInt(args[minIdx + 1]) : (ciMode ? 70 : null);
        await runSarifMode(target, minScore, outputPath, options);
        return;
      }

      // JSON mode: clean stdout output for machine consumption
      if (jsonMode) {
        const minIdx = args.indexOf('--min-score');
        const minScore = minIdx !== -1 ? parseInt(args[minIdx + 1]) : (ciMode ? 70 : null);
        await runJsonAuditMode(target, minScore, options);
        return;
      }

      printBanner();
      await checkDisclaimer(ciMode);

      if (ciMode) {
        const minIdx = args.indexOf('--min-score');
        const minScore = minIdx !== -1 ? parseInt(args[minIdx + 1]) : 70;
        await runCiMode(target, minScore, options);
        return;
      }
      clearFindings();
      const resolved = path.resolve(target);
      const { modules, extraModules, config } = await prepareModules(resolved);
      await runLocalAudit(resolved, modules, { parallel: false, extraModules });
      applyConfigTransform(config);
      applyProjectBaseline(resolved, options);
      printReport(`Local audit — ${path.basename(resolved)}`, { minConfidence });
      await exportJson(resolved, DATA_DIR);
      console.log(chalk.hex('#6366f1')('  Webba Creative Technologies') + chalk.gray(' — Audit complete.\n'));
      return;
    }

    if (command === 'baseline') {
      const target = args[1] && !args[1].startsWith('--') ? args[1] : '.';
      await runBaselineCommand(target);
      return;
    }

    if (command === 'scan') {
      printBanner();
      await checkDisclaimer();
      const cookieIdx = args.indexOf('--auth-cookie');
      const headerIdx = args.indexOf('--auth-header');
      const urlIdx = args.indexOf('--url');
      const scanOptions = {
        authCookie: cookieIdx !== -1 ? args[cookieIdx + 1] : null,
        authHeader: headerIdx !== -1 ? args[headerIdx + 1] : null,
        url: urlIdx !== -1 ? args[urlIdx + 1] : (args[1] && !args[1].startsWith('--') ? args[1] : null),
      };
      await runScanMode(scanOptions);
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

    if (command === 'diff') {
      await runDiffCommand(args);
      return;
    }

    // Help
    console.log(chalk.bold('\n  VICE — Vulnerability Inspector & Code Examiner\n'));
    console.log('  Usage:');
    console.log('    vice scan                            Remote scan (black-box, URL)');
    console.log('    vice audit [path]                    Local audit (white-box, source code)');
    console.log('    vice audit [path] --ci               CI mode (exits 0 if score >= threshold)');
    console.log('    vice audit [path] --ci --json        Machine-readable JSON output to stdout');
    console.log('    vice audit [path] --ci --format sarif');
    console.log('         [--output results.sarif]        SARIF v2.1.0 output for GitHub code scanning');
    console.log('    vice audit . --ci --min-score 80     Custom score threshold');
    console.log('    vice audit . --no-baseline           Ignore .vice-baseline.json');
    console.log('    vice audit . --min-confidence high   Only flag high-confidence findings');
    console.log('    vice audit . --severity-min HIGH     Only count CRITICAL+HIGH toward score');
    console.log('    vice scan <url> --auth-cookie "session=abc;remember=xyz"');
    console.log('    vice scan <url> --auth-header "Authorization: Bearer xxx"');
    console.log('    vice baseline [path]                 Snapshot current findings into .vice-baseline.json');
    console.log('    vice diff <old.json> <new.json>      Compare two scan reports');
    console.log('         [--json|--markdown]');
    console.log('    vice badge --input <report.json>     Generate shields.io badge from a report');
    console.log('         [--output .github/vice-badge.json]');
    console.log('    vice history                         View saved scan reports\n');
    console.log('  Optional: vice.config.js at project root for transformFinding/disabledModules.\n');
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
