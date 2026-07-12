import fs from 'fs';
import path from 'path';
import { exec } from 'child_process';
import { promisify } from 'util';
import { addFinding } from '../core/findings.js';
import { classifyNpmAudit, classifyOutdatedPackages } from '../core/detectors/dependency-audit.js';

const execAsync = promisify(exec);

async function commandJson(command, cwd) {
  try {
    const { stdout } = await execAsync(command, { cwd, timeout: 30000, maxBuffer: 50 * 1024 * 1024 });
    return JSON.parse(stdout || '{}');
  } catch (error) {
    const stdout = error?.stdout?.toString() || '';
    if (stdout) return JSON.parse(stdout);
    throw error;
  }
}

function emit(result) {
  addFinding(
    result.severity,
    'Dependencies',
    result.title,
    result.detail,
    result.recommendation,
    undefined,
    result.confidence,
    { rule_id: result.rule_id, classification: result.classification },
  );
}

export async function auditDependencies(projectPath, spinner) {
  spinner.text = 'Auditing npm dependencies...';

  if (!fs.existsSync(path.join(projectPath, 'package.json'))) {
    emit({
      severity: 'INFO',
      title: 'No package.json found',
      detail: '',
      recommendation: '',
      confidence: 'high',
      classification: 'confirmed',
      rule_id: 'vice/dependencies/no-package-json',
    });
    return;
  }

  spinner.text = 'Running npm audit...';
  try {
    const audit = await commandJson('npm audit --json', projectPath);
    for (const result of classifyNpmAudit(audit)) emit(result);
  } catch {
    emit({
      severity: 'INFO',
      title: 'npm audit unavailable',
      detail: 'A lockfile and installed dependency tree are required for a reliable npm audit.',
      recommendation: 'Run npm install, then npm audit --json.',
      confidence: 'high',
      classification: 'hardening',
      rule_id: 'vice/dependencies/npm-audit-unavailable',
    });
  }

  spinner.text = 'Checking outdated packages...';
  try {
    const outdated = await commandJson('npm outdated --json', projectPath);
    const result = classifyOutdatedPackages(outdated);
    if (result) emit(result);
  } catch {
    // Outdated-package inventory is optional and must not make the audit fail.
  }
}
