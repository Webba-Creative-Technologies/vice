// ──────────────────────────────────────────────
// VICE LOCAL — White-Box Audit Engine
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import ora from 'ora';
import chalk from 'chalk';
import { loadViceignore } from '../utils/ignore.js';
import { addFinding } from '../core/findings.js';
import { auditSecrets } from './secrets.js';
import { auditEnvFiles } from './env.js';
import { auditDependencies } from './dependencies.js';
import { auditSupabaseRls } from './supabase-rls.js';
import { auditAuth } from './auth.js';
import { auditCodeVulnerabilities } from './code-vulnerabilities.js';
import { auditHeadersConfig } from './headers-config.js';
import { auditGitHistory } from './git-history.js';
import { auditContainer } from './container.js';
import { auditCiSecurity } from './ci-security.js';

export const LOCAL_MODULES = [
  { name: 'Secrets in source code', value: 'secrets', fn: auditSecrets },
  { name: 'Environment files & .gitignore', value: 'env', fn: auditEnvFiles },
  { name: 'Vulnerable dependencies (npm audit)', value: 'deps', fn: auditDependencies },
  { name: 'Supabase RLS in migrations', value: 'rls', fn: auditSupabaseRls },
  { name: 'Auth, middleware & sessions', value: 'auth', fn: auditAuth },
  { name: 'Code vulnerabilities (SQLi, XSS, eval, cmd injection)', value: 'code', fn: auditCodeVulnerabilities },
  { name: 'Security headers configuration', value: 'headers', fn: auditHeadersConfig },
  { name: 'Git history secrets (last 500 commits)', value: 'git-history', fn: auditGitHistory },
  { name: 'Container & IaC misconfig (Dockerfile, compose)', value: 'container', fn: auditContainer },
  { name: 'CI/CD workflow security (GitHub Actions)', value: 'ci', fn: auditCiSecurity },
];

// Lightweight spinner-compatible logger used in parallel mode where ora's
// terminal redrawing would corrupt output if multiple instances share a TTY.
function makeQuietSpinner(name) {
  return {
    text: '',
    name,
    start() {
      process.stderr.write(`  ${chalk.gray('•')} ${this.name}...\n`);
      return this;
    },
    succeed(msg) {
      process.stderr.write(`  ${chalk.green('✓')} ${typeof msg === 'string' ? msg : this.name}\n`);
      return this;
    },
    fail(msg) {
      process.stderr.write(`  ${chalk.red('✗')} ${typeof msg === 'string' ? msg : this.name}\n`);
      return this;
    },
    warn() { return this; },
    info() { return this; },
    stop() { return this; },
    clear() { return this; },
  };
}

export async function runLocalAudit(projectPath, selectedModules, options = {}) {
  const isIgnored = await loadViceignore(projectPath);
  const allModules = [...LOCAL_MODULES, ...(options.extraModules || [])];
  const moduleList = allModules.filter(mod => selectedModules.includes(mod.value));
  const parallel = options.parallel === true;

  // Context passed to module functions. Custom modules use ctx.addFinding;
  // built-in modules import addFinding directly and ignore this argument.
  const ctx = { addFinding };

  if (parallel) {
    // Concurrent execution with non-redrawing spinners
    await Promise.all(moduleList.map(async (mod) => {
      const spinner = makeQuietSpinner(mod.name);
      spinner.start();
      try {
        await mod.fn(projectPath, spinner, isIgnored, ctx);
        spinner.succeed(chalk.green(mod.name));
      } catch (err) {
        spinner.fail(chalk.red(`${mod.name}: ${err.message}`));
      }
    }));
    return;
  }

  // Sequential mode with animated ora spinners (interactive use)
  console.log('');
  for (const mod of moduleList) {
    const spinner = ora({ text: mod.name + '...', color: 'magenta' }).start();
    try {
      await mod.fn(projectPath, spinner, isIgnored, ctx);
      spinner.succeed(chalk.green(mod.name));
    } catch (err) {
      spinner.fail(chalk.red(`${mod.name}: ${err.message}`));
    }
  }
}
