// ──────────────────────────────────────────────
// VICE LOCAL — White-Box Audit Engine
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import { resolve } from 'path';
import ora from 'ora';
import chalk from 'chalk';
import { loadViceignore } from '../utils/ignore.js';
import { auditSecrets } from './secrets.js';
import { auditEnvFiles } from './env.js';
import { auditDependencies } from './dependencies.js';
import { auditSupabaseRls } from './supabase-rls.js';
import { auditAuth } from './auth.js';
import { auditCodeVulnerabilities } from './code-vulnerabilities.js';
import { auditHeadersConfig } from './headers-config.js';

export const LOCAL_MODULES = [
  { name: 'Secrets in source code', value: 'secrets', fn: auditSecrets },
  { name: 'Environment files & .gitignore', value: 'env', fn: auditEnvFiles },
  { name: 'Vulnerable dependencies (npm audit)', value: 'deps', fn: auditDependencies },
  { name: 'Supabase RLS in migrations', value: 'rls', fn: auditSupabaseRls },
  { name: 'Auth, middleware & sessions', value: 'auth', fn: auditAuth },
  { name: 'Code vulnerabilities (SQLi, XSS, eval, cmd injection)', value: 'code', fn: auditCodeVulnerabilities },
  { name: 'Security headers configuration', value: 'headers', fn: auditHeadersConfig },
];

export async function runLocalAudit(projectPath, selectedModules) {
  const cwd = process.cwd();
  const safePath = resolve(cwd, projectPath);
  if (!safePath.startsWith(cwd)) {
    throw new Error(`Path traversal detected: "${projectPath}" resolves outside the working directory`);
  }
  projectPath = safePath;

  const isIgnored = loadViceignore(projectPath);
  console.log('');

  for (const mod of LOCAL_MODULES) {
    if (!selectedModules.includes(mod.value)) continue;

    const spinner = ora({ text: mod.name + '...', color: 'magenta' }).start();
    try {
      await mod.fn(projectPath, spinner, isIgnored);
      spinner.succeed(chalk.green(mod.name));
    } catch (err) {
      spinner.fail(chalk.red(`${mod.name}: ${err.message}`));
    }
  }
}
