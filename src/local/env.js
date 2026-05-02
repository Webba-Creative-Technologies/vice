// ──────────────────────────────────────────────
// VICE LOCAL — Environment Files Audit
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import { addFinding } from '../core/findings.js';

export async function auditEnvFiles(projectPath, spinner) {
  spinner.text = 'Auditing environment files...';

  const envFiles = ['.env', '.env.local', '.env.production', '.env.development', '.env.staging', '.env.test'];
  const gitignorePath = path.join(projectPath, '.gitignore');

  let gitignoreContent = '';
  let gitignoreFound = false;
  try {
    gitignoreContent = await fs.promises.readFile(gitignorePath, 'utf-8');
    gitignoreFound = true;
  } catch {}
  if (!gitignoreFound) {
    addFinding('HIGH', 'Env Files', 'No .gitignore found', 'Without .gitignore, sensitive files may be committed by mistake', 'Create a .gitignore and add: .env*\nnode_modules/\ndist/');
  }

  const envIgnored = /^\.env\*?$/m.test(gitignoreContent) || /^\.env$/m.test(gitignoreContent);
  if (!envIgnored && gitignoreContent) {
    addFinding('CRITICAL', 'Env Files', '.env is not in .gitignore', 'Env files containing secrets could be committed to the git repository', 'Add .env* to .gitignore');
  }

  for (const envFile of envFiles) {
    const envPath = path.join(projectPath, envFile);
    let content;
    try {
      content = await fs.promises.readFile(envPath, 'utf-8');
    } catch { continue; }
    const lines = content.split('\n');

    for (let i = 0; i < lines.length; i++) {
      const line = lines[i].trim();
      if (!line || line.startsWith('#')) continue;

      const match = line.match(/^([A-Z_][A-Z0-9_]*)=(.+)$/);
      if (!match) continue;

      const [, key, value] = match;
      const cleanValue = value.replace(/^["']|["']$/g, '');
      if (!cleanValue || /your_|example|changeme|replace|xxx/i.test(cleanValue)) continue;

      const sensitiveKeys = /SECRET|PASSWORD|PRIVATE|SERVICE_ROLE|DATABASE_URL|REDIS_URL|SMTP_PASS|API_SECRET|JWT_SECRET|ENCRYPTION_KEY|MASTER_KEY/i;

      if (sensitiveKeys.test(key) && (envFile.includes('example') || envFile.includes('sample'))) {
        addFinding('CRITICAL', 'Env Files', `${envFile} contains a real secret value`, `${key}=${cleanValue.substring(0, 10)}*** in ${envFile}:${i + 1}\n.env.example files should only contain placeholders.`, `Replace with: ${key}=your_${key.toLowerCase()}_here`);
      }
    }

    addFinding('INFO', 'Env Files', `${envFile} analyzed`, `${lines.filter(l => l.trim() && !l.startsWith('#')).length} variables`, '');
  }

  const configFiles = ['config.json', 'config.js', 'serviceAccountKey.json'];
  for (const configFile of configFiles) {
    const configPath = path.join(projectPath, configFile);
    if (fs.existsSync(configPath) && !gitignoreContent.includes(configFile) && /serviceAccount|private_key|secret/i.test(configFile)) {
      addFinding('HIGH', 'Env Files', `${configFile} may contain secrets and is not in .gitignore`, '', `Add ${configFile} to .gitignore`);
    }
  }
}
