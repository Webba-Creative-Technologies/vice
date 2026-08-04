// ──────────────────────────────────────────────
// VICE LOCAL - Environment Files Audit
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import { addFinding } from '../core/findings.js';
import { isPlaceholderSecret } from '../utils/patterns.js';

export async function auditEnvFiles(projectPath, spinner) {
  spinner.text = 'Auditing environment files...';

  const defaultEnvFiles = ['.env', '.env.local', '.env.production', '.env.development', '.env.staging', '.env.test'];
  let rootEntries = [];
  try { rootEntries = await fs.promises.readdir(projectPath); } catch {}
  const discoveredEnvFiles = rootEntries.filter((name) => /^\.env(?:\.[a-z0-9_-]+)*(?:\.example|\.sample)?$/i.test(name));
  const envFiles = [...new Set([...defaultEnvFiles, ...discoveredEnvFiles])];
  const presentEnvFiles = envFiles.filter((envFile) => fs.existsSync(path.join(projectPath, envFile)));
  const privateEnvFiles = presentEnvFiles.filter((envFile) => !/\.(?:example|sample)$/i.test(envFile));
  const gitignorePath = path.join(projectPath, '.gitignore');

  let gitignoreContent = '';
  let gitignoreFound = false;
  try {
    gitignoreContent = await fs.promises.readFile(gitignorePath, 'utf-8');
    gitignoreFound = true;
  } catch {}
  const matchesIgnorePattern = (filename, pattern) => {
    const normalized = pattern.replace(/^\//, '');
    if (!normalized || normalized.endsWith('/')) return false;
    const expression = normalized.replace(/[.+?^${}()|[\]\\]/g, '\\$&').replace(/\*/g, '.*');
    return new RegExp(`^${expression}$`).test(filename);
  };
  const ignoreLines = gitignoreContent.split(/\r?\n/).map((line) => line.trim()).filter((line) => line && !line.startsWith('#') && !line.startsWith('!'));
  const unignoredPrivateEnvFiles = privateEnvFiles.filter((envFile) => !ignoreLines.some((line) => matchesIgnorePattern(envFile, line)));
  if (!gitignoreFound && privateEnvFiles.length > 0) {
    addFinding('HIGH', 'Env Files', 'No .gitignore found', 'Without .gitignore, sensitive files may be committed by mistake', 'Create a .gitignore and add: .env*\nnode_modules/\ndist/');
  }

  if (gitignoreContent && unignoredPrivateEnvFiles.length > 0) {
    addFinding('HIGH', 'Env Files', 'Environment files are not ignored by Git', `Detected: ${unignoredPrivateEnvFiles.join(', ')}`, 'Add .env* to .gitignore.', undefined, 'high');
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
      if (!cleanValue || isPlaceholderSecret(`${key}=${cleanValue}`)) continue;

      const sensitiveKeys = /SECRET|PASSWORD|PRIVATE|SERVICE_ROLE|DATABASE_URL|REDIS_URL|SMTP_PASS|API_SECRET|JWT_SECRET|ENCRYPTION_KEY|MASTER_KEY/i;

      if (sensitiveKeys.test(key) && (envFile.includes('example') || envFile.includes('sample'))) {
        addFinding('CRITICAL', 'Env Files', `${envFile} contains a real secret value`, `${key} has a non-placeholder value in ${envFile}:${i + 1}. Example files should only contain placeholders.`, `Replace with: ${key}=your_${key.toLowerCase()}_here`, { file: envFile, line: i + 1 }, 'high');
      }
    }

    addFinding('INFO', 'Env Files', `${envFile} analyzed`, `${lines.filter(l => l.trim() && !l.startsWith('#')).length} variables`, '');
  }

  const configFiles = ['config.json', 'config.js', 'serviceAccountKey.json'];
  for (const configFile of configFiles) {
    const configPath = path.join(projectPath, configFile);
    let content;
    try { content = await fs.promises.readFile(configPath, 'utf-8'); } catch { continue; }
    const hasCredential = /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|["'](?:private_key|client_secret|service_account_key)["']\s*:\s*["'][^"']{16,}/i.test(content);
    const configIgnored = ignoreLines.some((line) => matchesIgnorePattern(configFile, line));
    if (hasCredential && !configIgnored) {
      addFinding('HIGH', 'Env Files', `${configFile} contains credentials and is not ignored by Git`, 'Credential material was found in this configuration file.', `Add ${configFile} to .gitignore and rotate any committed credential.`, { file: configFile }, 'high');
    }
  }
}
