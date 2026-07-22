import fs from 'node:fs';
import path from 'node:path';

const MAX_CONFIG_BYTES = 128 * 1024;
const SECRET_ENV_PATTERN = /^[A-Z][A-Z0-9_]{0,63}$/;

export function loadAiRagCliConfig(configPath, environment = process.env) {
  if (typeof configPath !== 'string' || !configPath.trim()) throw new Error('ai_rag_config_path_required');
  const resolved = path.resolve(configPath);
  const stat = fs.statSync(resolved);
  if (!stat.isFile() || stat.size === 0 || stat.size > MAX_CONFIG_BYTES) {
    throw new Error('invalid_ai_rag_config_file');
  }

  const parsed = JSON.parse(fs.readFileSync(resolved, 'utf8'));
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('invalid_ai_rag_config_file');
  }

  const sourceProfiles = parsed.authProfiles ?? {};
  if (!sourceProfiles || typeof sourceProfiles !== 'object' || Array.isArray(sourceProfiles)) {
    throw new Error('invalid_ai_rag_config_file');
  }
  if (Object.keys(sourceProfiles).some((name) => name !== 'a' && name !== 'b')) {
    throw new Error('invalid_ai_rag_auth_profile');
  }

  const authProfiles = {};
  for (const name of ['a', 'b']) {
    const profile = sourceProfiles[name];
    if (profile === undefined || profile === null) continue;
    if (typeof profile !== 'object' || Array.isArray(profile)) throw new Error('invalid_ai_rag_auth_profile');
    if (Object.hasOwn(profile, 'secret') || Object.hasOwn(profile, 'value')) {
      throw new Error('ai_rag_literal_secret_forbidden');
    }
    const secretEnv = typeof profile.secretEnv === 'string' ? profile.secretEnv.trim() : '';
    if (!SECRET_ENV_PATTERN.test(secretEnv)) throw new Error('invalid_ai_rag_secret_env');
    const secret = environment[secretEnv];
    if (typeof secret !== 'string' || !secret || secret.length > 8192 || /[\r\n]/.test(secret)) {
      throw new Error(`ai_rag_secret_env_missing:${secretEnv}`);
    }
    const { secretEnv: ignoredSecretEnv, ...publicProfile } = profile;
    void ignoredSecretEnv;
    authProfiles[name] = { ...publicProfile, secret };
  }

  return { ...parsed, authProfiles };
}
