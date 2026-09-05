import { execFileSync } from 'node:child_process';

export function contentsEndpoint(repo, file, ref) {
  if (!/^[\w.-]+\/[\w.-]+$/.test(repo || '')) throw new Error('Invalid repository');
  const parts = String(file || '').split('/');
  if (parts.some(part => !part || part === '.' || part === '..' || /[\\\x00-\x1f]/.test(part))) {
    throw new Error('Invalid badge path');
  }
  const endpoint = `repos/${repo}/contents/${parts.map(encodeURIComponent).join('/')}`;
  return ref === undefined ? endpoint : `${endpoint}?ref=${encodeURIComponent(ref)}`;
}

export function githubApi(args, execute = execFileSync) {
  return execute('gh', ['api', ...args], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
    timeout: 30000,
    maxBuffer: 8 * 1024 * 1024,
  });
}
