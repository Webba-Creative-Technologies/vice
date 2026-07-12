import { createHash } from 'node:crypto';

export function createSupabaseCanary(projectUrl, purpose = 'audit') {
  const hostname = new URL(projectUrl).hostname.toLowerCase();
  const id = createHash('sha256').update(`${hostname}:${purpose}`).digest('hex').slice(0, 20);
  return {
    id,
    email: `vice-${purpose}-${id}@example.invalid`,
    password: `Vice!${id}Aa9`,
  };
}
