import { createHash } from 'node:crypto';

// This proof only covers the missing-policy finding, not overall email security.
export function dnsPolicyOutcome(kind, domain, records, error = null) {
  if (!['spf', 'dmarc'].includes(kind)) throw new Error('invalid_dns_policy_kind');
  const key = `dns-${kind}-presence-v1:${createHash('sha256').update(String(domain).toLowerCase()).digest('hex')}`;
  const absent = error && ['ENODATA', 'ENOTFOUND', 'NXDOMAIN'].includes(error.code);
  if (error || !Array.isArray(records)) return { key, version: '1', outcome: absent ? 'fail' : 'unknown' };
  const prefix = kind === 'spf' ? /^v=spf1(?:\s|$)/i : /^v=DMARC1\s*;/i;
  const policies = records.filter(record => Array.isArray(record) && record.every(chunk => typeof chunk === 'string')).map(record => record.join('').trim()).filter(record => prefix.test(record));
  if (!policies.length) return { key, version: '1', outcome: 'fail' };
  const effective = kind === 'spf' ? /(?:^|\s)[~-]all(?:\s|$)/i.test(policies[0]) : /;\s*p\s*=\s*(quarantine|reject)\s*(;|$)/i.test(policies[0]);
  return { key, version: '1', outcome: policies.length === 1 && effective ? 'pass' : 'unknown' };
}
