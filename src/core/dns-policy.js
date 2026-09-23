import { getDomain } from 'tldts';
import { dmarcPolicy, parseDirectives } from './detectors/policies.js';

export async function lookupDmarc(domain, resolveTxt) {
  const root = getDomain(domain, { allowPrivateDomains: true }) || domain;
  let owner = domain;
  for (let depth = 0; depth < 8; depth++) {
    try {
      const records = await resolveTxt(`_dmarc.${owner}`);
      const policies = records.map(chunks => chunks.join('')).filter(text => /^v=DMARC1\s*;/i.test(text.trim()));
      if (policies.length) {
        if (policies.length !== 1 || !dmarcPolicy(policies[0])) return { owner, records, effective: null };
        const directives = parseDirectives(policies[0]);
        const effective = owner === domain ? dmarcPolicy(policies[0]) : directives.get('sp') || dmarcPolicy(policies[0]);
        return { owner, records, effective: ['none', 'quarantine', 'reject'].includes(effective) ? effective : null };
      }
    } catch (error) {
      if (!['ENODATA', 'ENOTFOUND', 'NXDOMAIN'].includes(error.code)) throw error;
    }
    if (owner === root || !owner.endsWith(`.${root}`)) break;
    owner = owner.slice(owner.indexOf('.') + 1);
  }
  return { owner: domain, records: [], effective: null };
}
