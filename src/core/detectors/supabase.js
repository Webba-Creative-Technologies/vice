import { classifyPublicJson } from './public-json.js';

const SENSITIVE_TABLE = /(?:^|_)(?:users?|profiles?|accounts?|payments?|orders?|purchases?|transactions?|subscriptions?|credentials?|secrets?|tokens?|admins?|api_keys?|bank_accounts?)(?:$|_)/i;

const TABLE_CANDIDATE = /^[A-Za-z_][A-Za-z0-9_]{0,62}$/;

export const COMMON_SENSITIVE_TABLE_CANDIDATES = Object.freeze([
  'users',
  'profiles',
  'accounts',
  'admin_users',
  'api_keys',
  'platform_api_keys',
  'credentials',
  'secrets',
  'server_secrets',
  'tokens',
  'access_tokens',
  'refresh_tokens',
  'sessions',
  'bank_accounts',
  'player_bank_accounts',
  'payments',
  'payment_methods',
  'purchases',
  'purchase_items',
  'orders',
  'transactions',
  'invoices',
  'subscriptions',
  'customers',
  'newsletter_subscribers',
  'tickets',
  'ticket_messages',
  'ticket_notes',
  'ticket_participants',
  'integrations',
  'github_integration',
  'webhooks',
]);

export function extractSupabaseTableCandidates(sources, limit = 100) {
  const tables = new Set();
  const patterns = [
    /\.from\(\s*["']([A-Za-z_][A-Za-z0-9_]{0,62})["']\s*\)/g,
    /\/rest\/v1\/([A-Za-z_][A-Za-z0-9_]{0,62})(?:[?"'`/]|$)/g,
  ];

  for (const source of sources || []) {
    const text = String(source || '');
    for (const pattern of patterns) {
      pattern.lastIndex = 0;
      let match;
      while ((match = pattern.exec(text)) !== null) {
        if (TABLE_CANDIDATE.test(match[1])) tables.add(match[1]);
        if (tables.size >= limit) return [...tables];
      }
    }
  }
  return [...tables];
}

export function normalizeSupabaseSchemaTables(paths, limit = 100) {
  const tables = new Set();
  for (const path of paths || []) {
    const match = /^\/([A-Za-z_][A-Za-z0-9_]{0,62})$/.exec(String(path || ''));
    if (match) tables.add(match[1]);
    if (tables.size >= limit) break;
  }
  return [...tables];
}

export function classifySupabaseRead(table, data) {
  if (!Array.isArray(data) || data.length === 0) return null;

  const exposure = classifyPublicJson(data);
  if (exposure.kind === 'credentials') {
    return {
      severity: 'CRITIQUE',
      title: `Table "${table}" exposes credential fields with anon access`,
      paths: exposure.paths,
    };
  }

  if (exposure.kind === 'personal-data') {
    return {
      severity: 'ELEVEE',
      title: `Table "${table}" exposes personal data with anon access`,
      paths: exposure.paths,
    };
  }

  if (exposure.kind === 'sensitive-data') {
    return {
      severity: 'ELEVEE',
      title: `Table "${table}" exposes sensitive data with anon access`,
      paths: exposure.paths,
    };
  }

  if (SENSITIVE_TABLE.test(table)) {
    return {
      severity: 'ELEVEE',
      title: `Sensitive table "${table}" is readable with anon access`,
      paths: [],
    };
  }

  return {
    severity: 'INFO',
    title: `Public table "${table}" returns data`,
    paths: [],
  };
}

export function classifySupabaseWrite(table, status) {
  if (![200, 201, 204].includes(status)) return null;

  return {
    severity: SENSITIVE_TABLE.test(table) ? 'CRITIQUE' : 'ELEVEE',
    title: `Table "${table}" accepts anonymous inserts`,
  };
}

function rowBelongsToUser(row, identity) {
  if (!row || !identity) return null;
  const ownerValues = [row.user_id, row.userId, row.owner_id, row.ownerId, row.profile_id, row.email]
    .filter(value => value !== undefined && value !== null)
    .map(String);
  if (ownerValues.length === 0) return null;
  const expected = [identity.userId, identity.email].filter(Boolean).map(String);
  return ownerValues.some(value => expected.includes(value));
}

export function classifyAuthenticatedSupabaseRead(table, data, identity = {}) {
  if (!Array.isArray(data) || data.length === 0) return null;
  const exposure = classifyPublicJson(data);
  const ownership = data.map(row => rowBelongsToUser(row, identity));
  const hasExplicitForeignRow = ownership.some(value => value === false);
  const allExplicitRowsOwned = ownership.length > 0 && ownership.every(value => value === true);

  if (exposure.kind === 'credentials') {
    return {
      severity: 'CRITIQUE',
      confidence: 'high',
      classification: 'confirmed',
      title: `Newly registered user can read credential fields from "${table}"`,
      paths: exposure.paths,
    };
  }

  if (allExplicitRowsOwned) {
    return {
      severity: 'INFO',
      confidence: 'high',
      classification: 'confirmed',
      title: `Newly registered user reads only explicitly owned rows from "${table}"`,
      paths: [],
    };
  }

  if (hasExplicitForeignRow && (exposure.kind === 'personal-data' || exposure.kind === 'sensitive-data' || SENSITIVE_TABLE.test(table))) {
    return {
      severity: 'ELEVEE',
      confidence: 'high',
      classification: 'confirmed',
      title: `Newly registered user can read another user's data from "${table}"`,
      paths: exposure.paths || [],
    };
  }

  if (exposure.kind === 'personal-data' || exposure.kind === 'sensitive-data' || SENSITIVE_TABLE.test(table)) {
    return {
      severity: 'MOYENNE',
      confidence: 'medium',
      classification: 'probable',
      title: `Newly registered user can read sensitive rows from "${table}" without provable ownership`,
      paths: exposure.paths || [],
    };
  }

  return {
    severity: 'INFO',
    confidence: 'high',
    classification: 'confirmed',
    title: `Newly registered user can read public data from "${table}"`,
    paths: [],
  };
}
