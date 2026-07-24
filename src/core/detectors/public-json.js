import { isPlaceholderSecret } from '../../utils/patterns.js';

const CREDENTIAL_KEYS = new Set([
  'password',
  'password_hash',
  'passwd',
  'token',
  'access_token',
  'refresh_token',
  'api_key',
  'secret',
  'client_secret',
  'private_key',
]);

const PERSONAL_KEYS = new Set([
  'email',
  'phone',
  'phone_number',
  'address',
  'date_of_birth',
  'birth_date',
  'ssn',
  'national_id',
]);

const SENSITIVE_KEYS = new Set([
  'unsubscribe_token',
  'key_hash',
  'key_prefix',
  'permissions',
  'scopes',
  'account_no',
  'balance',
  'bank_name',
  'tebex_transaction_id',
  'tebex_payment_id',
]);

const PLACEHOLDERS = /^(?:redacted|masked|hidden|none|null|undefined|example|placeholder|changeme|\*+)$/i;

function normalizedKey(key) {
  return String(key || '').trim().toLowerCase().replace(/[\s-]+/g, '_');
}

function meaningfulValue(value) {
  if (typeof value !== 'string' && typeof value !== 'number') return false;
  const text = String(value).trim();
  if (text.length < 4 || PLACEHOLDERS.test(text)) return false;
  if (/^(?:process\.env|import\.meta\.env|env\.)/i.test(text)) return false;
  if (isPlaceholderSecret(text)) return false;
  return true;
}

function meaningfulSensitiveValue(value) {
  if (typeof value === 'number') return Number.isFinite(value);
  if (typeof value !== 'string') return false;
  const text = value.trim();
  return text.length > 0 && !PLACEHOLDERS.test(text);
}

function walk(value, path, state, depth = 0) {
  if (depth > 8 || state.visited >= 1000 || value === null) return;
  state.visited++;

  if (Array.isArray(value)) {
    value.slice(0, 100).forEach((item, index) => walk(item, `${path}[${index}]`, state, depth + 1));
    return;
  }

  if (typeof value !== 'object') return;

  for (const [key, child] of Object.entries(value)) {
    const field = normalizedKey(key);
    const fieldPath = path ? `${path}.${key}` : key;

    if (CREDENTIAL_KEYS.has(field) && meaningfulValue(child)) {
      state.credentials.add(fieldPath);
    }
    if (PERSONAL_KEYS.has(field) && meaningfulValue(child)) {
      state.personal.add(fieldPath);
    }
    if (SENSITIVE_KEYS.has(field) && meaningfulSensitiveValue(child)) {
      state.sensitive.add(fieldPath);
    }

    walk(child, fieldPath, state, depth + 1);
  }
}

export function classifyPublicJson(data) {
  const state = {
    credentials: new Set(),
    personal: new Set(),
    sensitive: new Set(),
    visited: 0,
  };
  walk(data, '', state);

  const credentialPaths = [...state.credentials].slice(0, 10);
  const personalPaths = [...state.personal].slice(0, 10);
  const sensitivePaths = [...state.sensitive].slice(0, 10);

  if (credentialPaths.length > 0) {
    return {
      kind: 'credentials',
      severity: 'CRITIQUE',
      title: 'Unauthenticated API exposes credential fields',
      paths: credentialPaths,
    };
  }

  if (personalPaths.length > 0) {
    return {
      kind: 'personal-data',
      severity: personalPaths.length > 1 ? 'ELEVEE' : 'MOYENNE',
      title: 'Unauthenticated API exposes personal data',
      paths: personalPaths,
    };
  }

  if (sensitivePaths.length > 0) {
    return {
      kind: 'sensitive-data',
      severity: 'ELEVEE',
      title: 'Unauthenticated API exposes sensitive data',
      paths: sensitivePaths,
    };
  }

  return {
    kind: 'public-json',
    severity: 'INFO',
    title: 'Public JSON API response',
    paths: [],
  };
}
