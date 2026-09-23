import {
  extractAssignedSecretValue,
  isPlaceholderSecret,
  SECRET_PATTERNS,
  SUPABASE_ANON_PATTERN,
} from '../../utils/patterns.js';

const PATTERN_POLICIES = new Map([
  ['Supabase Publishable Key', ['supabase-publishable-key', 'public-config', 'high', 'not-required']],
  ['Supabase Anon Key', ['supabase-anon-key', 'public-config', 'high', 'not-required']],
  ['Stripe Publishable Key', ['stripe-publishable-key', 'public-config', 'high', 'not-required']],
  ['Firebase API Key', ['firebase-api-key', 'public-config', 'medium', 'review']],
  ['Google OAuth', ['google-oauth-client-id', 'public-config', 'high', 'not-required']],
  ['AWS Access Key', ['aws-access-key-id', 'probable-credential', 'high', 'review']],
  ['AWS Temporary Access Key', ['aws-temporary-access-key-id', 'probable-credential', 'high', 'review']],
  ['Client Secret', ['client-secret', 'probable-credential', 'medium', 'review']],
  ['Generic API Key', ['generic-api-key', 'probable-credential', 'medium', 'review']],
  ['Generic Secret', ['generic-secret', 'probable-credential', 'medium', 'review']],
  ['Bearer Token', ['bearer-token', 'probable-credential', 'medium', 'review']],
  ['Supabase Secret Key', ['supabase-secret-key', 'confirmed-secret', 'high', 'required']],
  ['Supabase Service Role', ['supabase-service-role-key', 'confirmed-secret', 'high', 'required']],
  ['Discord Webhook', ['discord-webhook', 'confirmed-secret', 'high', 'required']],
  ['Stripe Secret Key', ['stripe-secret-key', 'confirmed-secret', 'high', 'required']],
  ['AWS Secret Key', ['aws-secret-access-key', 'confirmed-secret', 'high', 'required']],
  ['GitHub Token', ['github-token', 'confirmed-secret', 'high', 'required']],
  ['GitHub Fine-grained Token', ['github-fine-grained-token', 'confirmed-secret', 'high', 'required']],
  ['GitLab Token', ['gitlab-token', 'confirmed-secret', 'high', 'required']],
  ['npm Token', ['npm-token', 'confirmed-secret', 'high', 'required']],
  ['PyPI Token', ['pypi-token', 'confirmed-secret', 'high', 'required']],
  ['Slack Token', ['slack-token', 'confirmed-secret', 'high', 'required']],
  ['SendGrid API Key', ['sendgrid-api-key', 'confirmed-secret', 'high', 'required']],
  ['Twilio Auth Token', ['twilio-auth-token', 'confirmed-secret', 'high', 'required']],
  ['Database Credential URL', ['database-credential-url', 'confirmed-secret', 'high', 'required']],
  ['Private Key', ['private-key', 'confirmed-secret', 'high', 'required']],
]);

const GENERIC_PATTERNS = new Set([
  'Client Secret',
  'Generic API Key',
  'Generic Secret',
  'Bearer Token',
]);

const CLASSIFICATION_ORDER = new Map([
  ['confirmed-secret', 0],
  ['probable-credential', 1],
  ['public-config', 2],
]);

export function secretFindingPolicy(name) {
  const policy = PATTERN_POLICIES.get(name);
  if (!policy) return { severity: 'MOYENNE', classification: 'probable', confidence: 'medium' };
  const [kind, classification, confidence] = policy;
  return {
    rule_id: `vice/secrets/${kind}`,
    severity: classification === 'public-config' ? 'INFO' : classification === 'confirmed-secret'
      ? ['Supabase Secret Key', 'Supabase Service Role', 'Database Credential URL', 'Private Key', 'AWS Secret Key', 'Stripe Secret Key'].includes(name) ? 'CRITIQUE' : 'ELEVEE'
      : 'MOYENNE',
    classification: classification === 'public-config' ? 'informational' : classification === 'confirmed-secret' ? 'confirmed' : 'probable',
    confidence,
  };
}

function hasEnvironmentReference(source, match, index) {
  const context = source.slice(Math.max(0, index - 80), index + match.length + 80);
  return /process\.env\.|import\.meta\.env\.|os\.environ|getenv\(|ENV\[|System\.getenv|config\[|Config\./i.test(context);
}

function isDuplicateGeneric(value, specificValues) {
  if (value.length < 16) return false;
  return specificValues.some((known) => (
    known.length >= 16 && (known === value || known.includes(value) || value.includes(known))
  ));
}

export function analyzeBundleExposure(sources, options = {}) {
  const safeSources = (sources || []).filter((source) => typeof source === 'string');
  const seenValues = new Set();
  const specificValues = [];
  const observations = new Map();

  for (const source of safeSources) {
    for (const pattern of [SUPABASE_ANON_PATTERN, ...SECRET_PATTERNS]) {
      const policy = PATTERN_POLICIES.get(pattern.name);
      if (!policy) continue;

      const matches = source.match(pattern.regex) || [];
      for (const match of matches) {
        if (isPlaceholderSecret(match)) continue;
        if (pattern.validate && !pattern.validate(match)) continue;
        if (/Bearer\s+(?:xxx|token|your|example|wbt_xxx|test)/i.test(match)) continue;

        const matchIndex = source.indexOf(match);
        if (hasEnvironmentReference(source, match, Math.max(matchIndex, 0))) continue;

        const value = extractAssignedSecretValue(match);
        if (GENERIC_PATTERNS.has(pattern.name) && isDuplicateGeneric(value, specificValues)) continue;

        const [kind, classification, confidence, rotation] = policy;
        const valueKey = `${kind}:${value}`;
        if (seenValues.has(valueKey)) continue;
        seenValues.add(valueKey);

        if (!GENERIC_PATTERNS.has(pattern.name)) specificValues.push(value);

        const current = observations.get(kind);
        if (current) current.occurrences += 1;
        else observations.set(kind, { kind, classification, confidence, rotation, occurrences: 1 });
      }
    }
  }

  const output = [...observations.values()].sort((left, right) => (
    CLASSIFICATION_ORDER.get(left.classification) - CLASSIFICATION_ORDER.get(right.classification)
    || left.kind.localeCompare(right.kind)
  ));
  const counts = {
    publicConfig: 0,
    probableCredential: 0,
    confirmedSecret: 0,
  };
  for (const observation of output) {
    if (observation.classification === 'public-config') counts.publicConfig += observation.occurrences;
    else if (observation.classification === 'probable-credential') counts.probableCredential += observation.occurrences;
    else counts.confirmedSecret += observation.occurrences;
  }

  return {
    bundleCount: Number.isInteger(options.bundleCount) && options.bundleCount >= 0
      ? options.bundleCount
      : 0,
    sourceCount: safeSources.length,
    analyzedBytes: safeSources.reduce((total, source) => total + Buffer.byteLength(source), 0),
    observationCount: output.length,
    counts,
    observations: output,
  };
}
