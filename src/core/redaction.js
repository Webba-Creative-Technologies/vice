import { SECRET_PATTERNS } from '../utils/patterns.js';

const PUBLIC_PATTERN_NAMES = new Set([
  'Stripe Publishable Key',
  'Firebase API Key',
  'Google OAuth',
]);

function replacePattern(text, pattern) {
  const regex = new RegExp(pattern.regex.source, pattern.regex.flags);

  return text.replace(regex, match => {
    if (pattern.validate && !pattern.validate(match)) return match;
    return `[REDACTED:${pattern.name}]`;
  });
}

export function redactSensitiveText(value) {
  if (typeof value !== 'string' || value.length === 0) return value;

  return SECRET_PATTERNS.reduce((text, pattern) => {
    if (PUBLIC_PATTERN_NAMES.has(pattern.name)) return text;
    return replacePattern(text, pattern);
  }, value);
}

export function redactSensitiveValue(value) {
  if (typeof value === 'string') return redactSensitiveText(value);
  if (Array.isArray(value)) return value.map(redactSensitiveValue);
  if (!value || typeof value !== 'object') return value;

  return Object.fromEntries(
    Object.entries(value).map(([key, entry]) => [key, redactSensitiveValue(entry)]),
  );
}
