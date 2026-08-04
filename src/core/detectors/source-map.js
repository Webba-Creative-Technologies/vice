import { isPlaceholderSecret, isPublicSupabaseAnonMatch, SECRET_PATTERNS } from '../../utils/patterns.js';

const ACTIONABLE_SECRET_NAMES = new Set([
  'Supabase Service Role',
  'Stripe Secret Key',
  'AWS Access Key',
  'AWS Temporary Access Key',
  'AWS Secret Key',
  'GitHub Token',
  'GitHub Fine-grained Token',
  'GitLab Token',
  'npm Token',
  'PyPI Token',
  'Slack Token',
  'SendGrid API Key',
  'Twilio Auth Token',
  'Database Credential URL',
  'Private Key',
  'Client Secret',
  'Generic API Key',
  'Generic Secret',
  'Bearer Token',
]);

const SENSITIVE_SOURCE_PATH = /(?:^|\/)(?:server|backend|internal|private|secrets?)(?:\/|$)|(?:^|\/)\.env(?:\.|$)|serviceAccountKey\.json$/i;

function detectedSecretTypes(content) {
  const names = new Set();
  for (const pattern of SECRET_PATTERNS) {
    if (!ACTIONABLE_SECRET_NAMES.has(pattern.name)) continue;
    pattern.regex.lastIndex = 0;
    let match;
    while ((match = pattern.regex.exec(content)) !== null) {
      if (match[0].length === 0) pattern.regex.lastIndex++;
      if (isPlaceholderSecret(match[0])) continue;
      if (pattern.validate && !pattern.validate(match[0])) continue;
      if (isPublicSupabaseAnonMatch(content, match[0], match.index)) continue;
      names.add(pattern.name);
      break;
    }
  }
  return [...names];
}

export function analyzeSourceMap(text) {
  let sourceMap;
  try { sourceMap = JSON.parse(text); } catch { return null; }
  if (!sourceMap || typeof sourceMap !== 'object' || !Array.isArray(sourceMap.sources)) return null;
  if (sourceMap.version !== 3 && sourceMap.version !== '3') return null;

  const sources = sourceMap.sources.filter((source) => typeof source === 'string');
  const sourceContents = Array.isArray(sourceMap.sourcesContent)
    ? sourceMap.sourcesContent.filter((content) => typeof content === 'string')
    : [];
  const combinedContent = sourceContents.join('\n').slice(0, 2 * 1024 * 1024);
  const secretTypes = detectedSecretTypes(combinedContent);
  const sensitiveSources = sources.filter((source) => SENSITIVE_SOURCE_PATH.test(source)).slice(0, 10);

  if (secretTypes.length > 0) {
    return {
      severity: 'CRITIQUE',
      kind: 'credentials',
      sourceCount: sources.length,
      embeddedSourceCount: sourceContents.length,
      secretTypes,
      sensitiveSources,
    };
  }

  if (sensitiveSources.length > 0) {
    return {
      severity: 'INFO',
      kind: 'sensitive-sources',
      sourceCount: sources.length,
      embeddedSourceCount: sourceContents.length,
      secretTypes: [],
      sensitiveSources,
    };
  }

  return {
    severity: 'INFO',
    kind: 'source-metadata',
    sourceCount: sources.length,
    embeddedSourceCount: sourceContents.length,
    secretTypes: [],
    sensitiveSources: [],
  };
}
