import { fingerprintFinding } from './fingerprint.js';
import { redactSensitiveValue } from './redaction.js';
import { findingToRuleId } from './reporter/sarif.js';
import { ENGINE_VERSION, RULESET_VERSION } from './version.js';

function slugify(value) {
  return String(value || '')
    .toLowerCase()
    .replace(/https?:\/\/\S+/g, 'url')
    .replace(/["'`](?:[^"'`]|\\.)*["'`]/g, 'value')
    .replace(/\b\d+\b/g, 'number')
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/^-+|-+$/g, '')
    .slice(0, 72) || 'generic';
}

export function deriveRuleId(finding) {
  const taxonomyId = findingToRuleId(finding);
  if (!/(?:generic|issue|misconfig)$/.test(taxonomyId)) return taxonomyId;

  const prefix = taxonomyId.replace(/\/(?:generic|issue|misconfig)$/, '');
  return `${prefix}/${slugify(finding.title)}`;
}

export function inferFindingClassification(finding) {
  const module = String(finding.module || '').toLowerCase();
  const title = String(finding.title || '').toLowerCase();

  if (
    ['csp', 'sri', 'stack detection', 'headers', 'source map'].includes(module)
    && /missing|detectable|public|exposed|without|^no\s/.test(title)
  ) return 'hardening';

  if (/confirmed|succeeded|exposes|readable|writable|expired|weak cipher|open redirect detected|xss reflected detected|access obtained/.test(title)) {
    return 'confirmed';
  }

  if (/potential|possible|could|may |no explicit|without .* flag|not detected/.test(title)) {
    return 'heuristic';
  }

  return 'probable';
}

function confidenceForClassification(classification) {
  if (classification === 'confirmed' || classification === 'hardening') return 'high';
  if (classification === 'heuristic') return 'low';
  return 'medium';
}

export function decorateFinding(finding) {
  const safeFinding = redactSensitiveValue(finding);
  const ruleId = safeFinding.rule_id || safeFinding.ruleId || deriveRuleId(safeFinding);
  const classification = safeFinding.classification || inferFindingClassification(safeFinding);
  const decorated = {
    ...safeFinding,
    rule_id: ruleId,
    confidence: safeFinding.confidence || confidenceForClassification(classification),
    classification,
    engine_version: ENGINE_VERSION,
    ruleset_version: RULESET_VERSION,
  };

  return {
    ...decorated,
    fingerprint: safeFinding.fingerprint || fingerprintFinding(decorated),
  };
}
