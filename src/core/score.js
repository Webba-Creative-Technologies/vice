// ──────────────────────────────────────────────
// VICE - Score Calculator
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import chalk from 'chalk';
import { getFindings } from './findings.js';
import { groupKey } from './fingerprint.js';
import { scorePresentation } from './score-policy.js';

// Supports both French (legacy scan.js) and English severity levels
const WEIGHT_MAP = {
  CRITIQUE: 15, CRITICAL: 15,
  ELEVEE: 8, HIGH: 8,
  MOYENNE: 3, MEDIUM: 3,
  FAIBLE: 1, LOW: 1,
  INFO: 0,
};

// Cap how many times the same rule can hit the score (prevents one noisy
// rule on many files from tanking the grade beyond reason).
const MAX_PENALTIES_PER_RULE = 3;

const CONFIDENCE_RANK = { high: 3, medium: 2, low: 1 };
export const SEVERITY_RANK = {
  CRITICAL: 5, CRITIQUE: 5,
  HIGH: 4, ELEVEE: 4,
  MEDIUM: 3, MOYENNE: 3,
  LOW: 2, FAIBLE: 2,
  INFO: 1,
};

export function calculateScore(findingsData, options = {}) {
  const data = findingsData || getFindings();
  const minConfidence = options.minConfidence || 'low';
  const minRank = CONFIDENCE_RANK[minConfidence] || 1;
  const minSevRank = options.minSeverity ? (SEVERITY_RANK[options.minSeverity.toUpperCase()] || 1) : 1;

  const penaltiesByRule = new Map();
  const excluded = { baselined: 0, confidence: 0, severity: 0, informational: 0 };

  for (const f of data) {
    if (f.baselined) {
      excluded.baselined++;
      continue;
    }
    const rank = CONFIDENCE_RANK[f.confidence || 'medium'] || 2;
    if (rank < minRank) {
      excluded.confidence++;
      continue;
    }
    if ((SEVERITY_RANK[f.severity] || 0) < minSevRank) {
      excluded.severity++;
      continue;
    }
    const weight = WEIGHT_MAP[f.severity] || 0;
    if (weight === 0) {
      excluded.informational++;
      continue;
    }
    const key = groupKey(f);
    const weights = penaltiesByRule.get(key) || [];
    weights.push(weight);
    penaltiesByRule.set(key, weights);
  }

  const breakdown = [...penaltiesByRule.entries()].map(([ruleId, weights]) => {
    const strongest = [...weights].sort((left, right) => right - left).slice(0, MAX_PENALTIES_PER_RULE);
    return {
      rule_id: ruleId,
      penalty: strongest.reduce((sum, weight) => sum + weight, 0),
      counted_findings: strongest.length,
      observed_findings: weights.length,
    };
  }).sort((left, right) => right.penalty - left.penalty || left.rule_id.localeCompare(right.rule_id));
  const penalty = breakdown.reduce((total, rule) => total + rule.penalty, 0);

  const rawScore = Math.max(0, 100 - penalty);
  const presentation = scorePresentation(rawScore, {
    criticalCount: data.filter(f => !f.baselined && ['CRITICAL', 'CRITIQUE'].includes(f.severity)).length,
    highCount: data.filter(f => !f.baselined && ['HIGH', 'ELEVEE'].includes(f.severity)).length,
    reliable: options.reliable,
    coverageStatus: options.coverageStatus,
    authStatus: options.authStatus,
  });
  const grade = presentation.grade;
  const color = presentation.tone === 'error' ? chalk.red.bold
    : presentation.tone === 'success' ? chalk.green.bold : chalk.yellow.bold;
  return {
    score: rawScore,
    grade,
    color,
    presentation,
    total_penalty: penalty,
    breakdown,
    excluded,
    min_confidence: minConfidence,
  };
}

const SEV_COLOR_MAP = {
  CRITIQUE: chalk.bgRed.white.bold, CRITICAL: chalk.bgRed.white.bold,
  ELEVEE: chalk.red.bold, HIGH: chalk.red.bold,
  MOYENNE: chalk.yellow.bold, MEDIUM: chalk.yellow.bold,
  FAIBLE: chalk.blue, LOW: chalk.blue,
  INFO: chalk.gray,
};

export function severityColor(sev) {
  return (SEV_COLOR_MAP[sev] || chalk.white)(` ${sev} `);
}
