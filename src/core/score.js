// ──────────────────────────────────────────────
// VICE — Score Calculator
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import chalk from 'chalk';
import { getFindings } from './findings.js';
import { groupKey } from './fingerprint.js';

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

  let penalty = 0;
  const counts = new Map();

  for (const f of data) {
    if (f.baselined) continue;
    const rank = CONFIDENCE_RANK[f.confidence || 'medium'] || 2;
    if (rank < minRank) continue;
    if ((SEVERITY_RANK[f.severity] || 0) < minSevRank) continue;
    const key = groupKey(f);
    const count = counts.get(key) || 0;
    if (count >= MAX_PENALTIES_PER_RULE) continue;
    counts.set(key, count + 1);
    penalty += WEIGHT_MAP[f.severity] || 0;
  }

  const rawScore = Math.max(0, 100 - penalty);
  let grade, color;
  if (rawScore >= 90) { grade = 'A'; color = chalk.green.bold; }
  else if (rawScore >= 75) { grade = 'B'; color = chalk.hex('#995ff6').bold; }
  else if (rawScore >= 60) { grade = 'C'; color = chalk.yellow.bold; }
  else if (rawScore >= 40) { grade = 'D'; color = chalk.red.bold; }
  else if (rawScore >= 20) { grade = 'E'; color = chalk.bgRed.white.bold; }
  else { grade = 'F'; color = chalk.bgRed.white.bold; }
  return { score: rawScore, grade, color };
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
