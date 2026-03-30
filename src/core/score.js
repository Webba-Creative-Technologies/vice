// ──────────────────────────────────────────────
// VICE — Score Calculator
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import chalk from 'chalk';
import { getFindings } from './findings.js';

// Supports both French (legacy scan.js) and English severity levels
const WEIGHT_MAP = {
  CRITIQUE: 15, CRITICAL: 15,
  ELEVEE: 8, HIGH: 8,
  MOYENNE: 3, MEDIUM: 3,
  FAIBLE: 1, LOW: 1,
  INFO: 0,
};

export function calculateScore(findingsData) {
  const data = findingsData || getFindings();
  let penalty = 0;
  for (const f of data) {
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
