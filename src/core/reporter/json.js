// ──────────────────────────────────────────────
// VICE - JSON Reporter
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import { getFindings } from '../findings.js';
import { calculateScore } from '../score.js';
import { ENGINE_VERSION, RULESET_VERSION, SCORING_VERSION } from '../version.js';

export async function exportJson(url, baseDir, options = {}) {
  const { score, grade, presentation } = calculateScore(undefined, options);
  const dir = path.join(baseDir, 'scans');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const hostname = url.startsWith('http') ? new URL(url).hostname : path.basename(url);
  const filename = path.join(dir, `vice-report-${hostname}-${Date.now()}.json`);
  fs.writeFileSync(filename, JSON.stringify({
    url, date: new Date().toISOString(), score, grade, presentation,
    score_reliable: options.reliable ?? null,
    score_options: { minConfidence: options.minConfidence, minSeverity: options.minSeverity },
    engine_version: ENGINE_VERSION,
    ruleset_version: RULESET_VERSION,
    scoring_version: SCORING_VERSION,
    findings: getFindings(),
  }, null, 2));
  console.log(chalk.gray(`  Rapport JSON sauvegarde: ${filename}\n`));
  return filename;
}
