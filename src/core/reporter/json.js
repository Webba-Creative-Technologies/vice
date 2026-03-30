// ──────────────────────────────────────────────
// VICE — JSON Reporter
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import chalk from 'chalk';
import { getFindings } from '../findings.js';
import { calculateScore } from '../score.js';

export async function exportJson(url, baseDir) {
  const { score, grade } = calculateScore();
  const dir = path.join(baseDir, 'scans');
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  const hostname = url.startsWith('http') ? new URL(url).hostname : path.basename(url);
  const filename = path.join(dir, `vice-report-${hostname}-${Date.now()}.json`);
  fs.writeFileSync(filename, JSON.stringify({
    url, date: new Date().toISOString(), score, grade,
    findings: getFindings(),
  }, null, 2));
  console.log(chalk.gray(`  Rapport JSON sauvegarde: ${filename}\n`));
  return filename;
}
