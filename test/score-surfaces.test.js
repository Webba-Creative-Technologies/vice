import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { generateBadge, readReportFile } from '../src/core/badge.js';
import { addFinding, clearFindings } from '../src/core/findings.js';
import { exportHtml } from '../src/core/reporter/html.js';
import { buildBlackBoxReport } from '../scan.js';

test('critical and provisional evidence remains visible on report surfaces', async () => {
  const directory = await mkdtemp(join(tmpdir(), 'vice-score-surfaces-'));
  try {
    clearFindings();
    addFinding('CRITICAL', 'Fixture', 'Fixture exposure', 'Synthetic evidence', 'Fixture fix');
    const filename = await exportHtml('https://fixture.example', directory, { reliable: false });
    const html = await readFile(filename, 'utf8');
    assert.match(html, /Critical findings require attention/);
    assert.match(html, /Provisional score/);
    const report = buildBlackBoxReport('https://fixture.example', { score: 85, grade: 'B', score_reliable: false, findings: [{ severity: 'CRITICAL' }] });
    assert.equal(report.presentation.critical, true);
    assert.equal(report.presentation.provisional, true);
    const json = join(directory, 'report.json');
    await writeFile(json, JSON.stringify(report));
    const parsed = readReportFile(json);
    const badge = generateBadge(parsed.score, parsed.grade, parsed.options);
    assert.equal(badge.color, 'critical');
    assert.match(badge.message, /critical/);
    assert.equal(generateBadge(100, 'F', { reliable: false }).color, 'yellow');
    assert.match(generateBadge(100, 'F').message, /^A/);
  } finally {
    clearFindings();
    await rm(directory, { recursive: true, force: true });
  }
});
