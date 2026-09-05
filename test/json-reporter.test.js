import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { addFinding, clearFindings } from '../src/core/findings.js';
import { exportJson } from '../src/core/reporter/json.js';

test('JSON reports expose engine, ruleset and scoring versions', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'vice-json-'));
  clearFindings();
  addFinding('INFO', 'Test', 'Version fixture', '', '');

  try {
    const filename = await exportJson('example.test', directory);
    const report = JSON.parse(await readFile(filename, 'utf8'));

    assert.equal(report.engine_version, '3.4.1');
    assert.equal(report.ruleset_version, '2026.09.05.1');
    assert.equal(report.scoring_version, '2026.07.11.3');
  } finally {
    clearFindings();
    await rm(directory, { recursive: true, force: true });
  }
});
