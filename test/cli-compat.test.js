import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { spawnSync } from 'node:child_process';

import { buildSarif } from '../src/core/reporter/sarif.js';

const ROOT = fileURLToPath(new URL('..', import.meta.url));
const CLI = join(ROOT, 'bin', 'vice.js');
const SCAN_SOURCE = readFileSync(join(ROOT, 'scan.js'), 'utf8');

function createFixture() {
  const root = mkdtempSync(join(tmpdir(), 'vice-cli-'));
  const project = join(root, 'project');
  const home = join(root, 'home');
  mkdirSync(join(project, 'src'), { recursive: true });
  mkdirSync(home, { recursive: true });
  writeFileSync(join(project, 'package.json'), JSON.stringify({ name: 'vice-cli-fixture', version: '1.0.0', private: true }, null, 2));
  writeFileSync(join(project, 'src', 'app.js'), "export const status = 'ok';\n");
  return { root, project, home };
}

function runCli(args, home) {
  return spawnSync(process.execPath, [CLI, ...args], {
    cwd: ROOT,
    encoding: 'utf8',
    maxBuffer: 10 * 1024 * 1024,
    env: {
      ...process.env,
      HOME: home,
      USERPROFILE: home,
      VICE_ACCEPT_TERMS: '1',
      VICE_SKIP_GIT_HISTORY: '1',
    },
  });
}

test('public CLI keeps every documented command', () => {
  const fixture = createFixture();
  try {
    const result = runCli(['--help'], fixture.home);
    assert.equal(result.status, 0, result.stderr);
    for (const command of ['scan', 'audit', 'baseline', 'diff', 'badge', 'history']) {
      assert.match(result.stdout, new RegExp(`vice ${command}`));
    }
    assert.match(result.stdout, /--ai-rag-config vice\.ai-rag\.json/);
  } finally {
    rmSync(fixture.root, { recursive: true, force: true });
  }
});

test('interactive scanner uses the same runScan orchestrator as consumers', () => {
  const mainStart = SCAN_SOURCE.indexOf('async function main(options = {})');
  const mainEnd = SCAN_SOURCE.indexOf('export { main', mainStart);
  const mainBody = SCAN_SOURCE.slice(mainStart, mainEnd);

  assert.match(mainBody, /(?:const )?result = await runScan\(/);
  assert.doesNotMatch(mainBody, /await crawlAndExtract\(|await auditVps\(|await auditSupabase\(/);
  assert.match(mainBody, /await exportJson\(baseUrl, result\)/);
  assert.match(mainBody, /AI\/RAG application security \(API, prompts, retrieval, tools\)/);
  assert.match(mainBody, /value: 'ai-rag', checked: false/);
  assert.match(mainBody, /AI\/RAG configuration file:/);
  assert.match(mainBody, /loadAiRagCliConfig\(aiRagConfigPath\)/);
});

test('crawl failures remain operational errors', () => {
  assert.doesNotMatch(SCAN_SOURCE, /addFinding\([^\n]*Site unreachable/);
  assert.match(SCAN_SOURCE, /throw new Error\(`Unable to load \$\{baseUrl\}: \$\{message\}`\)/);
});

test('public CLI emits standalone JSON and SARIF reports', () => {
  const fixture = createFixture();
  try {
    const jsonResult = runCli(['audit', fixture.project, '--ci', '--json', '--min-score', '0', '--no-baseline'], fixture.home);
    assert.equal(jsonResult.status, 0, jsonResult.stderr);
    const report = JSON.parse(jsonResult.stdout);
    assert.equal(report.version, '3.4.0');
    assert.equal(report.target, fixture.project);
    assert.equal(typeof report.score, 'number');
    assert.ok(Array.isArray(report.findings));

    const sarifPath = join(fixture.root, 'reports', 'vice.sarif');
    const sarifResult = runCli(['audit', fixture.project, '--ci', '--format', 'sarif', '--min-score', '0', '--output', sarifPath, '--no-baseline'], fixture.home);
    assert.equal(sarifResult.status, 0, sarifResult.stderr);
    const sarif = JSON.parse(readFileSync(sarifPath, 'utf8'));
    assert.equal(sarif.version, '2.1.0');
    assert.equal(sarif.runs[0].tool.driver.version, '3.4.0');

    const historySarif = buildSarif([{
      severity: 'HIGH',
      module: 'Git History',
      title: 'Credential found in commit',
      detail: 'Commit: abc1234 by a contributor on Sun Jul 12 02:22:09 2026',
    }], '3.4.0');
    assert.equal(historySarif.runs[0].results[0].locations[0].physicalLocation.artifactLocation.uri, '.');
  } finally {
    rmSync(fixture.root, { recursive: true, force: true });
  }
});
