import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import test from 'node:test';
import { contentsEndpoint, githubApi } from '../action/api.mjs';
import { formatPrComment } from '../action/format.mjs';

test('GitHub API arguments are passed without shell evaluation', () => {
  let invocation;
  const branch = 'fixture/$(not-a-command)&ref=main';
  const endpoint = contentsEndpoint('fixture/repository', '.github/vice badge.json', branch);
  assert.match(endpoint, /vice%20badge\.json\?ref=fixture%2F/);
  assert.ok(endpoint.endsWith(encodeURIComponent(branch)));
  assert.throws(() => contentsEndpoint('fixture/repository', '../private'));
  assert.throws(() => contentsEndpoint('fixture/repository', 'a\\b'));
  assert.throws(() => contentsEndpoint('fixture/repository/extra', 'badge.json'));
  githubApi([endpoint, '--input', 'fixture with spaces.json'], (...args) => { invocation = args; return '{}'; });
  assert.equal(invocation[0], 'gh');
  assert.deepEqual(invocation[1], ['api', endpoint, '--input', 'fixture with spaces.json']);
  assert.equal(invocation[2].shell, undefined);
  assert.equal(invocation[2].timeout, 30000);
});

test('action comments preserve critical and incomplete evidence with escaped text', () => {
  const comment = formatPrComment({
    score: 95, grade: 'A', score_reliable: false,
    findings: [{ severity: 'CRITICAL', title: '![image](https://example.test)', detail: '<script>fixture</script>' }],
    summary: { total: 1, critical: 1 },
  });
  assert.match(comment, /Critical findings require attention/);
  assert.match(comment, /Provisional score/);
  assert.ok(comment.includes('\\!\\[image\\]\\(https://example.test\\)'));
  assert.doesNotMatch(comment, /<script>|&mdash;|\u2014/);
  assert.match(formatPrComment({ score: null, grade: 'A' }), /Score unavailable/);
});

test('action outputs reject forged grades and multiline counts', async () => {
  const directory = await mkdtemp(path.join(tmpdir(), 'vice-action-fixture-'));
  try {
    const report = path.join(directory, 'report.json');
    const output = path.join(directory, 'output.txt');
    await writeFile(report, JSON.stringify({ score: 95, grade: 'F\nforged=true', summary: { total: '1\nforged=true' } }));
    const result = spawnSync(process.execPath, [new URL('../action/set-outputs.mjs', import.meta.url).pathname.replace(/^\/(?=[A-Za-z]:)/, ''), report], {
      encoding: 'utf8', env: { ...process.env, GITHUB_OUTPUT: output },
    });
    assert.equal(result.status, 0, result.stderr);
    const content = await readFile(output, 'utf8');
    assert.match(content, /grade=A\n/);
    assert.match(content, /total=0\n/);
    assert.doesNotMatch(content, /forged/);
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
});

test('action scripts keep user inputs out of shell source and install locked dependencies', async () => {
  const workflow = await readFile(new URL('../action.yml', import.meta.url), 'utf8');
  assert.match(workflow, /npm ci --omit=dev --omit=optional --ignore-scripts/);
  const runLines = workflow.split('\n').filter(line => /run:|node |echo /.test(line));
  assert.equal(runLines.some(line => line.includes('${{ inputs.')), false);
  for (const file of ['post-comment.mjs', 'update-badge.mjs']) {
    assert.doesNotMatch(await readFile(new URL('../action/' + file, import.meta.url), 'utf8'), /execSync/);
  }
});
