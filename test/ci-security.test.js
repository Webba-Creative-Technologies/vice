import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { clearFindings, getFindings } from '../src/core/findings.js';
import { auditCiSecurity } from '../src/local/ci-security.js';

const spinner = { text: '' };

test('CI audit scans GitLab without GitHub Actions', async () => {
  const project = await mkdtemp(path.join(tmpdir(), 'vice-ci-'));

  try {
    await writeFile(path.join(project, '.gitlab-ci.yml'), 'image: node:latest\nvariables:\n  API_TOKEN: "real-token-value-1234"\n', 'utf8');
    clearFindings();

    await auditCiSecurity(project, spinner);

    const titles = getFindings().map((finding) => finding.title);
    assert.ok(titles.some((title) => title.includes('GitLab CI image')));
    assert.ok(titles.some((title) => title.includes('Hardcoded secret')));
  } finally {
    clearFindings();
    await rm(project, { recursive: true, force: true });
  }
});

test('CI audit does not treat pull_request_target alone as a vulnerability', async () => {
  const project = await mkdtemp(path.join(tmpdir(), 'vice-ci-'));

  try {
    const workflows = path.join(project, '.github', 'workflows');
    await mkdir(workflows, { recursive: true });
    await writeFile(path.join(workflows, 'label.yml'), 'on: pull_request_target\njobs:\n  label:\n    steps:\n      - uses: actions/github-script@v7\n', 'utf8');
    clearFindings();

    await auditCiSecurity(project, spinner);

    const findings = getFindings();
    assert.equal(findings.some((finding) => finding.title.includes('pull_request_target trigger')), false);
    assert.equal(findings.find((finding) => finding.title.includes('actions/github-script'))?.severity, 'INFO');
  } finally {
    clearFindings();
    await rm(project, { recursive: true, force: true });
  }
});
