import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
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
