import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { clearFindings, getFindings } from '../src/core/findings.js';
import { auditHeadersConfig } from '../src/local/headers-config.js';

const spinner = { text: '' };

test('header audit does not infer deployment headers from an ordinary project', async () => {
  const project = await mkdtemp(path.join(tmpdir(), 'vice-headers-'));
  try {
    await writeFile(path.join(project, 'package.json'), '{"name":"library"}', 'utf8');
    clearFindings();
    await auditHeadersConfig(project, spinner);
    assert.equal(getFindings().some((finding) => /CSP|HSTS/.test(finding.title)), false);
  } finally {
    clearFindings();
    await rm(project, { recursive: true, force: true });
  }
});

test('missing headers in an inspected server layer are informational', async () => {
  const project = await mkdtemp(path.join(tmpdir(), 'vice-headers-'));
  try {
    await writeFile(path.join(project, 'nginx.conf'), 'server { add_header X-Content-Type-Options nosniff; }', 'utf8');
    clearFindings();
    await auditHeadersConfig(project, spinner);
    assert.ok(getFindings().filter((finding) => /CSP|HSTS/.test(finding.title)).every((finding) => finding.severity === 'INFO'));
  } finally {
    clearFindings();
    await rm(project, { recursive: true, force: true });
  }
});
