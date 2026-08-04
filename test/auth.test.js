import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { clearFindings, getFindings } from '../src/core/findings.js';
import { auditAuth } from '../src/local/auth.js';

const spinner = { text: '' };

async function withProject(source, assertion) {
  const project = await mkdtemp(path.join(tmpdir(), 'vice-auth-'));
  try {
    await writeFile(path.join(project, 'app.js'), source, 'utf8');
    clearFindings();
    await auditAuth(project, spinner);
    await assertion(getFindings());
  } finally {
    clearFindings();
    await rm(project, { recursive: true, force: true });
  }
}

test('auth audit does not infer missing controls for a project without login', async () => {
  await withProject('export function formatDate(value) { return String(value); }', (findings) => {
    assert.equal(findings.some((finding) => /rate limit|csrf|auth middleware/i.test(finding.title)), false);
  });
});

test('CORS requires arbitrary origin reflection with credentials to become actionable', async () => {
  await withProject("app.use(cors({ origin: '*' }));", (findings) => {
    assert.equal(findings.some((finding) => /Credentialed CORS/i.test(finding.title)), false);
  });
  await withProject("app.use(cors({ origin: '*', credentials: true }));", (findings) => {
    assert.equal(findings.some((finding) => /Credentialed CORS/i.test(finding.title)), false);
  });
  await withProject("app.use(cors({ origin: true, credentials: true }));", (findings) => {
    assert.equal(findings.find((finding) => /Credentialed CORS/i.test(finding.title))?.severity, 'HIGH');
  });
});

test('session defaults are not treated as disabled cookie protection', async () => {
  await withProject("app.use(session({ secret: process.env.SESSION_SECRET }));", (findings) => {
    assert.equal(findings.some((finding) => /accessible to scripts/i.test(finding.title)), false);
  });
  await withProject("app.use(session({ cookie: { httpOnly: false } }));", (findings) => {
    assert.equal(findings.find((finding) => /accessible to scripts/i.test(finding.title))?.severity, 'HIGH');
  });
});
