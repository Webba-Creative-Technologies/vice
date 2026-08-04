import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { clearFindings, getFindings } from '../src/core/findings.js';
import { auditEnvFiles } from '../src/local/env.js';

const spinner = { text: '' };

test('environment audit discovers example and sample variants', async () => {
  const project = await mkdtemp(path.join(tmpdir(), 'vice-env-'));

  try {
    await writeFile(path.join(project, '.gitignore'), '.env*\n!.env.example\n', 'utf8');
    await writeFile(path.join(project, '.env.example'), 'API_SECRET=real-secret-value-1234\n', 'utf8');
    await writeFile(path.join(project, '.env.production.sample'), 'JWT_SECRET=another-real-secret-5678\n', 'utf8');
    clearFindings();

    await auditEnvFiles(project, spinner);

    const titles = getFindings().map((finding) => finding.title);
    assert.ok(titles.includes('.env.example contains a real secret value'));
    assert.ok(titles.includes('.env.production.sample contains a real secret value'));
  } finally {
    clearFindings();
    await rm(project, { recursive: true, force: true });
  }
});

test('environment audit ignores documented placeholder formats', async () => {
  const project = await mkdtemp(path.join(tmpdir(), 'vice-env-'));

  try {
    await writeFile(path.join(project, '.gitignore'), '.env*\n!.env.example\n', 'utf8');
    await writeFile(
      path.join(project, '.env.example'),
      [
        `STRIPE_SECRET_KEY=${['sk', 'test', 'x'.repeat(24)].join('_')}`,
        'DATABASE_URL=postgresql://user:password@db.example.com/app',
        'JWT_SECRET=VITE_PUBLIC_JWT_SECRET',
      ].join('\n'),
      'utf8',
    );
    clearFindings();

    await auditEnvFiles(project, spinner);

    assert.equal(
      getFindings().some((item) => item.title.includes('contains a real secret value')),
      false,
    );
  } finally {
    clearFindings();
    await rm(project, { recursive: true, force: true });
  }
});

test('environment audit does not require gitignore when no private environment file exists', async () => {
  const project = await mkdtemp(path.join(tmpdir(), 'vice-env-'));

  try {
    await writeFile(path.join(project, '.env.example'), 'API_SECRET=your_api_secret_here\n', 'utf8');
    clearFindings();

    await auditEnvFiles(project, spinner);

    assert.equal(getFindings().some((item) => /gitignore/i.test(item.title)), false);
  } finally {
    clearFindings();
    await rm(project, { recursive: true, force: true });
  }
});

test('environment audit accepts an explicit ignore rule for the detected file', async () => {
  const project = await mkdtemp(path.join(tmpdir(), 'vice-env-'));

  try {
    await writeFile(path.join(project, '.gitignore'), '.env.local\n', 'utf8');
    await writeFile(path.join(project, '.env.local'), 'DATABASE_URL=postgresql://user:password@localhost/app\n', 'utf8');
    clearFindings();

    await auditEnvFiles(project, spinner);

    assert.equal(getFindings().some((item) => item.title === 'Environment files are not ignored by Git'), false);
  } finally {
    clearFindings();
    await rm(project, { recursive: true, force: true });
  }
});
