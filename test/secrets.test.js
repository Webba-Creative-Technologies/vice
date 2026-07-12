import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { clearFindings, getFindings } from '../src/core/findings.js';
import { auditSecrets } from '../src/local/secrets.js';

const spinner = { text: '' };

test('secret audit detects active duplicate after commented value', async () => {
  const project = await mkdtemp(path.join(tmpdir(), 'vice-secrets-'));
  const secret = 'sk_live_1234567890abcdefghijkl';

  try {
    await writeFile(path.join(project, 'config.js'), `// const oldKey = '${secret}';\nconst activeKey = '${secret}';\n`, 'utf8');
    clearFindings();

    await auditSecrets(project, spinner);

    const finding = getFindings().find((item) => item.title.includes('Stripe Secret Key'));
    assert.equal(finding?.location?.line, 2);
  } finally {
    clearFindings();
    await rm(project, { recursive: true, force: true });
  }
});

test('secret audit keeps Stripe test credentials actionable', async () => {
  const project = await mkdtemp(path.join(tmpdir(), 'vice-secrets-'));

  try {
    await writeFile(path.join(project, 'config.js'), 'const stripeKey = "sk_test_1234567890abcdefghijkl";\n', 'utf8');
    clearFindings();

    await auditSecrets(project, spinner);

    assert.ok(getFindings().some((item) => item.title.includes('Stripe Secret Key')));
  } finally {
    clearFindings();
    await rm(project, { recursive: true, force: true });
  }
});
