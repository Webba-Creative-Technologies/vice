import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { clearFindings, getFindings } from '../src/core/findings.js';
import { auditCodeVulnerabilities } from '../src/local/code-vulnerabilities.js';

test('code audit separates direct request flows from benign sinks', async () => {
  const project = await mkdtemp(path.join(tmpdir(), 'vice-code-'));
  const sourceDir = path.join(project, 'src');
  await mkdir(sourceDir);
  await writeFile(path.join(sourceDir, 'app.js'), `
    node.innerHTML = '<strong>Ready</strong>';
    node.innerHTML = DOMPurify.sanitize(req.body.preview);
    db.query('SELECT * FROM users WHERE id = $1', [req.query.id]);
    db.query(\`SELECT * FROM users WHERE id = \${req.query.id}\`);
    output.innerHTML = req.body.html;
    res.redirect(req.query.next);
  `);

  clearFindings();
  try {
    await auditCodeVulnerabilities(project, { text: '' });
    const findings = getFindings();
    const ruleIds = findings.map((finding) => finding.rule_id);

    assert.deepEqual(ruleIds.sort(), [
      'vice/code/open-redirect',
      'vice/code/sqli-template',
      'vice/code/xss-dom',
    ]);
    assert.ok(findings.every((finding) => finding.confidence === 'high'));
  } finally {
    clearFindings();
    await rm(project, { recursive: true, force: true });
  }
});
