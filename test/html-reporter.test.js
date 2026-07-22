import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { addFinding, clearFindings } from '../src/core/findings.js';
import { escapeHtml } from '../src/core/reporter/escape.js';
import { exportHtml } from '../src/core/reporter/html.js';

test('escapeHtml encodes text and attribute delimiters', () => {
  assert.equal(
    escapeHtml(`<img src=x onerror="alert('x')"> & more`),
    '&lt;img src=x onerror=&quot;alert(&#39;x&#39;)&quot;&gt; &amp; more',
  );
});

test('HTML reporter escapes finding content and includes a restrictive CSP', async () => {
  const baseDir = await mkdtemp(path.join(tmpdir(), 'vice-report-'));

  try {
    clearFindings();
    addFinding(
      'HIGH',
      '<img src=x onerror=alert(1)>',
      '<script>alert(1)</script>',
      `Evidence & "quoted" <iframe src=evil>`,
      `Use 'safe' output`,
    );

    const filename = await exportHtml('https://example.test/?probe=<svg onload=alert(1)>', baseDir);
    const html = await readFile(filename, 'utf8');

    assert.equal(html.includes('<script>alert(1)</script>'), false);
    assert.equal(html.includes('<img src=x onerror=alert(1)>'), false);
    assert.match(html, /&lt;script&gt;alert\(1\)&lt;\/script&gt;/);
    assert.match(html, /Evidence &amp; &quot;quoted&quot; &lt;iframe/);
    assert.match(html, /Content-Security-Policy/);
    assert.match(html, /VICE<\/a> v3\.4\.0/);
    assert.match(html, /default-src 'none'/);
  } finally {
    clearFindings();
    await rm(baseDir, { recursive: true, force: true });
  }
});
