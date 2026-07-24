import assert from 'node:assert/strict';
import test from 'node:test';

import { classifySensitiveFile } from '../src/core/detectors/sensitive-file.js';

test('sensitive file detector confirms private environment values', () => {
  const result = classifySensitiveFile('/.env', 'DATABASE_URL=postgresql://user:A7f9K2mQ8vX4@db.acme-secure.net/app', 'text/plain');
  assert.equal(result.severity, 'CRITIQUE');
  assert.equal(result.classification, 'confirmed');
});

test('sensitive file detector lowers public environment configuration', () => {
  const result = classifySensitiveFile('/.env.production', 'PUBLIC_SITE_NAME=VICE\nPUBLIC_THEME=dark', 'text/plain');
  assert.equal(result.severity, 'MOYENNE');
});

test('sensitive file detector does not confirm placeholder secrets', () => {
  const result = classifySensitiveFile(
    '/.env.example',
    [
      `STRIPE_SECRET_KEY=${['sk', 'test', 'x'.repeat(24)].join('_')}`,
      'DATABASE_URL=postgresql://user:password@db.example.com/app',
    ].join('\n'),
    'text/plain',
  );

  assert.equal(result.severity, 'MOYENNE');
  assert.equal(result.kind, 'environment configuration');
  assert.equal(result.classification, 'probable');
});

test('sensitive file detector rejects SPA and fake responses', () => {
  assert.equal(classifySensitiveFile('/.env', '<html><body>Application</body></html>', 'text/html'), null);
  assert.equal(classifySensitiveFile('/package.json', '{"error":"not found"}', 'application/json'), null);
  assert.equal(classifySensitiveFile('/.git/HEAD', 'Not found', 'text/plain'), null);
});

test('package manifest is hardening rather than high severity', () => {
  const result = classifySensitiveFile('/package.json', '{"name":"demo","scripts":{"start":"node app.js"}}', 'application/json');
  assert.equal(result.severity, 'FAIBLE');
  assert.equal(result.classification, 'hardening');
});

test('ordinary public JSON config is not a sensitive-file finding', () => {
  assert.equal(classifySensitiveFile('/config.json', '{"apiUrl":"https://api.example.test"}', 'application/json'), null);
  assert.equal(classifySensitiveFile('/config.json', '{"database_url":"postgresql://private"}', 'application/json').severity, 'CRITIQUE');
});

test('Git and WordPress signatures require recognizable content', () => {
  assert.equal(classifySensitiveFile('/.git/HEAD', 'ref: refs/heads/main', 'text/plain').severity, 'ELEVEE');
  assert.equal(classifySensitiveFile('/wp-config.php', "define('DB_PASSWORD', 'secret');", 'text/plain').severity, 'CRITIQUE');
});
