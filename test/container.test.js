import assert from 'node:assert/strict';
import { mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { clearFindings, getFindings } from '../src/core/findings.js';
import { auditContainer } from '../src/local/container.js';

const spinner = { text: '' };

test('container audit detects quoted public Compose ports', async () => {
  const project = await mkdtemp(path.join(tmpdir(), 'vice-compose-'));

  try {
    await writeFile(path.join(project, 'compose.yml'), 'services:\n  db:\n    image: postgres:17\n    ports:\n      - "5432:5432"\n', 'utf8');
    clearFindings();

    await auditContainer(project, spinner);

    const finding = getFindings().find((item) => item.title.includes('0.0.0.0:5432'));
    assert.equal(finding?.severity, 'HIGH');
  } finally {
    clearFindings();
    await rm(project, { recursive: true, force: true });
  }
});

test('container audit ignores localhost Compose bindings', async () => {
  const project = await mkdtemp(path.join(tmpdir(), 'vice-compose-'));

  try {
    await writeFile(path.join(project, 'compose.yml'), 'services:\n  db:\n    image: postgres:17\n    ports:\n      - "127.0.0.1:5432:5432"\n', 'utf8');
    clearFindings();

    await auditContainer(project, spinner);

    assert.equal(getFindings().some((item) => item.title.includes('0.0.0.0:5432')), false);
  } finally {
    clearFindings();
    await rm(project, { recursive: true, force: true });
  }
});

test('container audit detects host escape and isolation controls', async () => {
  const project = await mkdtemp(path.join(tmpdir(), 'vice-compose-'));

  try {
    await writeFile(path.join(project, 'compose.yml'), `services:
  worker:
    image: worker:1.0.0
    network_mode: host
    pid: host
    ipc: host
    cap_add:
      - ALL
    security_opt:
      - seccomp:unconfined
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
`, 'utf8');
    clearFindings();

    await auditContainer(project, spinner);

    const findings = getFindings();
    const titles = findings.map(item => item.title);
    assert.equal(findings.find(item => item.title.includes('Docker socket'))?.severity, 'CRITICAL');
    assert.ok(titles.some(title => title.includes('host network namespace')));
    assert.ok(titles.some(title => title.includes('host PID namespace')));
    assert.ok(titles.some(title => title.includes('host IPC namespace')));
    assert.ok(titles.some(title => title.includes('All Linux capabilities')));
    assert.ok(titles.some(title => title.includes('Unconfined security profile')));
  } finally {
    clearFindings();
    await rm(project, { recursive: true, force: true });
  }
});

test('container findings never retain detected environment values', async () => {
  const project = await mkdtemp(path.join(tmpdir(), 'vice-compose-'));

  try {
    await writeFile(path.join(project, 'compose.yml'), 'services:\n  app:\n    image: app:1.0.0\n    environment:\n      API_TOKEN: super-private-token-value\n', 'utf8');
    clearFindings();

    await auditContainer(project, spinner);

    assert.equal(JSON.stringify(getFindings()).includes('super-private-token-value'), false);
  } finally {
    clearFindings();
    await rm(project, { recursive: true, force: true });
  }
});
