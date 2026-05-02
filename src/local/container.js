// ──────────────────────────────────────────────
// VICE LOCAL — Container & IaC Audit
// Reviews Dockerfile and docker-compose for common misconfigurations:
// running as root, secrets baked into images, untagged base images,
// services exposed on 0.0.0.0, and privileged containers.
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import { addFinding } from '../core/findings.js';

function getLine(content, position) {
  return content.substring(0, position).split('\n').length;
}

function auditDockerfile(content, rel) {
  let issues = 0;

  // FROM with :latest or no tag
  const fromRegex = /^FROM\s+(--platform=\S+\s+)?(\S+)(\s+AS\s+\S+)?\s*$/gim;
  let m;
  while ((m = fromRegex.exec(content)) !== null) {
    const image = m[2];
    if (image.startsWith('scratch')) continue;
    const tag = image.split(':')[1];
    const line = getLine(content, m.index);
    if (!tag) {
      addFinding('LOW', 'Container', `FROM without explicit tag in ${rel}:${line}`,
        `${m[0].trim()}\nNo tag specified - defaults to :latest, making builds non-reproducible.`,
        `Pin to a specific version: FROM ${image}:1.2.3 or use a digest.`,
        { file: rel, line }, 'high');
      issues++;
    } else if (tag === 'latest') {
      addFinding('LOW', 'Container', `FROM uses :latest in ${rel}:${line}`,
        `${m[0].trim()}\nLatest tag changes silently and breaks reproducibility.`,
        `Pin to a specific version: FROM ${image.split(':')[0]}:1.2.3`,
        { file: rel, line }, 'high');
      issues++;
    }
  }

  // No USER directive (or runs as root)
  const userMatches = [...content.matchAll(/^USER\s+(\S+)/gim)];
  if (userMatches.length === 0) {
    addFinding('MEDIUM', 'Container', `No USER directive in ${rel}`,
      `Container will run as root by default. Privilege escalation risk if the process is exploited.`,
      `Add a non-root user: \n  RUN adduser -D appuser\n  USER appuser`,
      { file: rel }, 'high');
    issues++;
  } else {
    const lastUser = userMatches[userMatches.length - 1];
    const userVal = lastUser[1].trim();
    if (userVal === '0' || userVal === 'root') {
      const line = getLine(content, lastUser.index);
      addFinding('MEDIUM', 'Container', `USER root explicitly set in ${rel}:${line}`,
        `Container runs as root.`,
        `Use a non-root user: USER appuser (after creating it via RUN adduser).`,
        { file: rel, line }, 'high');
      issues++;
    }
  }

  // ADD with URL (no checksum verification possible)
  const addUrlRegex = /^ADD\s+(?:--\S+\s+)*https?:\/\/\S+/gim;
  while ((m = addUrlRegex.exec(content)) !== null) {
    const line = getLine(content, m.index);
    addFinding('MEDIUM', 'Container', `ADD with URL in ${rel}:${line}`,
      `${m[0]}\nADD does not verify checksums. A compromised origin would push malicious content into your image.`,
      `Replace with: RUN curl -fsSL <url> -o file && echo "<sha256>  file" | sha256sum -c`,
      { file: rel, line }, 'medium');
    issues++;
  }

  // Hardcoded secrets in ENV
  const envSecretRegex = /^ENV\s+\w*(?:SECRET|PASSWORD|API[_-]?KEY|TOKEN|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)\w*[\s=]+\S+/gim;
  while ((m = envSecretRegex.exec(content)) !== null) {
    const line = getLine(content, m.index);
    // Skip if value is a placeholder
    if (/your_|example|placeholder|xxx|changeme|\$\{/i.test(m[0])) continue;
    addFinding('CRITICAL', 'Container', `Potential secret in ENV in ${rel}:${line}`,
      `${m[0]}\nSecrets baked into image layers are accessible to anyone with the image. They cannot be revoked from existing pulls.`,
      `Pass secrets at runtime instead: docker run -e SECRET=val (or use Docker/Compose secrets).`,
      { file: rel, line }, 'high');
    issues++;
  }

  return issues;
}

function auditCompose(content, rel) {
  let issues = 0;
  let m;

  // privileged: true
  const privRegex = /^[ \t]+privileged:\s*true/gim;
  while ((m = privRegex.exec(content)) !== null) {
    const line = getLine(content, m.index);
    addFinding('HIGH', 'Container', `privileged: true in ${rel}:${line}`,
      `Container has full host access. Effectively root on the Docker host.`,
      `Remove privileged: true. If specific capabilities are needed, use cap_add.`,
      { file: rel, line }, 'high');
    issues++;
  }

  // Ports bound to 0.0.0.0 (or no host binding, which defaults to 0.0.0.0)
  const portRegex = /^[ \t]*-\s*["']?0\.0\.0\.0:(\d+):/gm;
  while ((m = portRegex.exec(content)) !== null) {
    const port = parseInt(m[1]);
    const line = getLine(content, m.index);
    const dbPorts = [3306, 5432, 27017, 6379, 9200, 11211, 5984];
    const sev = dbPorts.includes(port) ? 'HIGH' : 'MEDIUM';
    addFinding(sev, 'Container', `Service exposed on 0.0.0.0:${port} in ${rel}:${line}`,
      `Service is reachable from any network interface. ${dbPorts.includes(port) ? 'Database services should only be reachable on localhost or internal networks.' : 'Consider whether external exposure is intended.'}`,
      `Bind to localhost: "127.0.0.1:${port}:${port}" - or remove the host binding to keep it on the internal Compose network only.`,
      { file: rel, line }, 'medium');
    issues++;
  }

  // Hardcoded secrets in environment:
  const envSecretRegex = /^[ \t]+(?:-\s+)?(\w*(?:SECRET|PASSWORD|API[_-]?KEY|TOKEN|PRIVATE[_-]?KEY|ACCESS[_-]?KEY)\w*)\s*[:=]\s*["']?([^"'\n${}]+)["']?/gim;
  while ((m = envSecretRegex.exec(content)) !== null) {
    const value = m[2].trim();
    if (!value || value.length < 6) continue;
    if (/your_|example|placeholder|xxx|changeme|\$\{/i.test(value)) continue;
    const line = getLine(content, m.index);
    addFinding('CRITICAL', 'Container', `Potential secret in environment in ${rel}:${line}`,
      `${m[0].trim()}\nCommitted secrets in compose files are visible to anyone with repo access and history.`,
      `Use a .env file (in .gitignore) referenced via env_file: or use Docker secrets.`,
      { file: rel, line }, 'high');
    issues++;
  }

  return issues;
}

export async function auditContainer(projectPath, spinner) {
  spinner.text = 'Auditing container configuration...';

  let issues = 0;
  let scanned = 0;

  const dockerfilePath = path.join(projectPath, 'Dockerfile');
  let dockerfileContent;
  try { dockerfileContent = await fs.promises.readFile(dockerfilePath, 'utf-8'); } catch {}
  if (dockerfileContent) {
    scanned++;
    issues += auditDockerfile(dockerfileContent, 'Dockerfile');
  }

  for (const name of ['docker-compose.yml', 'docker-compose.yaml', 'compose.yml', 'compose.yaml']) {
    const composePath = path.join(projectPath, name);
    let content;
    try { content = await fs.promises.readFile(composePath, 'utf-8'); } catch { continue; }
    scanned++;
    issues += auditCompose(content, name);
  }

  if (scanned === 0) {
    addFinding('INFO', 'Container', 'No Dockerfile or docker-compose found', '', '');
  } else if (issues === 0) {
    addFinding('INFO', 'Container', `${scanned} container file(s) scanned, no issues`, '', '');
  }
}
