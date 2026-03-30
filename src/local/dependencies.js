// ──────────────────────────────────────────────
// VICE LOCAL — Dependencies Audit
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import { execSync } from 'child_process';
import { addFinding } from '../core/findings.js';

export async function auditDependencies(projectPath, spinner) {
  spinner.text = 'Auditing npm dependencies...';

  const pkgPath = path.join(projectPath, 'package.json');
  if (!fs.existsSync(pkgPath)) {
    addFinding('INFO', 'Dependencies', 'No package.json found', '', '');
    return;
  }

  spinner.text = 'Running npm audit...';
  try {
    const output = execSync('npm audit --json 2>/dev/null', { cwd: projectPath, timeout: 30000 }).toString();
    const audit = JSON.parse(output);

    if (audit.metadata) {
      const { vulnerabilities } = audit.metadata;
      const critical = vulnerabilities?.critical || 0;
      const high = vulnerabilities?.high || 0;
      const moderate = vulnerabilities?.moderate || 0;
      const low = vulnerabilities?.low || 0;
      const total = critical + high + moderate + low;

      if (total === 0) {
        addFinding('INFO', 'Dependencies', 'npm audit: no known vulnerabilities', '', '');
      } else if (critical > 0) {
        addFinding('CRITICAL', 'Dependencies', `${critical} critical vulnerability(ies) in dependencies`, `Total: ${total} (${critical} critical, ${high} high, ${moderate} moderate, ${low} low)`, 'Run: npm audit fix --force');
      } else if (high > 0) {
        addFinding('HIGH', 'Dependencies', `${high} high vulnerability(ies) in dependencies`, `Total: ${total} vulnerabilities`, 'Run: npm audit fix');
      } else {
        addFinding('MEDIUM', 'Dependencies', `${total} vulnerability(ies) in dependencies`, `${moderate} moderate, ${low} low`, 'Run: npm audit fix');
      }
    }

    if (audit.vulnerabilities) {
      for (const [name, vuln] of Object.entries(audit.vulnerabilities)) {
        if (vuln.severity === 'critical' || vuln.severity === 'high') {
          const via = Array.isArray(vuln.via) ? vuln.via.filter(v => typeof v === 'object').map(v => v.title || v.url).join(', ') : '';
          addFinding(
            vuln.severity === 'critical' ? 'CRITICAL' : 'HIGH',
            'Dependencies', `${name}@${vuln.range} — ${vuln.severity}`,
            `${via}\nFix available: ${vuln.fixAvailable ? 'yes' : 'no'}`,
            vuln.fixAvailable ? `npm update ${name}` : `Look for an alternative to ${name}`
          );
        }
      }
    }
  } catch (err) {
    try {
      const output = err.stdout?.toString() || '';
      if (output) {
        const audit = JSON.parse(output);
        const vulns = audit.metadata?.vulnerabilities || {};
        const total = (vulns.critical || 0) + (vulns.high || 0) + (vulns.moderate || 0) + (vulns.low || 0);
        if (total > 0) {
          addFinding(vulns.critical > 0 ? 'CRITICAL' : 'HIGH', 'Dependencies',
            `${total} vulnerability(ies) found by npm audit`,
            `Critical: ${vulns.critical || 0}, High: ${vulns.high || 0}, Moderate: ${vulns.moderate || 0}, Low: ${vulns.low || 0}`,
            'Run: npm audit fix');
        }
      }
    } catch {
      addFinding('INFO', 'Dependencies', 'npm audit unavailable', 'Run npm install first', '');
    }
  }

  spinner.text = 'Checking outdated packages...';
  try {
    const output = execSync('npm outdated --json 2>/dev/null', { cwd: projectPath, timeout: 30000 }).toString();
    const outdated = JSON.parse(output);
    if (Object.keys(outdated).length > 10) {
      addFinding('LOW', 'Dependencies', `${Object.keys(outdated).length} outdated packages`, 'Outdated packages may contain unpatched security vulnerabilities', 'Run: npm update');
    }
  } catch {}
}
