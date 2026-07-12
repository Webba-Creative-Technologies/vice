const SEVERITY = {
  critical: 'CRITICAL',
  high: 'HIGH',
  moderate: 'MEDIUM',
  low: 'LOW',
};

function slug(value) {
  return String(value || 'package').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');
}

function fixDescription(value) {
  if (!value) return 'No automatic fix is currently available.';
  if (value === true) return 'An automatic fix is available.';
  if (typeof value === 'object') {
    const target = value.name ? `${value.name}${value.version ? `@${value.version}` : ''}` : 'a replacement version';
    return `A fix is available through ${target}${value.isSemVerMajor ? ' with a major-version change' : ''}.`;
  }
  return 'Review the available remediation.';
}

export function classifyNpmAudit(report) {
  const results = [];
  const vulnerabilities = report?.vulnerabilities || {};

  for (const [name, vulnerability] of Object.entries(vulnerabilities)) {
    const severity = SEVERITY[String(vulnerability?.severity || '').toLowerCase()];
    if (!severity) continue;
    const advisories = Array.isArray(vulnerability.via)
      ? vulnerability.via
        .filter((item) => item && typeof item === 'object')
        .map((item) => item.title || item.url)
        .filter(Boolean)
      : [];
    const directness = vulnerability.isDirect ? 'direct' : 'transitive';

    results.push({
      severity,
      title: `${name} has a ${String(vulnerability.severity).toLowerCase()} npm advisory`,
      detail: [
        `Affected range: ${vulnerability.range || 'unknown'}`,
        `Dependency type: ${directness}`,
        advisories.length ? `Advisories: ${[...new Set(advisories)].join('; ')}` : null,
        fixDescription(vulnerability.fixAvailable),
      ].filter(Boolean).join('\n'),
      recommendation: 'Review the advisory and update the dependency or its parent package. Validate breaking changes before deployment.',
      confidence: 'high',
      classification: 'confirmed',
      rule_id: `vice/dependencies/npm-advisory/${slug(name)}`,
    });
  }

  if (results.length > 0) return results;

  const counts = report?.metadata?.vulnerabilities || {};
  const total = ['critical', 'high', 'moderate', 'low'].reduce((sum, key) => sum + Number(counts[key] || 0), 0);
  if (total === 0) {
    return [{
      severity: 'INFO',
      title: 'npm audit found no known vulnerabilities',
      detail: '',
      recommendation: '',
      confidence: 'high',
      classification: 'confirmed',
      rule_id: 'vice/dependencies/npm-audit-clean',
    }];
  }

  const highest = ['critical', 'high', 'moderate', 'low'].find((key) => Number(counts[key] || 0) > 0);
  return [{
    severity: SEVERITY[highest],
    title: `npm audit reports ${total} known vulnerabilities`,
    detail: `Critical: ${counts.critical || 0}, high: ${counts.high || 0}, moderate: ${counts.moderate || 0}, low: ${counts.low || 0}. Package-level details were unavailable.`,
    recommendation: 'Run npm audit locally, review each advisory and update affected dependency paths.',
    confidence: 'high',
    classification: 'confirmed',
    rule_id: 'vice/dependencies/npm-advisory-summary',
  }];
}

export function classifyOutdatedPackages(report) {
  const names = Object.keys(report || {});
  if (names.length === 0) return null;
  return {
    severity: 'INFO',
    title: `${names.length} outdated npm package(s)`,
    detail: `Maintenance signal only, not proof of a vulnerability. Packages: ${names.slice(0, 25).join(', ')}${names.length > 25 ? ', …' : ''}`,
    recommendation: 'Review release notes and schedule compatible dependency updates.',
    confidence: 'high',
    classification: 'hardening',
    rule_id: 'vice/dependencies/npm-outdated',
  };
}
