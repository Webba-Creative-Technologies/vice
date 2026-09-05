// Pure presentation policy. Numeric scoring and CI thresholds are unchanged.
export const SCORE_PRESENTATION_VERSION = '2026.09.05.1';

/** @param {number | null | undefined} score */
export function gradeForScore(score) {
  if (typeof score !== 'number' || !Number.isFinite(score) || score < 0 || score > 100) return null;
  if (score >= 90) return 'A';
  if (score >= 75) return 'B';
  if (score >= 60) return 'C';
  if (score >= 40) return 'D';
  if (score >= 20) return 'E';
  return 'F';
}

/**
 * @param {number | null | undefined} score
 * @param {{criticalCount?: number, highCount?: number, reliable?: boolean,
 * coverageStatus?: string | null, authStatus?: string | null}} [options]
 */
export function scorePresentation(score, options = {}) {
  const grade = gradeForScore(score);
  const provisional = options.reliable === false
    || ['partial', 'incomplete'].includes(options.coverageStatus || '')
    || ['required', 'unverified', 'unavailable'].includes(options.authStatus || '');
  const critical = (options.criticalCount || 0) > 0;
  const status = critical ? 'critical'
    : provisional ? 'provisional'
    : grade === null ? 'unknown'
    : (options.highCount || 0) > 0 || grade !== 'A' ? 'attention' : 'clear';
  const tone = status === 'critical' ? 'error'
    : status === 'unknown' ? 'default'
    : status === 'clear' ? 'success' : 'warning';
  return { grade, status, tone, provisional, critical, version: SCORE_PRESENTATION_VERSION };
}

