function roundDuration(value) {
  return Math.max(0, Math.round(value));
}

export function createScanMetrics(options = {}) {
  const now = options.now || (() => performance.now());
  const getFindingCount = options.getFindingCount || (() => 0);
  const scanStartedAt = now();
  const steps = [];

  return {
    async run(name, fn) {
      const startedAt = now();
      const findingsBefore = getFindingCount();
      let status = 'completed';

      try {
        return await fn();
      } catch (error) {
        status = 'failed';
        throw error;
      } finally {
        steps.push({
          module: name,
          status,
          duration_ms: roundDuration(now() - startedAt),
          findings_added: Math.max(0, getFindingCount() - findingsBefore),
        });
      }
    },

    finish() {
      return {
        total_duration_ms: roundDuration(now() - scanStartedAt),
        steps: steps.map((step) => ({ ...step })),
      };
    },
  };
}
