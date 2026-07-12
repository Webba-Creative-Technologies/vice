export function summarizeCoverage(requestedModules, steps, options = {}) {
  const requested = [...new Set(requestedModules)];
  const moduleSteps = new Map(
    steps
      .filter((step) => requested.includes(step.module))
      .map((step) => [step.module, step]),
  );
  const completed = [];
  const failed = [];
  const skipped = [];

  for (const module of requested) {
    const step = moduleSteps.get(module);
    if (!step) skipped.push(module);
    else if (step.status === 'failed') failed.push(module);
    else completed.push(module);
  }

  const ratio = requested.length === 0 ? 0 : completed.length / requested.length;
  const limitations = [...new Set(options.limitations || [])];
  let status = failed.length > 0 || skipped.length > 0
    ? completed.length > 0 ? 'partial' : 'incomplete'
    : 'complete';
  if (status === 'complete' && limitations.length > 0) status = completed.length > 0 ? 'partial' : 'incomplete';

  return {
    status,
    requested,
    completed,
    failed,
    skipped,
    limitations,
    ratio: Number(ratio.toFixed(3)),
  };
}
