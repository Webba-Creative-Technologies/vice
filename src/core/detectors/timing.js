function median(values) {
  const sorted = [...values].sort((left, right) => left - right);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
}

export function classifyTimingSamples(controlSamples, attackSamples, expectedDelayMs) {
  if (controlSamples.length < 3 || attackSamples.length < 2) return null;
  if (![...controlSamples, ...attackSamples].every(Number.isFinite)) return null;

  const controlMedian = median(controlSamples);
  const attackMedian = median(attackSamples);
  const controlRange = Math.max(...controlSamples) - Math.min(...controlSamples);
  const difference = attackMedian - controlMedian;
  const stableBaseline = controlRange < expectedDelayMs * 0.5;
  const repeatedDelay = attackSamples.every((sample) => sample > Math.max(...controlSamples) + expectedDelayMs * 0.5);

  if (!stableBaseline || !repeatedDelay || difference < expectedDelayMs * 0.75) return null;
  return {
    controlMedian: Math.round(controlMedian),
    attackMedian: Math.round(attackMedian),
    difference: Math.round(difference),
  };
}
