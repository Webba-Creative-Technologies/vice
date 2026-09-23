import { readFile, writeFile } from 'node:fs/promises';

const [input, output] = process.argv.slice(2);
if (!output) throw new Error('Usage: node benchmark/summarize.mjs results.json summary.json');
const data = JSON.parse(await readFile(input, 'utf8'));
const median = values => {
  const sorted = [...values].sort((a, b) => a - b);
  const middle = Math.floor(sorted.length / 2);
  return sorted.length % 2 ? sorted[middle] : (sorted[middle - 1] + sorted[middle]) / 2;
};
const grouped = Map.groupBy(data.cases, item => item.id);
const cases = [...grouped].map(([id, pairs]) => ({
  id, expected: pairs[0].expected, repetitions: pairs.length,
  ...Object.fromEntries(['baseline', 'candidate'].map(label => [label, {
    detected: [...new Set(pairs.flatMap(pair => pair[label].detected))],
    missed: [...new Set(pairs.flatMap(pair => pair[label].missed))],
    false_positives: [...new Set(pairs.flatMap(pair => pair[label].false_positives))],
    stable: new Set(pairs.map(pair => JSON.stringify([...pair[label].detected].sort()))).size === 1,
    errors: pairs.reduce((total, pair) => total + pair[label].errors.length, 0),
    duration_ms: { median: median(pairs.map(pair => pair[label].duration_ms)), min: Math.min(...pairs.map(pair => pair[label].duration_ms)), max: Math.max(...pairs.map(pair => pair[label].duration_ms)) },
    requests: median(pairs.map(pair => pair[label].requests)),
    scores: [...new Set(pairs.map(pair => pair[label].score))],
  }])),
}));
const totals = Object.fromEntries(['baseline', 'candidate'].map(label => {
  const repetitions = [...Map.groupBy(data.cases, item => item.repetition).values()].filter(pairs => pairs.length === cases.length);
  return [label, {
    found: cases.reduce((total, item) => total + item.expected.filter(defect => item[label].detected.includes(defect)).length, 0),
    expected: cases.reduce((total, item) => total + item.expected.length, 0),
    false_positives: cases.reduce((total, item) => total + item[label].false_positives.length, 0),
    median_pass_duration_ms: median(repetitions.map(pairs => pairs.reduce((total, pair) => total + pair[label].duration_ms, 0))),
    errors: cases.reduce((total, item) => total + item[label].errors, 0),
    stable: cases.every(item => item[label].stable),
  }];
}));
const result = { node: data.node, repetitions: Math.min(...cases.map(item => item.repetitions)), requested_repetitions: data.repetitions, case_count: cases.length, totals,
  duration_reduction_percent: 100 * (1 - totals.candidate.median_pass_duration_ms / totals.baseline.median_pass_duration_ms), cases };
await writeFile(output, JSON.stringify(result, null, 2));
console.log(JSON.stringify({ ...result, cases: undefined }, null, 2));
for (const item of cases) console.log(`${item.id}: ${item.baseline.detected.length} -> ${item.candidate.detected.length}; ${item.baseline.duration_ms.median} -> ${item.candidate.duration_ms.median} ms; scores ${item.baseline.scores} -> ${item.candidate.scores}`);
