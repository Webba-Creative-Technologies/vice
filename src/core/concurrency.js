export async function mapWithConcurrency(items, limit, mapper) {
  const values = Array.from(items);
  if (values.length === 0) return [];

  const workerCount = Math.max(1, Math.min(values.length, Math.floor(limit) || 1));
  const results = new Array(values.length);
  let nextIndex = 0;

  async function worker() {
    while (true) {
      const index = nextIndex++;
      if (index >= values.length) return;
      results[index] = await mapper(values[index], index);
    }
  }

  await Promise.all(Array.from({ length: workerCount }, () => worker()));
  return results;
}
