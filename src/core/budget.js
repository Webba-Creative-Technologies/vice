export function boundedAdd(set, value, limit) {
  if (!(set instanceof Set) || !Number.isInteger(limit) || limit < 1) return false;
  if (set.has(value)) return true;
  if (set.size >= limit) return false;
  set.add(value);
  return true;
}

export function boundedPush(array, value, limit) {
  if (!Array.isArray(array) || !Number.isInteger(limit) || limit < 1 || array.length >= limit) return false;
  array.push(value);
  return true;
}
