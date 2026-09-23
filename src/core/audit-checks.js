export function recordAuditCheck(context, module, outcome) {
  if (!context || !['pass', 'fail', 'unknown'].includes(outcome)) return;
  context.auditChecks ||= {};
  context.auditChecks[module] ||= { pass: 0, fail: 0, unknown: 0 };
  context.auditChecks[module][outcome]++;
  if (outcome === 'unknown') context.limitations.add(`${module}_probe_inconclusive`);
}

export async function publicClientSources(sources, context, fetch) {
  if (!context?.authContext) return sources;
  const publicBodies = new Map();
  const output = [];
  for (const source of sources) {
    const record = context.stackSources?.find(item => item.content === source);
    if (!record || record.kind === 'Browser storage') continue;
    if (!publicBodies.has(record.url)) {
      const response = await fetch(record.url);
      publicBodies.set(record.url, response?.status === 200 ? await response.text() : '');
    }
    const body = publicBodies.get(record.url);
    if (body.includes(source)) output.push(source);
    else if (record.kind === 'Rendered HTML' && body) output.push(body);
  }
  return [...new Set(output)];
}
