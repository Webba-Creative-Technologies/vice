import { classifyPublicJson } from './public-json.js';

const PRIVILEGED_FIELD = /^(?:role|roles|is_admin|isadmin|admin|permissions|owner_id|ownerid|user_id|userid|account_id|tenant_id|status|price|amount|balance|verified|email_verified|plan|subscription_tier)$/i;

function resolveSchema(schema, spec, seen = new Set()) {
  if (!schema || typeof schema !== 'object') return null;
  if (!schema.$ref) return schema;
  if (!schema.$ref.startsWith('#/')) return null;
  if (seen.has(schema.$ref)) return null;
  seen.add(schema.$ref);
  return schema.$ref.slice(2).split('/').reduce((value, key) => value?.[key.replace(/~1/g, '/').replace(/~0/g, '~')], spec) || null;
}

function requestSchema(operation, spec) {
  const content = operation?.requestBody?.content;
  if (content && typeof content === 'object') {
    const media = content['application/json'] || Object.values(content)[0];
    return resolveSchema(media?.schema, spec);
  }
  const bodyParameter = Array.isArray(operation?.parameters)
    ? operation.parameters.find(parameter => parameter?.in === 'body')
    : null;
  return resolveSchema(bodyParameter?.schema, spec);
}

export function findMassAssignmentSurfaces(spec, limit = 30) {
  if (!spec?.paths || typeof spec.paths !== 'object') return [];
  const results = [];

  for (const [path, pathItem] of Object.entries(spec.paths)) {
    for (const method of ['post', 'put', 'patch']) {
      const operation = pathItem?.[method];
      if (!operation || typeof operation !== 'object') continue;
      let schema = requestSchema(operation, spec);
      schema = resolveSchema(schema, spec);
      if (schema?.type === 'array') schema = resolveSchema(schema.items, spec);
      const properties = schema?.properties;
      if (!properties || typeof properties !== 'object') continue;

      const fields = Object.entries(properties)
        .filter(([name, definition]) => PRIVILEGED_FIELD.test(name) && definition?.readOnly !== true)
        .map(([name]) => name);
      if (fields.length > 0) results.push({ path, method: method.toUpperCase(), fields });
      if (results.length >= limit) return results;
    }
  }
  return results;
}

export function classifyUnauthenticatedApiResponse(path, payload, status = 200) {
  if (status < 200 || status >= 300 || payload === null || payload === undefined) return null;
  const exposure = classifyPublicJson(payload);

  if (exposure.kind === 'credentials') {
    return { severity: 'CRITIQUE', confidence: 'high', classification: 'confirmed', kind: 'credentials', paths: exposure.paths };
  }
  if (exposure.kind === 'personal-data') {
    return { severity: 'ELEVEE', confidence: 'high', classification: 'confirmed', kind: 'personal-data', paths: exposure.paths };
  }
  if (/\/(?:admin|internal|debug|config|users?|accounts?)\b/i.test(path)) {
    return { severity: 'INFO', confidence: 'low', classification: 'heuristic', kind: 'sensitive-route', paths: [] };
  }
  return { severity: 'INFO', confidence: 'high', classification: 'confirmed', kind: 'public-data', paths: [] };
}
