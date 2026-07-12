import assert from 'node:assert/strict';
import test from 'node:test';

import { classifyUnauthenticatedApiResponse, findMassAssignmentSurfaces } from '../src/core/detectors/api-schema.js';

test('OpenAPI detector finds writable privileged fields through refs', () => {
  const spec = {
    paths: { '/users': { patch: { requestBody: { content: { 'application/json': { schema: { $ref: '#/components/schemas/UserUpdate' } } } } } } },
    components: { schemas: { UserUpdate: { type: 'object', properties: { display_name: { type: 'string' }, role: { type: 'string' }, is_admin: { type: 'boolean', readOnly: true } } } } },
  };

  assert.deepEqual(findMassAssignmentSurfaces(spec), [{ path: '/users', method: 'PATCH', fields: ['role'] }]);
});

test('OpenAPI detector ignores read-only and ordinary request fields', () => {
  const spec = { paths: { '/profile': { post: { requestBody: { content: { 'application/json': { schema: { type: 'object', properties: { name: {}, role: { readOnly: true } } } } } } } } } };
  assert.deepEqual(findMassAssignmentSurfaces(spec), []);
});

test('public API classifier separates catalog and personal data', () => {
  const catalog = classifyUnauthenticatedApiResponse('/api/products', [{ id: 1, name: 'Public product' }]);
  const personal = classifyUnauthenticatedApiResponse('/api/profile', [{ email: 'person@example.test' }]);
  assert.equal(catalog.severity, 'INFO');
  assert.equal(personal.severity, 'ELEVEE');
});

test('public API classifier keeps unknown admin responses probable', () => {
  const result = classifyUnauthenticatedApiResponse('/api/admin/stats', { uptime: 42 });
  assert.equal(result.severity, 'MOYENNE');
  assert.equal(result.classification, 'probable');
});
