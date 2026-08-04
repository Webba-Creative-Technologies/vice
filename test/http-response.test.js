import assert from 'node:assert/strict';
import test from 'node:test';

import { isLikelyCatchAll, responseSnapshot } from '../src/core/detectors/http-response.js';

test('response comparison recognizes an SPA fallback with dynamic values', () => {
  const content = '<section><h1>Application</h1><p>Shared single page shell</p></section>'.repeat(5);
  const baseline = responseSnapshot(200, 'text/html', `<html>${content}<script src="/app.12345678.js"></script></html>`);
  const candidate = responseSnapshot(200, 'text/html', `<html>${content}<script src="/app.87654321.js"></script></html>`);
  assert.equal(isLikelyCatchAll(candidate, [baseline]), true);
});

test('response comparison keeps distinct JSON endpoints', () => {
  const baseline = responseSnapshot(404, 'application/json', '{"error":"not found"}');
  const candidate = responseSnapshot(200, 'application/json', '{"users":[{"email":"person@example.test"}]}');
  assert.equal(isLikelyCatchAll(candidate, [baseline]), false);
});
