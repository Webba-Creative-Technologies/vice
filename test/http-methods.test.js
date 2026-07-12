import assert from 'node:assert/strict';
import test from 'node:test';

import { classifyHttpMethodResponse, classifyTraceResponse } from '../src/core/detectors/http-methods.js';

test('identical GET fallback does not prove method handling', () => {
  const result = classifyHttpMethodResponse({
    method: 'DELETE', status: 200, body: '<html>SPA</html>', referenceStatus: 200, referenceBody: '<html>SPA</html>',
  });
  assert.equal(result.state, 'same-as-get');
  assert.equal(result.severity, 'INFO');
});

test('successful status without mutation evidence stays informational', () => {
  const result = classifyHttpMethodResponse({
    method: 'PUT', status: 204, body: '', referenceStatus: 200, referenceBody: '{}',
  });
  assert.equal(result.state, 'success-unproven');
  assert.equal(result.confidence, 'low');
});

test('explicit affected row count confirms mutation handling', () => {
  const result = classifyHttpMethodResponse({
    method: 'PATCH', status: 200, body: '{"affectedRows":1}', referenceStatus: 200, referenceBody: '{}',
  });
  assert.equal(result.state, 'mutation-confirmed');
  assert.equal(result.severity, 'ELEVEE');
});

test('mutation words in documentation do not confirm a state change', () => {
  const result = classifyHttpMethodResponse({
    method: 'POST', status: 200, body: 'Resources are created through this endpoint.', referenceStatus: 404, referenceBody: '',
  });
  assert.equal(result.state, 'success-unproven');
});

test('method rejection in a 200 response is recognized', () => {
  const result = classifyHttpMethodResponse({
    method: 'DELETE', status: 200, body: 'Method not allowed', referenceStatus: 200, referenceBody: 'home',
  });
  assert.equal(result.state, 'rejected');
});

test('TRACE requires reflection of the request canary', () => {
  assert.equal(classifyTraceResponse(200, 'TRACE documentation', 'vice-trace-123'), null);
  assert.equal(classifyTraceResponse(200, 'X-Vice-Trace: vice-trace-123', 'vice-trace-123').state, 'reflected');
});
