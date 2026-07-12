import assert from 'node:assert/strict';
import test from 'node:test';

import { classifyGraphqlAliasResponse, classifyGraphqlBatchResponse, classifyGraphqlDepthResponse } from '../src/core/detectors/graphql.js';

test('GraphQL validation errors do not prove missing depth limits', () => {
  const result = classifyGraphqlDepthResponse({
    errors: [{ message: 'Cannot query field "x" on type "Query".' }],
  }, 200);

  assert.equal(result, null);
});

test('GraphQL depth rejection is recognized as protection', () => {
  const result = classifyGraphqlDepthResponse({
    errors: [{ message: 'Query exceeds maximum depth of 7' }],
  }, 200);

  assert.deepEqual(result, { kind: 'protected', severity: 'INFO' });
});

test('successful deep GraphQL data remains actionable', () => {
  const result = classifyGraphqlDepthResponse({ data: { nested: { value: true } } }, 200);

  assert.deepEqual(result, { kind: 'accepted', severity: 'MOYENNE' });
});

test('HTTP errors are not classified as accepted GraphQL queries', () => {
  assert.equal(classifyGraphqlDepthResponse({ data: {} }, 429), null);
});

test('GraphQL batch support requires a complete response array', () => {
  const supported = classifyGraphqlBatchResponse([{ data: { __typename: 'Query' } }, { data: { __typename: 'Query' } }], 200, 2);
  assert.deepEqual(supported, { kind: 'supported', severity: 'INFO' });
  assert.equal(classifyGraphqlBatchResponse([{ data: {} }], 200, 2), null);
});

test('GraphQL batch rejection is recognized as protection', () => {
  const result = classifyGraphqlBatchResponse({ errors: [{ message: 'Batching is disabled' }] }, 400, 2);
  assert.deepEqual(result, { kind: 'protected', severity: 'INFO' });
});

test('bounded alias response requires every expected alias', () => {
  const data = Object.fromEntries(Array.from({ length: 20 }, (_, index) => [`viceAlias${index}`, 'Query']));
  assert.deepEqual(classifyGraphqlAliasResponse({ data }, 200, 20), { kind: 'accepted', severity: 'INFO' });
  delete data.viceAlias19;
  assert.equal(classifyGraphqlAliasResponse({ data }, 200, 20), null);
});

test('GraphQL cost rejection is recognized on alias probes', () => {
  const result = classifyGraphqlAliasResponse({ errors: [{ message: 'Query exceeds maximum complexity' }] }, 200, 20);
  assert.deepEqual(result, { kind: 'protected', severity: 'INFO' });
});
