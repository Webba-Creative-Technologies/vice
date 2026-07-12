import assert from 'node:assert/strict';
import test from 'node:test';

import { classifyWebSocketMessages, redactWebSocketUrl } from '../src/core/detectors/websocket.js';

test('protocol handshakes stay informational', () => {
  const result = classifyWebSocketMessages(['{"event":"phx_reply","payload":{"status":"ok"}}']);
  assert.equal(result.state, 'protocol-only');
  assert.equal(result.severity, 'INFO');
});

test('authorization rejection is recognized as protection', () => {
  const result = classifyWebSocketMessages(['{"error":"Authentication required"}']);
  assert.equal(result.state, 'auth-rejected');
});

test('exact personal fields qualify realtime exposure', () => {
  const result = classifyWebSocketMessages(['42["profile",{"email":"person@example.test"}]']);
  assert.equal(result.state, 'personal-data');
  assert.equal(result.confidence, 'high');
});

test('generic application messages are not vulnerabilities', () => {
  const result = classifyWebSocketMessages(['{"event":"price","value":42}']);
  assert.equal(result.state, 'application-data-unclassified');
  assert.equal(result.severity, 'INFO');
});

test('credential-shaped values are critical', () => {
  const jwt = `eyJ${'a'.repeat(25)}.${'b'.repeat(25)}.${'c'.repeat(25)}`;
  assert.equal(classifyWebSocketMessages([jwt]).state, 'credentials');
});

test('WebSocket URL credentials are redacted', () => {
  const redacted = redactWebSocketUrl('wss://example.test/realtime?apikey=secret-value&vsn=1');
  assert.match(redacted, /apikey=%5Bredacted%5D/);
  assert.doesNotMatch(redacted, /secret-value/);
});
