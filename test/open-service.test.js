import assert from 'node:assert/strict';
import test from 'node:test';

import { classifyHttpOnlySubdomain, classifyOpenService } from '../src/core/detectors/open-service.js';

test('normal web ports produce no service finding', () => {
  assert.equal(classifyOpenService(80, 'HTTP/1.1 200 OK'), null);
  assert.equal(classifyOpenService(443, ''), null);
});

test('plaintext administration protocols remain actionable', () => {
  assert.equal(classifyOpenService(23, 'Telnet service\nlogin:').severity, 'CRITIQUE');
  assert.equal(classifyOpenService(21, '220 FTP service ready').severity, 'ELEVEE');
  assert.equal(classifyOpenService(23, '').state, 'port-only');
});

test('database ports without protocol evidence stay heuristic', () => {
  const result = classifyOpenService(5432, '');
  assert.equal(result.severity, 'FAIBLE');
  assert.equal(result.confidence, 'low');
});

test('database protocol evidence raises confidence without claiming no auth', () => {
  const result = classifyOpenService(3306, '8.0 mysql_native_password');
  assert.equal(result.severity, 'INFO');
  assert.equal(result.state, 'protocol-confirmed');
});

test('Redis distinguishes unauthenticated and protected responses', () => {
  assert.equal(classifyOpenService(6379, '+PONG\r\n').severity, 'CRITIQUE');
  assert.equal(classifyOpenService(6379, '-NOAUTH Authentication required.').severity, 'INFO');
});

test('Elasticsearch reachability remains informational without data exposure', () => {
  assert.equal(classifyOpenService(9200, 'HTTP/1.1 401 Unauthorized').severity, 'INFO');
  assert.equal(classifyOpenService(9200, 'HTTP/1.1 200 OK\r\nx-elastic-product: Elasticsearch').severity, 'INFO');
});

test('unknown admin ports remain low-confidence review signals', () => {
  const unknown = classifyOpenService(9000, '');
  const recognized = classifyOpenService(9090, 'HTTP/1.1 200 OK\r\nServer: Prometheus');
  assert.equal(unknown.confidence, 'low');
  assert.equal(recognized.severity, 'INFO');
});

test('HTTP-only subdomains require a live web response', () => {
  assert.equal(classifyHttpOnlySubdomain({ httpStatus: 404, httpsReachable: false, subName: 'support' }), null);
  assert.equal(classifyHttpOnlySubdomain({ httpStatus: 200, httpsReachable: false, subName: 'support' }).severity, 'MOYENNE');
  assert.equal(classifyHttpOnlySubdomain({ httpStatus: 200, httpsReachable: true, subName: 'support' }), null);
});
