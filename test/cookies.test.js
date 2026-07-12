import assert from 'node:assert/strict';
import test from 'node:test';

import { classifySetCookie, getSetCookieHeaders } from '../src/core/detectors/cookies.js';

test('cookie parser handles multiple Set-Cookie values', () => {
  const headers = new Headers();
  headers.append('set-cookie', 'theme=dark; Path=/');
  headers.append('set-cookie', 'session=secret; HttpOnly; Secure; SameSite=Lax');

  assert.equal(getSetCookieHeaders(headers).length, 2);
});

test('sensitive cookies require HttpOnly, Secure, and SameSite', () => {
  const result = classifySetCookie('session=super-secret-value; Path=/', { https: true });

  assert.equal(result.severity, 'ELEVEE');
  assert.equal(result.name, 'session');
  assert.equal(JSON.stringify(result).includes('super-secret-value'), false);
  assert.equal(result.issues.length, 3);
});

test('secure session cookies produce no finding', () => {
  assert.equal(classifySetCookie('session=secret; Path=/; HttpOnly; Secure; SameSite=Lax', { https: true }), null);
});

test('SameSite None without Secure is invalid', () => {
  const result = classifySetCookie('analytics=id; SameSite=None', { https: true });

  assert.equal(result.severity, 'MOYENNE');
  assert.ok(result.issues.some((issue) => issue.includes('rejected')));
});

test('Host prefix requirements are enforced', () => {
  const invalid = classifySetCookie('__Host-session=value; HttpOnly; Secure; Path=/app', { https: true });
  const valid = classifySetCookie('__Host-session=value; HttpOnly; Secure; Path=/; SameSite=Strict', { https: true });

  assert.equal(invalid.severity, 'ELEVEE');
  assert.equal(valid, null);
});
