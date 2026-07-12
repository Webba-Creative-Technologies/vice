import test from 'node:test';
import assert from 'node:assert/strict';

import { analyzeJwt, findJwtCandidates } from '../src/core/detectors/jwt.js';

function segment(value) {
  return Buffer.from(JSON.stringify(value)).toString('base64url');
}

function token(header, payload, signature = 'valid-looking-signature') {
  return `${segment(header)}.${segment(payload)}.${signature}`;
}

test('detects unsigned JWTs without trying to exploit them', () => {
  const jwt = token({ alg: 'none', typ: 'JWT' }, { sub: '123' }, '');
  const result = analyzeJwt(jwt);

  assert.equal(result.signals.length, 1);
  assert.equal(result.signals[0].type, 'unsigned');
  assert.equal(result.signals[0].confidence, 'high');
});

test('detects explicit privileged roles in signed client tokens', () => {
  const jwt = token({ alg: 'RS256' }, { sub: '123', roles: ['user', 'admin'] });
  const result = analyzeJwt(jwt);

  assert.deepEqual(result.roles, ['user', 'admin']);
  assert.equal(result.signals[0].type, 'privileged-role');
  assert.match(result.signals[0].detail, /admin/);
});

test('does not flag ordinary or Supabase public roles', () => {
  const ordinary = analyzeJwt(token({ alg: 'RS256' }, { role: 'user' }));
  const supabaseAnon = analyzeJwt(token({ alg: 'HS256' }, { role: 'anon' }));

  assert.deepEqual(ordinary.signals, []);
  assert.deepEqual(supabaseAnon.signals, []);
});

test('bounds candidate extraction and rejects malformed tokens', () => {
  const first = token({ alg: 'RS256' }, { role: 'user' });
  const second = token({ alg: 'RS256' }, { role: 'admin' });

  assert.deepEqual(findJwtCandidates(`${first} ${second}`, 1), [first]);
  assert.equal(analyzeJwt('not.a.jwt'), null);
});
