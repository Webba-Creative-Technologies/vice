import assert from 'node:assert/strict';
import test from 'node:test';
import { discoverSupabase, supabaseHeaders } from '../src/core/supabase-config.js';
import { cspScriptPolicy, dmarcPolicy } from '../src/core/detectors/policies.js';

const key = 'sb_publishable_A7b8C9d0E1f2G3h4I5j6K7l8';
test('publishable keys are discovered and never used as bearer JWTs', () => {
  assert.deepEqual(discoverSupabase([`createClient("https://alpha.supabase.co", "${key}")`]), { url: 'https://alpha.supabase.co', key });
  assert.deepEqual(supabaseHeaders(key), { apikey: key });
  assert.deepEqual(supabaseHeaders(key, 'user-session'), { apikey: key, Authorization: 'Bearer user-session' });
});
test('ambiguous Supabase projects are not paired with an unrelated key', () => {
  assert.deepEqual(discoverSupabase([`https://alpha.supabase.co https://beta.supabase.co ${key}`]), { url: null, key: null });
});
test('legacy anon discovery binds the JWT project reference', () => {
  const jwt = `eyJhbGciOiJIUzI1NiJ9.${Buffer.from(JSON.stringify({role:'anon',ref:'alpha'})).toString('base64url')}.signature`;
  assert.equal(discoverSupabase([`https://alpha.supabase.co ${jwt}`]).key, jwt);
  assert.equal(supabaseHeaders(jwt).Authorization, `Bearer ${jwt}`);
  assert.equal(discoverSupabase([`https://beta.supabase.co ${jwt}`]).key, null);
});
test('CSP explicit script policy takes precedence regardless of directive order', () => {
  assert.equal(cspScriptPolicy("default-src 'self'; script-src 'self' 'unsafe-eval'"), "'self' 'unsafe-eval'");
  assert.equal(cspScriptPolicy("script-src 'none'; default-src *"), "'none'");
  assert.equal(cspScriptPolicy("default-src *; script-src 'none'; script-src-elem 'self'"), "'self'");
});
test('DMARC distinguishes p from sp and rejects contradictory policies', () => {
  assert.equal(dmarcPolicy('v=DMARC1; p=reject; sp=none'), 'reject');
  assert.equal(dmarcPolicy('v=DMARC1; p = quarantine'), 'quarantine');
  assert.equal(dmarcPolicy('v=DMARC1; p=reject; p=none'), null);
});
