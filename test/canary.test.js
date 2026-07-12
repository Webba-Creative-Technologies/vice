import assert from 'node:assert/strict';
import test from 'node:test';

import { createSupabaseCanary } from '../src/core/canary.js';

test('Supabase canary is stable per project and purpose', () => {
  const first = createSupabaseCanary('https://project.supabase.co', 'audit');
  const second = createSupabaseCanary('https://project.supabase.co/path', 'audit');
  assert.deepEqual(first, second);
});

test('Supabase canaries separate projects and intrusive purposes', () => {
  const signup = createSupabaseCanary('https://project.supabase.co', 'audit');
  const injection = createSupabaseCanary('https://project.supabase.co', 'injection');
  const otherProject = createSupabaseCanary('https://other.supabase.co', 'audit');

  assert.notEqual(signup.email, injection.email);
  assert.notEqual(signup.email, otherProject.email);
  assert.match(signup.email, /^vice-audit-[a-f0-9]{20}@example\.invalid$/);
  assert.ok(signup.password.length >= 12);
});
