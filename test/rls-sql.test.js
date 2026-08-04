import assert from 'node:assert/strict';
import { mkdir, mkdtemp, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import test from 'node:test';

import { analyzeRlsSql } from '../src/core/detectors/rls-sql.js';
import { clearFindings, getFindings } from '../src/core/findings.js';
import { auditSupabaseRls } from '../src/local/supabase-rls.js';

const spinner = { text: '' };

test('SQL detector separates public reads from unconditional writes', () => {
  const result = analyzeRlsSql(`
    CREATE POLICY public_read ON public.notes FOR SELECT TO anon USING (true);
    CREATE POLICY public_write ON public.notes FOR INSERT TO anon WITH CHECK (true);
  `);

  const signals = result.policyEvents.map(event => event.signal).filter(Boolean);
  assert.equal(signals.length, 1);
  assert.match(signals[0].title, /Permissive INSERT/);
});

test('RLS audit reports active high-signal SQL controls', async () => {
  const project = await mkdtemp(path.join(tmpdir(), 'vice-rls-'));
  const migrations = path.join(project, 'supabase', 'migrations');

  try {
    await mkdir(migrations, { recursive: true });
    await writeFile(path.join(migrations, '001_risky.sql'), `
      CREATE TABLE public.notes (id uuid primary key, owner_id uuid);
      ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;
      CREATE POLICY public_write ON public.notes FOR INSERT TO anon WITH CHECK (true);
      GRANT UPDATE ON TABLE public.notes TO authenticated;
      CREATE FUNCTION public.promote() RETURNS void
      LANGUAGE plpgsql SECURITY DEFINER AS $$
      BEGIN PERFORM 1; END;
      $$;
    `, 'utf8');
    clearFindings();

    await auditSupabaseRls(project, spinner);

    const titles = getFindings().map(finding => finding.title);
    assert.ok(titles.some(title => title.includes('Permissive INSERT policy')));
    assert.ok(titles.some(title => title.includes('Direct write grant')));
    assert.ok(titles.some(title => title.includes('without auth check')));
    assert.ok(titles.some(title => title.includes('without fixed search_path')));
  } finally {
    clearFindings();
    await rm(project, { recursive: true, force: true });
  }
});

test('RLS audit evaluates the final ordered migration state', async () => {
  const project = await mkdtemp(path.join(tmpdir(), 'vice-rls-'));
  const migrations = path.join(project, 'supabase', 'migrations');

  try {
    await mkdir(migrations, { recursive: true });
    await writeFile(path.join(migrations, '001_initial.sql'), `
      CREATE TABLE public.notes (id uuid primary key, owner_id uuid);
      ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;
      CREATE POLICY public_write ON public.notes FOR INSERT TO anon WITH CHECK (true);
      GRANT UPDATE ON TABLE public.notes TO authenticated;
      CREATE FUNCTION public.promote() RETURNS void
      LANGUAGE plpgsql SECURITY DEFINER AS $$ BEGIN PERFORM 1; END; $$;
    `, 'utf8');
    await writeFile(path.join(migrations, '002_harden.sql'), `
      DROP POLICY public_write ON public.notes;
      CREATE POLICY owner_write ON public.notes FOR INSERT TO authenticated WITH CHECK (auth.uid() = owner_id);
      REVOKE UPDATE ON TABLE public.notes FROM authenticated;
      CREATE OR REPLACE FUNCTION public.promote() RETURNS void
      LANGUAGE plpgsql SECURITY DEFINER SET search_path = '' AS $$
      BEGIN PERFORM auth.uid(); END;
      $$;
      ALTER TABLE public.notes DISABLE ROW LEVEL SECURITY;
      ALTER TABLE public.notes ENABLE ROW LEVEL SECURITY;
    `, 'utf8');
    clearFindings();

    await auditSupabaseRls(project, spinner);

    const titles = getFindings().map(finding => finding.title);
    assert.equal(titles.some(title => title.includes('Permissive INSERT policy')), false);
    assert.equal(titles.some(title => title.includes('Direct write grant')), false);
    assert.equal(titles.some(title => title.includes('SECURITY DEFINER function')), false);
    assert.equal(titles.some(title => title.includes('without RLS')), false);
  } finally {
    clearFindings();
    await rm(project, { recursive: true, force: true });
  }
});

test('RLS audit ignores generic non-Supabase migrations', async () => {
  const project = await mkdtemp(path.join(tmpdir(), 'vice-rls-'));
  const migrations = path.join(project, 'prisma', 'migrations', '001_initial');

  try {
    await mkdir(migrations, { recursive: true });
    await writeFile(path.join(migrations, 'migration.sql'), 'CREATE TABLE users (id integer primary key);', 'utf8');
    clearFindings();

    await auditSupabaseRls(project, spinner);

    assert.equal(getFindings().some((finding) => finding.title.includes('without RLS')), false);
  } finally {
    clearFindings();
    await rm(project, { recursive: true, force: true });
  }
});

test('RLS without policies is reported as deny by default', async () => {
  const project = await mkdtemp(path.join(tmpdir(), 'vice-rls-'));
  const migrations = path.join(project, 'supabase', 'migrations');

  try {
    await mkdir(migrations, { recursive: true });
    await writeFile(path.join(migrations, '001_private.sql'), 'CREATE TABLE public.private_notes (id uuid);\nALTER TABLE public.private_notes ENABLE ROW LEVEL SECURITY;', 'utf8');
    clearFindings();

    await auditSupabaseRls(project, spinner);

    const finding = getFindings().find((item) => item.title.includes('deny-by-default'));
    assert.equal(finding?.severity, 'INFO');
  } finally {
    clearFindings();
    await rm(project, { recursive: true, force: true });
  }
});
