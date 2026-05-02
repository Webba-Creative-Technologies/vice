// ──────────────────────────────────────────────
// VICE LOCAL — Supabase RLS Audit in Migrations
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import { addFinding } from '../core/findings.js';

export async function auditSupabaseRls(projectPath, spinner) {
  spinner.text = 'Looking for Supabase migrations...';

  const migrationPaths = [
    path.join(projectPath, 'supabase', 'migrations'),
    path.join(projectPath, 'migrations'),
    path.join(projectPath, 'db', 'migrations'),
    path.join(projectPath, 'prisma', 'migrations'),
    path.join(projectPath, 'sql'),
  ];

  let migrationDir = null;
  for (const p of migrationPaths) {
    if (fs.existsSync(p)) { migrationDir = p; break; }
  }

  if (!migrationDir) {
    addFinding('INFO', 'Supabase RLS', 'No migrations directory found', `Paths checked: ${migrationPaths.map(p => path.relative(projectPath, p)).join(', ')}`, '');
    return;
  }

  const sqlFiles = [];
  async function findSql(dir) {
    let entries;
    try { entries = await fs.promises.readdir(dir, { withFileTypes: true }); } catch { return; }
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      if (entry.isDirectory()) await findSql(fullPath);
      else if (entry.name.endsWith('.sql')) sqlFiles.push(fullPath);
    }
  }
  await findSql(migrationDir);

  if (sqlFiles.length === 0) {
    addFinding('INFO', 'Supabase RLS', 'No SQL files found in migrations', '', '');
    return;
  }

  spinner.text = `Analyzing ${sqlFiles.length} SQL files...`;

  const tablesCreated = new Map();
  const tablesWithRls = new Set();
  const tablesWithPolicies = new Set();

  for (const filePath of sqlFiles) {
    const content = await fs.promises.readFile(filePath, 'utf-8');
    const rel = path.relative(projectPath, filePath);

    const createTableRegex = /CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?["']?(\w+)["']?/gi;
    let match;
    while ((match = createTableRegex.exec(content)) !== null) {
      const tableName = match[1].toLowerCase();
      if (!['schema_migrations', 'migrations', '__drizzle_migrations'].includes(tableName)) {
        tablesCreated.set(tableName, rel);
      }
    }

    const rlsRegex = /ALTER\s+TABLE\s+(?:public\.)?["']?(\w+)["']?\s+ENABLE\s+ROW\s+LEVEL\s+SECURITY/gi;
    while ((match = rlsRegex.exec(content)) !== null) tablesWithRls.add(match[1].toLowerCase());

    const policyRegex = /CREATE\s+POLICY\s+.*?\s+ON\s+(?:public\.)?["']?(\w+)["']?/gi;
    while ((match = policyRegex.exec(content)) !== null) tablesWithPolicies.add(match[1].toLowerCase());

    if (/EXECUTE\s+['"].*?\|\|.*?['"]|format\s*\(.*?%s/gi.test(content)) {
      addFinding('HIGH', 'Supabase RLS', `Unsafe dynamic SQL in ${rel}`, 'String concatenation or format() used in SQL query — injection risk', 'Use parameters ($1, $2) instead of string concatenation');
    }

    const grantRegex = /GRANT\s+ALL\s+(?:PRIVILEGES\s+)?ON\s+.*?\s+TO\s+(anon|authenticated|public)/gi;
    while ((match = grantRegex.exec(content)) !== null) {
      addFinding('HIGH', 'Supabase RLS', `GRANT ALL to public role in ${rel}`, `GRANT ALL TO ${match[1]} — grants all permissions`, `Restrict grants: GRANT SELECT, INSERT ON table TO ${match[1]}`);
    }

    const secDefRegex = /CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+(\w+).*?SECURITY\s+DEFINER/gis;
    while ((match = secDefRegex.exec(content)) !== null) {
      if (!/auth\.uid\(\)|auth\.role\(\)|current_user/i.test(match[0])) {
        addFinding('HIGH', 'Supabase RLS', `SECURITY DEFINER function without auth check: ${match[1]}`, `${rel}\nFunction ${match[1]} runs with creator privileges but does not verify caller identity`, `Add check: IF auth.uid() IS NULL THEN RAISE EXCEPTION 'Not authenticated'; END IF;`);
      }
    }
  }

  for (const [table, file] of tablesCreated) {
    if (!tablesWithRls.has(table)) {
      addFinding('CRITICAL', 'Supabase RLS', `Table "${table}" created without RLS`, `Defined in ${file}\nNo ALTER TABLE ... ENABLE ROW LEVEL SECURITY found`, `Add after table creation:\n  ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY;\n  CREATE POLICY "${table}_select" ON ${table} FOR SELECT USING (auth.uid() = user_id);`);
    } else if (!tablesWithPolicies.has(table)) {
      addFinding('HIGH', 'Supabase RLS', `Table "${table}" has RLS enabled but no policies`, 'RLS is on but without policies, NO data is accessible (even for authorized users)', `Add policies:\n  CREATE POLICY "${table}_read" ON ${table} FOR SELECT USING (auth.uid() = user_id);`);
    }
  }

  if (tablesCreated.size > 0) {
    const withRls = [...tablesCreated.keys()].filter(t => tablesWithRls.has(t)).length;
    addFinding('INFO', 'Supabase RLS', `${tablesCreated.size} tables, ${withRls} with RLS`, `Tables: ${[...tablesCreated.keys()].join(', ')}`, '');
  }
}
