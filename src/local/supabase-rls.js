// ──────────────────────────────────────────────
// VICE LOCAL - Supabase RLS Audit in Migrations
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import { addFinding } from '../core/findings.js';
import { analyzeRlsSql } from '../core/detectors/rls-sql.js';

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
  sqlFiles.sort((left, right) => left.localeCompare(right));

  if (sqlFiles.length === 0) {
    addFinding('INFO', 'Supabase RLS', 'No SQL files found in migrations', '', '');
    return;
  }

  spinner.text = `Analyzing ${sqlFiles.length} SQL files...`;

  const tablesCreated = new Map();
  const rlsState = new Map();
  const policiesByTable = new Map();
  const activeGrants = new Map();
  const functions = new Map();

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

    const rlsAnalysis = analyzeRlsSql(content);
    for (const event of rlsAnalysis.tableEvents.sort((left, right) => left.index - right.index)) {
      rlsState.set(event.table, event.enabled);
    }
    for (const event of rlsAnalysis.policyEvents.sort((left, right) => left.index - right.index)) {
      const policies = policiesByTable.get(event.table) || new Map();
      if (event.action === 'create') policies.set(event.name, { ...event, file: rel });
      else policies.delete(event.name);
      policiesByTable.set(event.table, policies);
    }
    for (const event of rlsAnalysis.grantEvents.sort((left, right) => left.index - right.index)) {
      if (event.action === 'grant') {
        const key = `${event.table}:${[...event.roles].sort().join(',')}:${[...event.privileges].sort().join(',')}`;
        activeGrants.set(key, { ...event, file: rel });
      } else {
        for (const [key, grant] of activeGrants) {
          const sameTable = grant.table === event.table;
          const sharedRole = grant.roles.some(role => event.roles.includes(role));
          const sharedPrivilege = event.privileges.includes('ALL') || grant.privileges.some(privilege => event.privileges.includes(privilege));
          if (sameTable && sharedRole && sharedPrivilege) activeGrants.delete(key);
        }
      }
    }
    for (const event of rlsAnalysis.functionEvents.sort((left, right) => left.index - right.index)) {
      if (event.action === 'create') functions.set(event.name, { ...event, file: rel });
      else functions.delete(event.name);
    }
    for (const signal of rlsAnalysis.signals) {
      addFinding(signal.severity, 'Supabase RLS', signal.title, `${rel}\n${signal.detail}`, signal.recommendation);
    }

    if (/EXECUTE\s+['"].*?\|\|.*?['"]|format\s*\(.*?%s/gi.test(content)) {
      addFinding('HIGH', 'Supabase RLS', `Unsafe dynamic SQL in ${rel}`, 'String concatenation or format() used in SQL query - injection risk', 'Use parameters ($1, $2) instead of string concatenation');
    }

  }

  for (const [table, enabled] of rlsState) {
    if (!enabled && !tablesCreated.has(table)) {
      addFinding('CRITICAL', 'Supabase RLS', `RLS explicitly disabled on "${table}"`, `The final migration state contains DISABLE ROW LEVEL SECURITY for ${table}.`, `Enable RLS on ${table} and add restrictive policies.`);
    }
  }

  for (const policies of policiesByTable.values()) {
    for (const policy of policies.values()) {
      if (policy.signal) addFinding(policy.signal.severity, 'Supabase RLS', policy.signal.title, `${policy.file}\n${policy.signal.detail}`, policy.signal.recommendation);
    }
  }

  for (const grant of activeGrants.values()) {
    if (grant.signal) addFinding(grant.signal.severity, 'Supabase RLS', grant.signal.title, `${grant.file}\n${grant.signal.detail}`, grant.signal.recommendation);
  }

  for (const definition of functions.values()) {
    for (const signal of definition.signals) {
      addFinding(signal.severity, 'Supabase RLS', signal.title, `${definition.file}\n${signal.detail}`, signal.recommendation);
    }
  }

  for (const [table, file] of tablesCreated) {
    if (rlsState.get(table) !== true) {
      addFinding('CRITICAL', 'Supabase RLS', `Table "${table}" created without RLS`, `Defined in ${file}\nNo ALTER TABLE ... ENABLE ROW LEVEL SECURITY found`, `Add after table creation:\n  ALTER TABLE ${table} ENABLE ROW LEVEL SECURITY;\n  CREATE POLICY "${table}_select" ON ${table} FOR SELECT USING (auth.uid() = user_id);`);
    } else if ((policiesByTable.get(table)?.size || 0) === 0) {
      addFinding('HIGH', 'Supabase RLS', `Table "${table}" has RLS enabled but no policies`, 'RLS is on but without policies, NO data is accessible (even for authorized users)', `Add policies:\n  CREATE POLICY "${table}_read" ON ${table} FOR SELECT USING (auth.uid() = user_id);`);
    }
  }

  if (tablesCreated.size > 0) {
    const withRls = [...tablesCreated.keys()].filter(t => rlsState.get(t) === true).length;
    addFinding('INFO', 'Supabase RLS', `${tablesCreated.size} tables, ${withRls} with RLS`, `Tables: ${[...tablesCreated.keys()].join(', ')}`, '');
  }
}
