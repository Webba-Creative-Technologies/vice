function normalizeIdentifier(value) {
  return String(value || '').replace(/^public\./i, '').replace(/["']/g, '').toLowerCase();
}

function publicRoleList(statement) {
  const roleMatch = statement.match(/\bTO\s+([^;]+?)(?=\s+(?:USING|WITH\s+CHECK)\b|;|$)/i);
  if (!roleMatch) return ['public'];
  return roleMatch[1].split(',').map(role => normalizeIdentifier(role.trim()));
}

export function analyzeRlsSql(content) {
  const sql = String(content || '');
  const tableEvents = [];
  const policyEvents = [];
  const grantEvents = [];
  const functionEvents = [];
  const signals = [];
  let match;

  const rlsRegex = /ALTER\s+TABLE\s+(?:ONLY\s+)?((?:public\.)?["']?\w+["']?)\s+(ENABLE|DISABLE)\s+ROW\s+LEVEL\s+SECURITY/gi;
  while ((match = rlsRegex.exec(sql)) !== null) {
    const table = normalizeIdentifier(match[1]);
    const enabled = match[2].toUpperCase() === 'ENABLE';
    tableEvents.push({ table, enabled, index: match.index });
  }

  const createPolicyRegex = /CREATE\s+POLICY\s+(?:"([^"]+)"|'([^']+)'|(\w+))\s+ON\s+((?:public\.)?["']?\w+["']?)([\s\S]*?);/gi;
  while ((match = createPolicyRegex.exec(sql)) !== null) {
    const name = match[1] || match[2] || match[3];
    const table = normalizeIdentifier(match[4]);
    const statement = match[0];
    const command = statement.match(/\bFOR\s+(ALL|SELECT|INSERT|UPDATE|DELETE)\b/i)?.[1]?.toUpperCase() || 'ALL';
    const roles = publicRoleList(statement);
    const publicFacing = roles.some(role => ['anon', 'authenticated', 'public'].includes(role));
    const alwaysUsing = /\bUSING\s*\(\s*(?:true|'?true'?::boolean)\s*\)/i.test(statement);
    const alwaysCheck = /\bWITH\s+CHECK\s*\(\s*(?:true|'?true'?::boolean)\s*\)/i.test(statement);

    let signal = null;
    if (publicFacing && ['ALL', 'INSERT', 'UPDATE', 'DELETE'].includes(command) && (alwaysUsing || alwaysCheck)) {
      signal = {
        severity: 'HIGH',
        title: `Permissive ${command} policy on "${table}"`,
        detail: `Policy "${name}" grants ${roles.join(', ')} unconditional write access through ${alwaysCheck ? 'WITH CHECK (true)' : 'USING (true)'}.`,
        recommendation: 'Bind write policies to auth.uid() and an ownership or tenant column.',
      };
    }
    policyEvents.push({ action: 'create', table, name: name.toLowerCase(), signal, index: match.index });
  }

  const dropPolicyRegex = /DROP\s+POLICY\s+(?:IF\s+EXISTS\s+)?(?:"([^"]+)"|'([^']+)'|(\w+))\s+ON\s+((?:public\.)?["']?\w+["']?)/gi;
  while ((match = dropPolicyRegex.exec(sql)) !== null) {
    policyEvents.push({
      action: 'drop',
      table: normalizeIdentifier(match[4]),
      name: (match[1] || match[2] || match[3]).toLowerCase(),
      index: match.index,
    });
  }

  const grantRegex = /GRANT\s+([^;]+?)\s+ON\s+(?:TABLE\s+)?((?:public\.)?["']?\w+["']?)\s+TO\s+([^;]+);/gi;
  while ((match = grantRegex.exec(sql)) !== null) {
    const privileges = match[1].replace(/\s+PRIVILEGES\b/i, '').split(',').map(value => value.trim().toUpperCase());
    const table = normalizeIdentifier(match[2]);
    const roles = match[3].split(',').map(role => normalizeIdentifier(role.trim()));
    const publicFacing = roles.some(role => ['anon', 'authenticated', 'public'].includes(role));
    const writes = privileges.filter(privilege => ['ALL', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE'].includes(privilege));
    let signal = null;
    if (publicFacing && writes.length > 0) {
      signal = {
        severity: 'HIGH',
        title: `Direct write grant on "${table}"`,
        detail: `${writes.join(', ')} granted directly to ${roles.join(', ')}. RLS must still constrain every affected operation.`,
        recommendation: 'Grant only required operations and pair every public-facing write grant with restrictive RLS policies.',
      };
    }
    grantEvents.push({ action: 'grant', table, privileges, roles, signal, index: match.index });
  }

  const revokeRegex = /REVOKE\s+([^;]+?)\s+ON\s+(?:TABLE\s+)?((?:public\.)?["']?\w+["']?)\s+FROM\s+([^;]+);/gi;
  while ((match = revokeRegex.exec(sql)) !== null) {
    grantEvents.push({
      action: 'revoke',
      privileges: match[1].replace(/\s+PRIVILEGES\b/i, '').split(',').map(value => value.trim().toUpperCase()),
      table: normalizeIdentifier(match[2]),
      roles: match[3].split(',').map(role => normalizeIdentifier(role.trim())),
      index: match.index,
    });
  }

  const functionRegex = /CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+((?:public\.)?["']?\w+["']?)[\s\S]*?(\$[A-Za-z0-9_]*\$)([\s\S]*?)\2[\s\S]*?;/gi;
  while ((match = functionRegex.exec(sql)) !== null) {
    const name = normalizeIdentifier(match[1]);
    const body = match[3];
    const functionSignals = [];

    if (/\bSECURITY\s+DEFINER\b/i.test(match[0]) && !/auth\.uid\s*\(\s*\)|auth\.role\s*\(\s*\)|current_user\b/i.test(body)) {
      functionSignals.push({
        severity: 'HIGH',
        title: `SECURITY DEFINER function without auth check: ${name}`,
        detail: `Function ${name} runs with owner privileges but has no visible caller identity check.`,
        recommendation: 'Validate auth.uid() or an equivalent trusted caller identity before privileged operations.',
      });
    }

    if (/\bSECURITY\s+DEFINER\b/i.test(match[0]) && !/\bSET\s+(?:LOCAL\s+)?search_path\s*(?:=|TO)\s*/i.test(match[0])) {
      functionSignals.push({
        severity: 'HIGH',
        title: `SECURITY DEFINER function without fixed search_path: ${name}`,
        detail: `Function ${name} does not pin search_path and may resolve attacker-controlled objects with owner privileges.`,
        recommendation: "Set search_path to a trusted minimal value and schema-qualify referenced objects.",
      });
    }
    functionEvents.push({ action: 'create', name, signals: functionSignals, index: match.index });
  }

  const dropFunctionRegex = /DROP\s+FUNCTION\s+(?:IF\s+EXISTS\s+)?((?:public\.)?["']?\w+["']?)/gi;
  while ((match = dropFunctionRegex.exec(sql)) !== null) {
    functionEvents.push({ action: 'drop', name: normalizeIdentifier(match[1]), index: match.index });
  }

  return { tableEvents, policyEvents, grantEvents, functionEvents, signals };
}
