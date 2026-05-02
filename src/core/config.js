// ──────────────────────────────────────────────
// VICE — Project config loader (vice.config.js)
// Optional file at project root for custom severity overrides,
// finding transforms, and disabled modules.
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'fs';
import path from 'path';
import { pathToFileURL } from 'url';

const CONFIG_NAMES = ['vice.config.js', 'vice.config.mjs'];

export async function loadConfig(projectPath) {
  for (const name of CONFIG_NAMES) {
    const filePath = path.join(projectPath, name);
    if (!fs.existsSync(filePath)) continue;
    try {
      const mod = await import(pathToFileURL(filePath).href);
      const cfg = mod.default || mod;
      return validateConfig(cfg, filePath);
    } catch (err) {
      process.stderr.write(`VICE: failed to load ${name}: ${err.message}\n`);
      return null;
    }
  }
  return null;
}

function validateConfig(cfg, filePath) {
  if (!cfg || typeof cfg !== 'object') {
    process.stderr.write(`VICE: ${filePath} did not export a config object\n`);
    return null;
  }

  // Warn on type mismatches so users notice typos in their config
  if ('transformFinding' in cfg && typeof cfg.transformFinding !== 'function') {
    process.stderr.write(`VICE: ${filePath} - "transformFinding" must be a function (got ${typeof cfg.transformFinding}), ignored\n`);
  }
  if ('disabledModules' in cfg && !Array.isArray(cfg.disabledModules)) {
    process.stderr.write(`VICE: ${filePath} - "disabledModules" must be an array (got ${typeof cfg.disabledModules}), ignored\n`);
  }
  if ('modules' in cfg && !Array.isArray(cfg.modules)) {
    process.stderr.write(`VICE: ${filePath} - "modules" must be an array (got ${typeof cfg.modules}), ignored\n`);
  }

  return {
    transformFinding: typeof cfg.transformFinding === 'function' ? cfg.transformFinding : null,
    disabledModules: Array.isArray(cfg.disabledModules) ? cfg.disabledModules : [],
    moduleFiles: Array.isArray(cfg.modules) ? cfg.modules : [],
    sourcePath: filePath,
  };
}

// Load each path in cfg.modules as an ES module and validate the export shape.
// Each must export (default or named) an object: { name, value, fn }
// where fn(projectPath, spinner, isIgnored, ctx) is async and uses ctx.addFinding.
export async function loadCustomModules(projectPath, moduleFiles) {
  if (!Array.isArray(moduleFiles) || moduleFiles.length === 0) return [];
  const loaded = [];
  for (const modPath of moduleFiles) {
    const fullPath = path.resolve(projectPath, modPath);
    if (!fs.existsSync(fullPath)) {
      process.stderr.write(`VICE: custom module not found: ${modPath}\n`);
      continue;
    }
    try {
      const imported = await import(pathToFileURL(fullPath).href);
      const def = imported.default || imported;
      if (!def || typeof def !== 'object') {
        process.stderr.write(`VICE: ${modPath} did not export a module object\n`);
        continue;
      }
      if (!def.value || !def.name || typeof def.fn !== 'function') {
        process.stderr.write(`VICE: ${modPath} missing required fields { name, value, fn }\n`);
        continue;
      }
      loaded.push(def);
    } catch (err) {
      process.stderr.write(`VICE: failed to load custom module ${modPath}: ${err.message}\n`);
    }
  }
  return loaded;
}

// Apply transformFinding to every finding. Mutations:
//   - return null/undefined  -> drop the finding
//   - return modified object -> use the new finding
//   - return finding unchanged -> kept as-is
// Errors in transform are isolated: bad transforms log ONCE to stderr (with
// the count of failures) and the original finding is kept on each error.
export function applyTransform(findings, transform) {
  if (!transform) return findings;
  const out = [];
  let firstError = null;
  let errorCount = 0;
  for (const f of findings) {
    let result;
    try {
      result = transform({ ...f });
    } catch (err) {
      if (!firstError) firstError = err.message;
      errorCount++;
      out.push(f);
      continue;
    }
    if (result === null || result === undefined) continue;
    if (typeof result === 'object') out.push(result);
    else out.push(f);
  }
  if (errorCount > 0) {
    process.stderr.write(`VICE: transformFinding threw on ${errorCount} finding(s): ${firstError}\n`);
  }
  return out;
}
