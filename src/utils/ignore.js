// ──────────────────────────────────────────────
// VICE — .viceignore Parser
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import fs from 'fs';
import path from 'path';

function globToRegex(pattern) {
  let regex = '';
  let i = 0;
  while (i < pattern.length) {
    const c = pattern[i];
    if (c === '*') {
      if (pattern[i + 1] === '*') {
        if (pattern[i + 2] === '/') {
          regex += '(?:.*/)?';
          i += 3;
        } else {
          regex += '.*';
          i += 2;
        }
      } else {
        regex += '[^/]*';
        i++;
      }
    } else if (c === '?') {
      regex += '[^/]';
      i++;
    } else if ('.+^${}()|[]\\'.includes(c)) {
      regex += '\\' + c;
      i++;
    } else {
      regex += c;
      i++;
    }
  }
  return new RegExp(regex);
}

export async function loadViceignore(projectPath) {
  const ignorePath = path.join(projectPath, '.viceignore');
  let content;
  try { content = await fs.promises.readFile(ignorePath, 'utf-8'); } catch { return () => false; }

  const patterns = content
    .split('\n')
    .map(line => line.trim())
    .filter(line => line && !line.startsWith('#'))
    .map(globToRegex);

  if (patterns.length === 0) return () => false;

  return (relativePath) => {
    const normalized = relativePath.replace(/\\/g, '/');
    return patterns.some(regex => regex.test(normalized));
  };
}
