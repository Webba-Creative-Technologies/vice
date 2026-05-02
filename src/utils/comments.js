// ──────────────────────────────────────────────
// VICE — Comment-aware position helper
// Tells you whether a given offset in a file is inside a comment.
// Used by detection modules to skip patterns matched in commented-out code,
// JSDoc blocks, HTML comments, and shell/YAML hash comments.
// Webba Creative Technologies (c) 2026
// ──────────────────────────────────────────────

import path from 'path';

const C_STYLE_EXT = /^\.(?:js|ts|jsx|tsx|mjs|cjs|vue|svelte|css|scss|less|java|c|cpp|cc|h|hpp|go|rs|swift|kt|cs|php|m)$/i;
const HASH_STYLE_EXT = /^\.(?:py|sh|bash|zsh|fish|yml|yaml|toml|conf|cfg|ini|envrc)$/i;

// Inline `//` not preceded by `:` or `/` to avoid matching URLs (https://, file://)
// Lookbehind requires Node 10+; we target 18+ so it's safe.
const C_INLINE_COMMENT = /(?<![:\/])\/\//;

export function isInComment(content, position, filePath) {
  if (!content || position < 0 || position >= content.length) return false;

  const ext = path.extname(filePath || '').toLowerCase();
  const isCStyle = C_STYLE_EXT.test(ext);
  const isHashStyle = HASH_STYLE_EXT.test(ext) || /\.env(\..+)?$/i.test(filePath || '');

  const beforeMatch = content.substring(0, position);

  // HTML/XML comments work in any file
  const htmlOpens = (beforeMatch.match(/<!--/g) || []).length;
  const htmlCloses = (beforeMatch.match(/-->/g) || []).length;
  if (htmlOpens > htmlCloses) return true;

  // C-style block comments
  if (isCStyle) {
    const blockOpens = (beforeMatch.match(/\/\*/g) || []).length;
    const blockCloses = (beforeMatch.match(/\*\//g) || []).length;
    if (blockOpens > blockCloses) return true;
  }

  // Line comments
  const lineStart = content.lastIndexOf('\n', position) + 1;
  const lineEnd = content.indexOf('\n', position);
  const lineContent = content.substring(lineStart, lineEnd === -1 ? content.length : lineEnd);
  const matchOnLine = position - lineStart;
  const trimmedLine = lineContent.trim();

  if (isCStyle) {
    if (trimmedLine.startsWith('//') || trimmedLine.startsWith('*')) return true;
    const cInlineMatch = C_INLINE_COMMENT.exec(lineContent);
    if (cInlineMatch && cInlineMatch.index < matchOnLine) return true;
  }
  if (isHashStyle) {
    if (trimmedLine.startsWith('#')) return true;
    const hashIdx = lineContent.indexOf('#');
    if (hashIdx !== -1 && hashIdx < matchOnLine) return true;
  }

  return false;
}

export function isMarkdownFile(filePath) {
  return /\.(md|mdx|markdown)$/i.test(filePath || '');
}
