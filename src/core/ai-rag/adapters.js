const PATH_PATTERN = /^[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]+)*$/;
const RESERVED_PATH_PARTS = new Set(['__proto__', 'constructor', 'prototype']);

function cloneTemplate(value) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return {};
  return JSON.parse(JSON.stringify(value));
}

function pathParts(path) {
  if (typeof path !== 'string' || !PATH_PATTERN.test(path)) return [];
  const parts = path.split('.');
  return parts.some((part) => RESERVED_PATH_PARTS.has(part)) ? [] : parts;
}

function setPath(target, path, value) {
  const parts = pathParts(path);
  if (parts.length === 0) throw new Error('invalid_ai_rag_mapping');
  let current = target;
  for (let index = 0; index < parts.length - 1; index++) {
    const part = parts[index];
    if (!current[part] || typeof current[part] !== 'object' || Array.isArray(current[part])) current[part] = {};
    current = current[part];
  }
  current[parts.at(-1)] = value;
}

export function getPath(source, path) {
  if (!path) return source;
  const parts = pathParts(path);
  if (parts.length === 0) return undefined;
  let current = source;
  for (const part of parts) {
    if (current === null || current === undefined) return undefined;
    const key = Array.isArray(current) && /^\d+$/.test(part) ? Number(part) : part;
    current = current[key];
  }
  return current;
}

export function buildAiRequest(config, prompt, conversationId = null) {
  if (config.adapter === 'openai-compatible') {
    const body = cloneTemplate(config.requestTemplate);
    body.messages = [{ role: 'user', content: prompt }];
    if (config.model) body.model = config.model;
    if (conversationId && config.conversationRequestField) {
      setPath(body, config.conversationRequestField, conversationId);
    }
    return JSON.stringify(body);
  }

  const body = cloneTemplate(config.requestTemplate);
  setPath(body, config.messageField, prompt);
  if (conversationId && config.conversationRequestField) {
    setPath(body, config.conversationRequestField, conversationId);
  }
  return JSON.stringify(body);
}

function textValue(value) {
  if (typeof value === 'string') return value;
  if (typeof value === 'number' || typeof value === 'boolean') return String(value);
  return '';
}

function parseSse(raw, config) {
  const parts = [];
  let conversationId = null;
  for (const line of raw.split(/\r?\n/)) {
    if (!line.startsWith('data:')) continue;
    const value = line.slice(5).trim();
    if (!value || value === '[DONE]') continue;
    try {
      const data = JSON.parse(value);
      const content = getPath(data, config.streamResponseField)
        ?? getPath(data, config.responseField);
      const nextConversationId = getPath(data, config.conversationResponseField);
      if (nextConversationId !== undefined && nextConversationId !== null) conversationId = String(nextConversationId);
      const text = textValue(content);
      if (text) parts.push(text);
    } catch {}
  }
  return { text: parts.join(''), conversationId };
}

export function parseAiResponseBody(raw, contentType, config) {
  if (contentType.includes('text/event-stream') || config.streaming === 'sse') {
    return parseSse(raw, config);
  }

  try {
    const data = JSON.parse(raw);
    const text = textValue(getPath(data, config.responseField));
    const conversation = getPath(data, config.conversationResponseField);
    return {
      text,
      conversationId: conversation === undefined || conversation === null ? null : String(conversation),
    };
  } catch {
    return { text: raw, conversationId: null };
  }
}
