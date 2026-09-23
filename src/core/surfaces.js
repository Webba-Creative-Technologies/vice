const ACTION_PATH = /(?:^|\/)(?:logout|signout|delete|remove|unsubscribe|checkout|purchase|pay|reset-password|verify-email)(?:\/|$)/i;
const SECRET_PARAMETER = /^(?:access_token|refresh_token|token|secret|password|code|api[_-]?key|signature)$/i;
const ASSET_PATH = /\.(?:js|css|map|png|jpe?g|gif|svg|woff2?|ico|mp4|pdf|zip)$/i;

export function isGraphqlRead(body) {
  try {
    const payload = JSON.parse(body);
    const operations = Array.isArray(payload) ? payload : [payload];
    if (!operations.length || operations.length > 5) return false;
    return operations.every(operation => {
      if (typeof operation?.query !== 'string' || operation.query.length > 16384) return false;
      const query = operation.query.replace(/"""[\s\S]*?"""|"(?:\\.|[^"\\])*"|#[^\n]*/g, ' ');
      return /^\s*(?:query\b|\{)/.test(query) && !/\b(?:mutation|subscription)\b/.test(query);
    });
  } catch { return false; }
}

export function surfaceUrl(value, baseUrl) {
  try {
    const url = new URL(value, baseUrl);
    if (url.origin !== new URL(baseUrl).origin || url.username || url.password || ACTION_PATH.test(url.pathname)) return null;
    if ([...url.searchParams.keys()].some(key => SECRET_PARAMETER.test(key))) return null;
    if (url.href.length > 2048) return null;
    return url;
  } catch { return null; }
}

export function createSurfaceInventory(baseUrl, limits = {}) {
  const pages = new Map();
  const requests = new Map();
  const forms = new Map();
  const maxPages = limits.pages || 24;
  const maxRequests = limits.requests || 120;
  const parameterValues = new Map();
  function addPage(value, depth = 0) {
    const url = surfaceUrl(value, baseUrl);
    if (!url || ASSET_PATH.test(url.pathname) || depth > 3 || pages.size >= maxPages) return;
    const key = url.href;
    if (!pages.has(key)) pages.set(key, { url: key, depth, visited: false });
  }
  function addRequest(value, options = {}) {
    const url = surfaceUrl(value, baseUrl);
    if (!url || requests.size >= maxRequests || ASSET_PATH.test(url.pathname)) return;
    const method = String(options.method || 'GET').toUpperCase();
    const body = typeof options.body === 'string' && options.body.length <= 16384 ? options.body : null;
    if (method !== 'GET' && !(method === 'POST' && isGraphqlRead(body))) return;
    const key = `${method}:${url.href}:${body || ''}`;
    if (!requests.has(key)) requests.set(key, { url: url.href, method, body, authenticated: Boolean(options.authenticated), contentType: options.contentType || '' });
    else if (options.contentType) requests.get(key).contentType = options.contentType;
    for (const [name, value] of url.searchParams) {
      if (value.length <= 128 && !SECRET_PARAMETER.test(name)) {
        const values = parameterValues.get(name) || new Set();
        if (values.size < 5) values.add(value);
        parameterValues.set(name, values);
      }
    }
  }
  function addForm(form, pageUrl) {
    const url = surfaceUrl(form.action || pageUrl, baseUrl);
    if (!url || forms.size >= 30) return;
    const inputs = (form.inputs || []).slice(0, 30).filter(input => typeof input.name === 'string' && input.name.length <= 128);
    const method = String(form.method || 'GET').toUpperCase();
    forms.set(`${method}:${url.href}:${inputs.map(input => input.name).join(',')}`, { ...form, action: url.href, pageUrl, method, inputs });
    if (method === 'GET' && !inputs.some(input => input.type === 'password')) {
      for (const input of inputs) if (!SECRET_PARAMETER.test(input.name)) url.searchParams.set(input.name, input.value || 'vice');
      addRequest(url.href);
    }
  }
  function nextPage() {
    return [...pages.values()].filter(page => !page.visited).sort((a, b) => {
      const priority = value => /account|dashboard|search|document|file|admin|profile|login|api/i.test(value) ? 0 : 1;
      return priority(a.url) - priority(b.url) || a.depth - b.depth;
    })[0];
  }
  addPage(baseUrl);
  return { pages, requests, forms, parameterValues, addPage, addRequest, addForm, nextPage };
}

export async function collectPageSurfaces(page, inventory, depth = 0) {
  const snapshot = await page.evaluate(() => ({
    links: [...document.querySelectorAll('a[href]')].slice(0, 150).map(link => link.href),
    forms: [...document.forms].slice(0, 20).map(form => ({
      action: form.action, method: form.method,
      inputs: [...form.querySelectorAll('input,textarea,select')].slice(0, 30).map(input => ({
        name: input.name, type: input.type || 'text', value: input.type === 'password' || input.type === 'hidden' ? '' : input.value.slice(0, 128),
      })),
    })),
  }));
  for (const link of snapshot.links) inventory.addPage(link, depth + 1);
  for (const form of snapshot.forms) inventory.addForm(form, page.url());
  inventory.addRequest(page.url());
}
