import { isGraphqlRead } from './surfaces.js';

export function subscriptionFrame(text) {
  if (typeof text !== 'string' || text.length > 4096) return null;
  let frame;
  try { frame = JSON.parse(text); } catch { return null; }
  if (frame?.event === 'phx_join' && typeof frame.topic === 'string' && frame.topic.length < 256) {
    const changes = frame.payload?.config?.postgres_changes;
    return JSON.stringify({ topic: frame.topic, event: 'phx_join', ref: 'vice-1', payload: {
      config: { postgres_changes: Array.isArray(changes) ? changes.slice(0, 5).map(change => ({
        event: '*', schema: String(change.schema || 'public').slice(0, 63), table: String(change.table || '*').slice(0, 63),
      })) : [] },
    } });
  }
  if (frame?.type === 'connection_init') return JSON.stringify({ type: 'connection_init', payload: {} });
  if (['subscribe', 'start'].includes(frame?.type) && isGraphqlRead(JSON.stringify(frame.payload))) {
    return JSON.stringify({ id: 'vice-1', type: frame.type, payload: { query: frame.payload.query } });
  }
  return null;
}

export async function captureWebSockets(page, context) {
  const session = await page.createCDPSession();
  const requests = new Map();
  context.webSockets ||= new Map();
  await session.send('Network.enable');
  session.on('Network.webSocketCreated', ({ requestId, url }) => {
    if (context.webSockets.size >= 20) return;
    try {
      const parsed = new URL(url);
      if (parsed.username || parsed.password || [...parsed.searchParams.keys()].some(name => /token|secret|password|authorization/i.test(name))) return;
      requests.set(requestId, parsed.href);
      if (!context.webSockets.has(parsed.href)) context.webSockets.set(parsed.href, []);
    } catch {}
  });
  session.on('Network.webSocketFrameSent', ({ requestId, response }) => {
    const frames = context.webSockets.get(requests.get(requestId));
    const frame = subscriptionFrame(response.payloadData);
    if (frames && frame && frames.length < 4 && !frames.includes(frame)) frames.push(frame);
  });
  return session;
}
