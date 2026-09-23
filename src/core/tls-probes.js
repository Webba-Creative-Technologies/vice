import tls from 'node:tls';

export async function probeTls(options, connect = tls.connect) {
  return new Promise(resolve => {
    let socket;
    let settled = false;
    const finish = result => {
      if (settled) return;
      settled = true;
      options.signal?.removeEventListener('abort', abort);
      socket?.destroy();
      resolve(result);
    };
    const abort = () => finish({ state: 'unknown', reason: 'aborted' });
    if (options.signal?.aborted) { abort(); return; }
    options.signal?.addEventListener('abort', abort, { once: true });
    try {
      const { signal, ...connection } = options;
      socket = connect({ ...connection, timeout: 4000, rejectUnauthorized: false }, () => finish({ state: 'accepted', protocol: socket.getProtocol(), cipher: socket.getCipher()?.name }));
      socket.on('timeout', () => finish({ state: 'unknown', reason: 'timeout' }));
      socket.on('error', error => finish({
        state: /alert protocol version|alert handshake failure/i.test(error.message) ? 'rejected' : 'unknown',
        reason: /no ciphers|no protocols|unsupported protocol/i.test(error.message) ? 'client_capability' : 'handshake',
      }));
    } catch { finish({ state: 'unknown', reason: 'client_capability' }); }
  });
}

export function weakTlsCiphers(available = tls.getCiphers()) {
  return ['DES-CBC3-SHA', 'RC4-SHA', 'RC4-MD5', 'NULL-SHA'].filter(cipher => available.includes(cipher.toLowerCase()));
}
