const SERVICE_NAMES = {
  21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 80: 'HTTP', 443: 'HTTPS',
  3000: 'Dev Server', 3306: 'MySQL', 4200: 'Angular Dev', 5432: 'PostgreSQL',
  5555: 'Prisma Studio', 6379: 'Redis', 8000: 'HTTP Alt', 8080: 'HTTP Proxy',
  8443: 'HTTPS Alt', 8888: 'Jupyter', 9000: 'Portainer', 9090: 'Prometheus',
  9200: 'Elasticsearch', 27017: 'MongoDB',
};

function result(port, severity, confidence, classification, state, title, recommendation = '') {
  return { port, severity, confidence, classification, state, title, recommendation };
}

export function classifyOpenService(port, banner = '') {
  const text = String(banner || '');
  const name = SERVICE_NAMES[port] || `service on port ${port}`;

  if (port === 80 || port === 443) return null;
  if (port === 23) return result(port, 'CRITIQUE', 'high', 'confirmed', 'insecure-protocol', 'Telnet is reachable from the Internet', 'Disable Telnet and use SSH.');
  if (port === 21) return result(port, 'ELEVEE', 'high', 'confirmed', 'insecure-protocol', 'FTP is reachable from the Internet', 'Use SFTP or another encrypted transfer protocol.');
  if (port === 22) return result(port, 'INFO', 'high', 'confirmed', 'reachable', 'SSH is reachable from the Internet', 'Restrict source addresses and prefer key authentication.');
  if (port === 25) return result(port, 'INFO', 'high', 'confirmed', 'reachable', 'SMTP is reachable from the Internet', 'An open port does not prove open relay; test relay policy separately.');

  if (port === 6379) {
    if (/\+PONG|redis_version/i.test(text)) return result(port, 'CRITIQUE', 'high', 'confirmed', 'unauthenticated', 'Redis responds without an authentication challenge', 'Bind Redis privately and require authenticated, encrypted access.');
    if (/-NOAUTH|authentication required/i.test(text)) return result(port, 'INFO', 'high', 'confirmed', 'auth-required', 'Redis is reachable but requires authentication', 'Prefer private network exposure even when authentication is enabled.');
    return result(port, 'FAIBLE', 'low', 'heuristic', 'port-only', 'Port 6379 is open but Redis access is unconfirmed', 'Confirm the service and restrict it to a private network if possible.');
  }

  if ([3306, 5432, 27017].includes(port)) {
    const protocolSeen = /mysql|mariadb|postgres|mongodb|wire protocol|authentication/i.test(text);
    return protocolSeen
      ? result(port, 'MOYENNE', 'high', 'probable', 'protocol-confirmed', `${name} protocol is reachable from the Internet`, `Restrict ${name} to private networks and require encrypted authentication.`)
      : result(port, 'FAIBLE', 'low', 'heuristic', 'port-only', `Port ${port} is open but ${name} access is unconfirmed`, `Identify the service and restrict database exposure if confirmed.`);
  }

  if (port === 9200) {
    if (/HTTP\/\d(?:\.\d)?\s+(?:401|403)|www-authenticate/i.test(text)) return result(port, 'INFO', 'high', 'confirmed', 'auth-required', 'Elasticsearch endpoint is reachable but access-controlled', 'Keep authentication enabled and restrict network exposure.');
    if (/HTTP\/\d(?:\.\d)?\s+200|elasticsearch|x-elastic-product/i.test(text)) return result(port, 'ELEVEE', 'medium', 'probable', 'http-reachable', 'Probable Elasticsearch HTTP endpoint is publicly reachable', 'Require authentication and restrict the endpoint to trusted networks.');
    return result(port, 'FAIBLE', 'low', 'heuristic', 'port-only', 'Port 9200 is open but Elasticsearch is unconfirmed', 'Identify the service before treating this as Elasticsearch exposure.');
  }

  if ([3000, 4200, 5555, 8888, 9000, 9090].includes(port)) {
    const recognized = /next\.js|nuxt|angular|prisma|jupyter|portainer|prometheus|grafana|HTTP\/\d/i.test(text);
    return recognized
      ? result(port, 'MOYENNE', 'medium', 'probable', 'service-confirmed', `${name} appears publicly reachable`, `Authenticate ${name} and restrict it to trusted networks.`)
      : result(port, 'FAIBLE', 'low', 'heuristic', 'port-only', `Port ${port} is open but ${name} is unconfirmed`, 'Identify the service and review whether public exposure is intended.');
  }

  if ([8000, 8080, 8443].includes(port)) {
    return result(port, 'INFO', 'high', 'confirmed', 'reachable', `Alternative web port ${port} is reachable`, 'Review the service and restrict it if it hosts administrative functionality.');
  }

  return result(port, 'INFO', 'high', 'confirmed', 'reachable', `Port ${port} is reachable`, 'Review whether public exposure is intended.');
}

export function classifyHttpOnlySubdomain({ httpStatus, httpsReachable, subName }) {
  const nonHttpNames = new Set(['ftp', 'sftp', 'smtp', 'imap', 'pop', 'mail', 'mx', 'ssh', 'vpn', 'sip', 'irc', 'ldap', 'ntp', 'dns']);
  if (httpsReachable || nonHttpNames.has(String(subName || '').toLowerCase())) return null;
  if (!Number.isInteger(httpStatus) || httpStatus < 200 || httpStatus >= 400) return null;
  return { severity: 'MOYENNE', confidence: 'high', classification: 'confirmed' };
}
