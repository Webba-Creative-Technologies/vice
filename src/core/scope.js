import dns from 'node:dns/promises';
import net from 'node:net';
import { domainToASCII } from 'node:url';
import { getDomain } from 'tldts';

export class ScopeError extends Error {
  constructor(code, value) {
    super(`${code}: ${value}`);
    this.name = 'ScopeError';
    this.code = code;
    this.value = value;
  }
}

function normalizeHostname(value) {
  const unwrapped = String(value || '').replace(/^\[|\]$/g, '').replace(/\.$/, '').toLowerCase();
  return net.isIP(unwrapped) ? unwrapped : domainToASCII(unwrapped);
}

function ipv4Number(address) {
  const octets = address.split('.').map(Number);
  return (((octets[0] * 256 + octets[1]) * 256 + octets[2]) * 256 + octets[3]) >>> 0;
}

function inIpv4Range(value, base, prefix) {
  const shift = 32 - prefix;
  return (value >>> shift) === (ipv4Number(base) >>> shift);
}

function ipv6Words(address) {
  let source = address.toLowerCase().split('%')[0];
  const ipv4 = source.match(/(?:^|:)(\d+\.\d+\.\d+\.\d+)$/)?.[1];
  if (ipv4) {
    const value = ipv4Number(ipv4);
    source = source.slice(0, source.length - ipv4.length) + `${(value >>> 16).toString(16)}:${(value & 0xffff).toString(16)}`;
  }

  const halves = source.split('::');
  if (halves.length > 2) return null;
  const left = halves[0] ? halves[0].split(':') : [];
  const right = halves[1] ? halves[1].split(':') : [];
  const zeros = halves.length === 2 ? 8 - left.length - right.length : 0;
  const words = [...left, ...Array(Math.max(0, zeros)).fill('0'), ...right].map(word => Number.parseInt(word || '0', 16));
  return words.length === 8 && words.every(word => Number.isInteger(word) && word >= 0 && word <= 0xffff) ? words : null;
}

export function isBlockedIp(address) {
  const normalized = normalizeHostname(address);
  const family = net.isIP(normalized);
  if (family === 4) {
    const value = ipv4Number(normalized);
    return [
      ['0.0.0.0', 8],
      ['10.0.0.0', 8],
      ['100.64.0.0', 10],
      ['127.0.0.0', 8],
      ['169.254.0.0', 16],
      ['172.16.0.0', 12],
      ['192.0.0.0', 24],
      ['192.0.2.0', 24],
      ['192.168.0.0', 16],
      ['198.18.0.0', 15],
      ['198.51.100.0', 24],
      ['203.0.113.0', 24],
      ['224.0.0.0', 4],
      ['240.0.0.0', 4],
    ].some(([base, prefix]) => inIpv4Range(value, base, prefix));
  }

  if (family === 6) {
    const words = ipv6Words(normalized);
    if (!words) return true;
    if (words.every(word => word === 0)) return true;
    if (words.slice(0, 7).every(word => word === 0) && words[7] === 1) return true;
    if ((words[0] & 0xfe00) === 0xfc00) return true;
    if ((words[0] & 0xffc0) === 0xfe80) return true;
    if ((words[0] & 0xff00) === 0xff00) return true;
    if (words[0] === 0x2001 && [0x0000, 0x0002, 0x0db8].includes(words[1])) return true;
    if (words.slice(0, 5).every(word => word === 0) && words[5] === 0xffff) {
      return isBlockedIp(`${words[6] >>> 8}.${words[6] & 255}.${words[7] >>> 8}.${words[7] & 255}`);
    }
    if (words[0] === 0x2002) {
      return isBlockedIp(`${words[1] >>> 8}.${words[1] & 255}.${words[2] >>> 8}.${words[2] & 255}`);
    }
    return false;
  }

  return true;
}

export function authorizedDiscoveryRoot(hostname) {
  const normalized = normalizeHostname(hostname);
  const registrable = getDomain(normalized, { allowPrivateDomains: true });
  return registrable && registrable === normalized ? registrable : normalized;
}

function hostMatchesRoot(hostname, root, includeSubdomains) {
  return hostname === root || (includeSubdomains && hostname.endsWith(`.${root}`));
}

export function createScopePolicy(targetUrl, options = {}) {
  const target = new URL(targetUrl);
  const primaryHost = normalizeHostname(target.hostname);
  const includeSubdomains = options.includeSubdomains !== false;
  const allowedHosts = new Set((options.allowedHosts || []).map(normalizeHostname));
  const trustedHosts = new Set((options.trustedHosts || []).map(normalizeHostname));
  const discoveredHosts = new Set();
  const allowedProtocols = new Set(options.allowedProtocols || ['http:', 'https:', 'ws:', 'wss:']);
  const targetPort = target.port || (target.protocol === 'http:' ? '80' : '443');
  const allowedPorts = new Set((options.allowedPorts || ['80', '443']).map(String));
  allowedPorts.add(targetPort);
  const allowPrivateTargets = options.allowPrivateTargets === true;
  const resolver = options.resolver || ((hostname) => dns.lookup(hostname, { all: true, verbatim: true }));
  const maxDnsResolutions = options.maxDnsResolutions ?? 512;
  const maxDnsAnswers = options.maxDnsAnswers ?? 64;
  const pinnedAddresses = new Map();
  const counters = { dns_resolutions: 0, budget_exhausted: false };

  function isHostAllowed(hostname) {
    const normalized = normalizeHostname(hostname);
    return hostMatchesRoot(normalized, primaryHost, includeSubdomains)
      || allowedHosts.has(normalized)
      || trustedHosts.has(normalized)
      || discoveredHosts.has(normalized);
  }

  async function assertUrl(value, assertOptions = {}) {
    let url;
    try {
      url = value instanceof URL ? new URL(value.toString()) : new URL(String(value));
    } catch {
      throw new ScopeError('invalid_url', value);
    }

    const hostname = normalizeHostname(url.hostname);
    if (!allowedProtocols.has(url.protocol)) throw new ScopeError('blocked_protocol', url.protocol);
    if (url.username || url.password) throw new ScopeError('blocked_url_credentials', url.origin);
    if (!isHostAllowed(hostname)) throw new ScopeError('blocked_host', hostname);

    const port = url.port || (url.protocol === 'http:' || url.protocol === 'ws:' ? '80' : '443');
    if (!allowedPorts.has(port)) throw new ScopeError('blocked_port', port);

    let records;
    const previous = pinnedAddresses.get(hostname);
    if (assertOptions.reusePinned === true && previous) {
      records = previous.map(address => ({ address, family: net.isIP(address) }));
    } else if (net.isIP(hostname)) {
      records = [{ address: hostname, family: net.isIP(hostname) }];
    } else {
      if (counters.dns_resolutions >= maxDnsResolutions) {
        counters.budget_exhausted = true;
        throw new ScopeError('dns_budget_exhausted', hostname);
      }
      try {
        counters.dns_resolutions++;
        records = await resolver(hostname);
      } catch {
        throw new ScopeError('host_resolution_failed', hostname);
      }
    }
    if ((records || []).length > maxDnsAnswers) throw new ScopeError('dns_answer_too_large', hostname);
    const addresses = [...new Set((records || []).map(record => normalizeHostname(record.address)).filter(Boolean))].sort();
    if (addresses.length === 0) throw new ScopeError('host_resolution_failed', hostname);
    if (!allowPrivateTargets && addresses.some(isBlockedIp)) throw new ScopeError('blocked_private_target', hostname);

    if (previous && previous.join(',') !== addresses.join(',')) throw new ScopeError('dns_rebinding_detected', hostname);
    pinnedAddresses.set(hostname, addresses);
    return { url, hostname, addresses, trusted: trustedHosts.has(hostname) };
  }

  return {
    target: target.toString(),
    primaryHost,
    discoveryRoot: authorizedDiscoveryRoot(primaryHost),
    assertUrl,
    isHostAllowed,
    isPrimaryHost(hostname) {
      return hostMatchesRoot(normalizeHostname(hostname), primaryHost, includeSubdomains);
    },
    isPrimaryOrigin(value) {
      try { return new URL(String(value)).origin === target.origin; } catch { return false; }
    },
    getPinnedAddresses(hostname = primaryHost) {
      return [...(pinnedAddresses.get(normalizeHostname(hostname)) || [])];
    },
    assertAddress(address, port) {
      const normalized = normalizeHostname(address);
      if (!net.isIP(normalized)) throw new ScopeError('invalid_ip', address);
      if (!allowedPorts.has(String(port))) throw new ScopeError('blocked_port', port);
      const authorized = pinnedAddresses.get(primaryHost) || [];
      if (!authorized.includes(normalized)) throw new ScopeError('blocked_address', normalized);
      if (!allowPrivateTargets && isBlockedIp(normalized)) throw new ScopeError('blocked_private_target', normalized);
      return normalized;
    },
    async authorizeDiscoveredUrl(value, assertOptions = {}) {
      let url;
      try { url = new URL(String(value)); } catch { throw new ScopeError('invalid_url', value); }
      const hostname = normalizeHostname(url.hostname);
      if (!allowedProtocols.has(url.protocol)) throw new ScopeError('blocked_protocol', url.protocol);
      if (url.username || url.password) throw new ScopeError('blocked_url_credentials', url.origin);
      const port = url.port || (url.protocol === 'http:' || url.protocol === 'ws:' ? '80' : '443');
      const wasDiscovered = discoveredHosts.has(hostname);
      discoveredHosts.add(hostname);
      allowedPorts.add(port);
      try {
        return await assertUrl(url, assertOptions);
      } catch (error) {
        if (!wasDiscovered) discoveredHosts.delete(hostname);
        throw error;
      }
    },
    metrics() {
      return { ...counters, pinned_hosts: pinnedAddresses.size, discovered_hosts: discoveredHosts.size };
    },
  };
}
