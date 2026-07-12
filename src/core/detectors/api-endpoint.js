export function resolveFirstPartyApiEndpoint(baseUrl, candidate) {
  try {
    const base = new URL(baseUrl);
    const endpoint = new URL(candidate, base);
    return endpoint.origin === base.origin ? endpoint.toString() : null;
  } catch {
    return null;
  }
}
