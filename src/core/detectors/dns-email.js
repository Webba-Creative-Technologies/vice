export function classifyDkimSearch(foundSelector, testedSelectors = []) {
  if (foundSelector) {
    return {
      severity: 'INFO', confidence: 'high', classification: 'confirmed',
      title: `DKIM record found for selector ${foundSelector}`,
      detail: `Record found on ${foundSelector}._domainkey.`,
    };
  }
  return {
    severity: 'INFO', confidence: 'low', classification: 'heuristic',
    title: 'DKIM status is inconclusive',
    detail: `${testedSelectors.length} common selector(s) were tested, but providers may use an undiscovered selector.`,
  };
}
