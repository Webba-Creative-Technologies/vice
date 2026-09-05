import assert from 'node:assert/strict';
import test from 'node:test';
import { detectAnalyticsStack, recordStackSource, stackSourceLocation, stackSourceUrl } from '../src/core/detectors/stack.js';

const baseUrl = 'https://example.test/';
const script = src => `<script src="${src}"></script>`;

test('provider script declarations use exact hosts and paths', () => {
  const html = [
    script('https://www.googletagmanager.com/gtag/js?id=G-EXAMPLE'),
    script('//cdn.segment.com/analytics.js/v1/example/analytics.min.js'),
    script('https://client.crisp.chat/l.js'),
  ].join('\n');
  const detected = detectAnalyticsStack({ html, baseUrl });
  assert.deepEqual([...detected.keys()], ['Google Analytics', 'Segment', 'Crisp']);
  assert.match(detected.get('Crisp')[0], /HTML https:\/\/example\.test\/:3:1/);
  assert.match(detected.get('Crisp')[0], /execution not verified/);
});

test('lookalike domains, ordinary paths, strings and inactive markup are ignored', () => {
  const html = [
    script('https://client.crisp.chat.example.test/l.js'),
    script('https://client.crisp.chat@elsewhere.test/l.js'),
    script('https://example.test/crisp/analytics.js'),
    script('https://cdn.segment.com/documentation'),
    '<!-- ' + script('https://client.crisp.chat/l.js') + ' -->',
    '<template>' + script('https://client.crisp.chat/l.js') + '</template>',
    '<noscript>' + script('https://client.crisp.chat/l.js') + '</noscript>',
    '<script type="text/plain" src="https://client.crisp.chat/l.js"></script>',
    '<script>const sample = "<script src=\'https://client.crisp.chat/l.js\'>";</script>',
    '<script data-src="https://client.crisp.chat/l.js"></script>',
    '<p>segment crisp google-analytics gtag analytics.track</p>',
  ].join('\n');
  assert.equal(detectAnalyticsStack({ html, baseUrl }).size, 0);
  assert.equal(detectAnalyticsStack({
    baseUrl,
    sources: [{ kind: 'JS', content: 'window.$crisp = []; analytics.track("example"); gtag("config", "G-EXAMPLE");', url: 'https://example.test/cache/app.js', observed: true }],
  }).size, 0);
});

test('a tag manager or Google Ads loader alone does not establish Google Analytics', () => {
  const html = script('https://www.googletagmanager.com/gtm.js?id=GTM-EXAMPLE')
    + script('https://www.googletagmanager.com/gtag/js?id=AW-12345');
  assert.deepEqual([...detectAnalyticsStack({ html, baseUrl }).keys()], ['Google Tag Manager']);
});

test('observed provider responses are distinct from a static fetch or data URL', () => {
  const source = { content: '/* provider fixture */', url: 'https://client.crisp.chat/l.js', kind: 'JS' };
  assert.equal(detectAnalyticsStack({ baseUrl, sources: [source] }).size, 0);
  const detected = detectAnalyticsStack({ baseUrl, sources: [{ ...source, observed: true }] });
  assert.match(detected.get('Crisp')[0], /provider script response observed; tracking activity not verified/);
});

test('source evidence has stable bundle coordinates without credentials or query values', () => {
  const location = stackSourceLocation({
    kind: 'JS',
    content: 'const irrelevant = 1;\nwindow.__REACT_DEVTOOLS__ = {};',
    url: 'https://fixture:password@example.test/cache/app.a1b2.js?access_token=private-value#private-fragment',
  }, 22);
  assert.match(location, /JS https:\/\/example\.test\/cache\/app.a1b2\.js:2:1 \(source [a-f0-9]{12}\)/);
  assert.doesNotMatch(location, /password|private-value|private-fragment|irrelevant/);
  assert.equal(stackSourceUrl('https://cdn.segment.com/analytics.js/v1/private-value/analytics.min.js'), 'https://cdn.segment.com/analytics.js/v1/[REDACTED]/analytics.min.js');
  assert.equal(stackSourceUrl('file:///private/config.js'), '[source unavailable]');
});

test('source collection and repeated evidence remain bounded and isolated', () => {
  const first = {};
  const second = {};
  for (let index = 0; index < 200; index++) recordStackSource(first, 'fixture', baseUrl);
  assert.equal(first.stackSources.length, 180);
  assert.equal(second.stackSources, undefined);
  const sources = Array.from({ length: 20 }, (_, index) => ({ kind: 'JS', observed: true, url: 'https://client.crisp.chat/l.js', content: String(index) }));
  assert.equal(detectAnalyticsStack({ baseUrl, sources }).get('Crisp').length, 4);
});

test('HTML attribute parsing respects quoted delimiters, unquoted URLs and entities', () => {
  const html = '<script data-label="a > b" src=https://client.crisp.chat/l.js></script>'
    + '<SCRIPT SRC="https://www.googletagmanager.com/gtag/js?l=custom&amp;id=G-EXAMPLE"></SCRIPT>';
  assert.deepEqual([...detectAnalyticsStack({ html, baseUrl }).keys()], ['Crisp', 'Google Analytics']);
});
