import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

import { classifyCodeSink } from '../src/core/detectors/code-sinks.js';

const corpus = JSON.parse(readFileSync(new URL('./fixtures/detection-corpus.json', import.meta.url), 'utf8'));

for (const fixture of corpus.codeSinks) {
  test(`code sink corpus classifies ${fixture.name}`, () => {
    const result = classifyCodeSink(fixture.kind, fixture.source);
    if (fixture.ignored) {
      assert.equal(result, null);
      return;
    }

    assert.equal(result?.severity, fixture.severity);
    assert.equal(result?.confidence, fixture.confidence);
  });
}
