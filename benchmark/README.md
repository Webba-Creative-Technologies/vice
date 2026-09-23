# Engine comparison

Run both engines against the same loopback-only applications. Baseline sources
must come from an unchanged commit; share the installed dependency tree to avoid
comparing different Chromium or dependency versions. No live target is used.

```powershell
node benchmark/improvements.mjs C:/baseline/engine/scan.js ./scan.js C:/temp/results.json 3
```

The optional fifth argument selects comma-separated case IDs. Each repetition
alternates baseline/candidate execution order. Run sequentially without test
suites or other benchmarks in parallel. Use median per-case durations and retain
the individual measurements and server-observed request counts.

## Ground truth

- Application: nested links expose an anonymous credential endpoint, numeric SQL
  injection, a file parameter traversal, an external redirect and reflected XSS.
  The SQL route executes against an in-memory SQLite database, using an unsafe
  query or a parameterized statement. Other data exposures use synthetic records.
- Direct: exposed `.env` and the conventional `/api/users` credential endpoint
  provide a control for defects both versions should detect.
- Supabase: the fixture rejects a publishable key used as a bearer JWT. Its
  exposed table and the protected variant are accessed through the real HTTP
  client, with explicit project configuration.
- Login: a JavaScript form handler rejects the synthetic control; the vulnerable
  variant returns a session only for the injected username.
- GraphQL: an observed POST query on `/transport` exposes credentials in the
  vulnerable variant and rejects unauthenticated access in the fixed variant.
- Delayed DOM: a parameter reaches `innerHTML` after 700 ms, or `textContent`
  in the fixed variant.
- False signals: an unrelated alert, a documentation example containing a passwd
  record and a Location header on HTTP 200 must not prove exploitation.

All vulnerable applications have a corresponding fixed variant. Detection is
counted once per defect class per application, excluding informational and
low-confidence findings. The matcher maps both versions' finding text to the
same defect classes. Retained finding summaries permit independent review.

False positives are measured for these specified defect classes. Infrastructure
hardening findings caused by using loopback HTTP are outside this comparison.
The corpus targets known weaknesses and a delayed-DOM challenge; its recall and
false-positive counts are not production-wide estimates. Score changes are
reported separately from detection gains.

The benchmark uses Node's built-in SQLite support (validated with Node 22.20.0).
Its experimental-module notice on that version is expected.
