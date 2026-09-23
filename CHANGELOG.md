# Changelog

## 3.4.2 (unreleased)

- Validate the candidate against the unchanged 3.4.1 engine on paired local
  applications; include delayed DOM execution in XSS observation.
- Discover login forms on the requested page and observed application pages;
  exclude registration forms from synthetic login submissions.

- Share a bounded inventory of application routes, forms, parameters, API
  responses and read-only GraphQL requests across remote audit modules.
- Confirm XSS through a unique browser execution marker, compare injection
  responses with controls, and exercise actual login handlers with bounded
  synthetic credentials.
- Support Supabase publishable keys, preserve legacy anon JWT support and
  avoid combining unrelated project keys. Public client keys are informational.
- Inspect storage contents and registered WordPress REST routes, capture
  observed realtime subscriptions and seed AI discovery from application traffic.
- Correct CSP precedence, DMARC inheritance and TLS protocol uncertainty.
- Cap scores when confirmed high or critical impact exists, account for
  incomplete coverage and avoid multiple penalties for an explicit shared cause.
- Reuse Chromium within a scan while retaining isolated browser contexts.

Scoring version: `2026.09.23.1`. Existing reports keep their original scores.
No production detection rate or speed improvement is claimed from local fixtures.
