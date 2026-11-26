# Mutation testing — smart-dispatch @ 3e8b35acfda8

Mutations: 17 · killed: 17 · survived: 0 · errors: 0

**Kill rate 1.0**

Baseline (unmutated) exit 0 in 5.9s — green

| property | mutations | killed | survived | errors | kill rate |
|---|---|---|---|---|---|
| P1 | 4 | 4 | 0 | 0 | 1.0 |
| P2 | 2 | 2 | 0 | 0 | 1.0 |
| P4 | 1 | 1 | 0 | 0 | 1.0 |
| P5 | 3 | 3 | 0 | 0 | 1.0 |
| P6 | 5 | 5 | 0 | 0 | 1.0 |
| P8 | 1 | 1 | 0 | 0 | 1.0 |
| P9 | 1 | 1 | 0 | 0 | 1.0 |

| id | property | result | seconds | description |
|---|---|---|---|---|
| P1-forecast-marginal-cost-plain-float | P1 | killed | 2.5 | /forecast parses marginal_cost with float() again, so nan/inf/1e999 reach the margin and emit invalid JSON |
| P1-forecast-range-hours-unbounded | P1 | killed | 2.6 | /forecast/range accepts any integer for hours again (no 1..MAX_RANGE_HOURS bound, no finiteness) |
| P1-django-proxy-plain-float | P1 | killed | 2.7 | Django proxy validates numeric params with float() again, so nan/inf and out-of-range hours leave the process |
| P1-django-proxy-no-param-whitelist | P1 | killed | 2.6 | Django proxy forwards every query parameter upstream instead of the per-route whitelist |
| P2-zip-budget-skipped | P2 | killed | 5.5 | archive members are admitted straight from infolist(): no declared-size, total or ratio check before zf.read |
| P2-fetch-body-uncapped | P2 | killed | 2.9 | ERCOT listing/download bodies are read with no meaningful byte cap (the caller's cap is ignored) |
| P4-fetch-host-allowlist-dropped | P4 | killed | 2.9 | ERCOT fetches are no longer pinned to ercot.com: a redirect or DNS answer elsewhere is followed |
| P5-django-secret-dev-default-in-prod | P5 | killed | 4.4 | SECRET_KEY falls back to the dev placeholder in every environment (no fail-closed require_secret) |
| P5-django-debug-always-on | P5 | killed | 4.1 | DEBUG = True regardless of APP_ENV |
| P5-forecast-api-key-dev-default-in-prod | P5 | killed | 2.2 | the Flask API's bearer key falls back to the dev placeholder in production instead of refusing to start |
| P6-auth-gate-protects-nothing | P6 | killed | 2.1 | the bearer gate no longer covers /forecast* (the pre-fix open API) |
| P6-token-compare-not-constant-time | P6 | killed | 2.2 | bearer token compared with == instead of hmac.compare_digest (timing side channel) |
| P6-cors-wildcard | P6 | killed | 2.1 | CORS(app) wildcard origin again instead of the dashboard origin |
| P6-rate-limit-no-default | P6 | killed | 2.1 | no rate limit on /forecast* (empty default limits) |
| P6-rate-limit-bucket-per-unverified-token | P6 | killed | 2.1 | an unverified token gets its own rate-limit bucket, so rotating wrong tokens escapes the per-address limit |
| P8-harden-untrusted-passthrough | P8 | killed | 3.7 | harden_untrusted returns the retrieved text unchanged (no fence, no neutralisation) |
| P9-k8s-privilege-escalation-allowed | P9 | killed | 3.7 | the forecast deployment's container allows privilege escalation again |
