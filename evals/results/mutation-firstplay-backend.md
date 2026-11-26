# Mutation testing — firstplay-backend @ 4285065daa61

Mutations: 11 · killed: 11 · survived: 0 · errors: 0

**Kill rate 1.0**

Baseline (unmutated) exit 0 in 6.8s — green

| property | mutations | killed | survived | errors | kill rate |
|---|---|---|---|---|---|
| P1 | 3 | 3 | 0 | 0 | 1.0 |
| P4 | 2 | 2 | 0 | 0 | 1.0 |
| P8 | 5 | 5 | 0 | 0 | 1.0 |
| P9 | 1 | 1 | 0 | 0 | 1.0 |

| id | property | result | seconds | description |
|---|---|---|---|---|
| P1-ashby-dom-control-node-unchecked | P1 | killed | 5.0 | parse_ashby_dom trusts the shape of each DOM control node again (the gap that made a scalar node raise AttributeError -> 500 instead of MalformedPayload -> 400; its sibling parse_ashby_posting was hardened in F11 and the fix was never back-ported until 2026-11-25). |
| P1-ashby-dom-label-not-coerced | P1 | killed | 4.9 | A non-string `label` scalar in the DOM extract reaches .strip() again (AttributeError -> 500 instead of being coerced). |
| P1-malformed-input-not-mapped-to-400 | P1 | killed | 2.4 | The one global MalformedInput -> 400 handler is gone (registered for an exception nothing raises instead), so a boundary validator firing in a router without its own `except MalformedPayload` is a 500 again. |
| P4-fetch-body-uncapped | P4 | killed | 6.2 | The fetched job page is no longer read under MAX_HTML_BYTES — the cap is pushed to a terabyte, so an arbitrarily large body streams into memory. |
| P4-fetch-unpinned-client-resolves | P4 | killed | 7.1 | /api/job/url goes back to validating the host once and then letting the HTTP client resolve and connect by name with redirects auto-followed — the DNS-rebinding TOCTOU and the unchecked redirect hop. |
| P8-job-text-unhardened | P8 | killed | 6.7 | parse_jd_text binds the raw scraped posting into the {job_text} placeholder again, bypassing the fence + neutralize chokepoint. |
| P8-job-system-no-directive | P8 | killed | 7.1 | The job-parsing system message drops the data-boundary directive, so the fences around the posting mean nothing to the model. |
| P8-binder-text-unfenced | P8 | killed | 7.7 | The autofill binder formats labels, options and stored answers into its questions raw again (harden_untrusted unwired at the one place form text enters a prompt). |
| P8-binder-choice-unscrubbed | P8 | killed | 6.6 | A model answer's `choice` crosses _decide without scrub_output, so a tripwire marker in model output reaches logs and reasons again. |
| P8-chain-output-unscrubbed | P8 | killed | 6.5 | parse_jd_text returns the model's JobParsed without scrub_model, so a marker that survived the prompt side is stored and returned. |
| P9-sha1-without-usedforsecurity | P9 | killed | 6.3 | The taxonomy fingerprint calls hashlib.sha1() without usedforsecurity=False again — the scanner-tripping default the RC-9 pass removed from all four cache/fingerprint sites. |
