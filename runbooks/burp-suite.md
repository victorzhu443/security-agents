# Burp Suite runbook — testing the web apps (authorized, local only)

Scope: **your own** applications on localhost — `firstplay` (FastAPI backend +
React frontend + browser extension) and `smart-dispatch` (Django UI + `/forecast`
and `/query` REST API). Never point Burp at a host you do not own or have written
authorization to test. This runbook is the methodology; Burp is a GUI/manual
tool, so these are the steps you run, not something a script does for you.

## Setup

1. Start the target locally (e.g. `smart-dispatch`: `python manage.py runserver`;
   `firstplay-backend`: `uvicorn app.main:app --reload`).
2. Burp → Proxy → set browser proxy to `127.0.0.1:8080`, install Burp's CA cert.
3. Define scope: Target → Scope → add `http://localhost:8000` (and the API port).
   Turn on "proxy only in-scope" so you never capture unrelated traffic.

## The passes, in order

| Pass | Burp tool | What you are looking for |
|---|---|---|
| Map | Proxy + Target site map | every route, param, cookie, header; the real attack surface |
| AuthN/AuthZ | Repeater | hit authenticated routes with no / another user's token (IDOR, missing checks) |
| Input handling | Repeater + Intruder | reflected values, error leaks, SQLi/XSS on each param (sniper payload set) |
| Injection (LLM) | Repeater | send the `promptinject` corpus payloads through `/query` and any field that reaches a model; does the answer get subverted? |
| Rate / abuse | Intruder | does the forecast/query endpoint throttle? resource exhaustion on large bodies |
| Headers/TLS | Passive scan | missing CSP/HSTS/X-Content-Type-Options, verbose `Server`, CORS `*` |

## Recording findings

For each issue: request + response, the exact param, severity (CVSS-ish), repro
steps, and a fix. Put them in the project's `SECURITY.md`. A finding you cannot
reproduce from a saved Repeater tab is not yet a finding.

## Ties into the toolkit

The LLM-injection pass reuses `promptinject/corpus` — paste a canary payload into
a request, and if the canary comes back in the response, that endpoint has the
same data-as-instruction flaw the harness scores automatically. Burp is how you
confirm it over the real HTTP boundary, with auth and headers in play.
