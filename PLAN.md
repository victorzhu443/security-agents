# Plan: building the two security skill areas into every project

Goal — turn two resume bullets into genuine, demonstrable experience:

- **A. Security tooling** — Burp Suite, Semgrep, fuzzing frameworks, Metasploit.
- **B. Prompt injection / jailbreak** — hands-on, defensive, against our own LLM apps.

Approach: a shared toolkit (`security-agents/`) + a per-project integration that
wires the toolkit to that project's real attack surface. Every item below is a
concrete task with a status: `[x]` done, `[~]` scaffolded/needs a run, `[ ]` planned.

Legend for who: items marked (toolkit) are in this repo; the rest land in each
project under `tests/security/`, `semgrep` config, and `SECURITY.md`.

---

## Shared toolkit (security-agents/) — done

- [x] Semgrep custom ruleset incl. an LLM01 prompt-sink rule (`semgrep/rules.yml`), runner (`scan.sh`).
- [x] Prompt-injection corpus + harness + defenses; vulnerable stub 1/8 → hardened 8/8 (`promptinject/`).
- [x] Hypothesis fuzzing library with the safe-degradation property (`fuzzing/fuzz_lib.py`).
- [x] Burp Suite and Metasploit runbooks (`runbooks/`).

---

## 1. research-replication-agent  (Python LLM agent; papers are untrusted model input)

Attack surface: `replicator/llm.py` (model calls), `spec/extract.py` (paper text
→ prompt), paper/JSON parsers. The compelling threat: a paper PDF carrying an
injected instruction that steers the replication verdict or coerces a tool call.

- [x] A. Semgrep: custom rules + `p/python`/`p/secrets` scan; triage findings.
- [x] A. Fuzzing: Hypothesis target on the paper/JSON parsing path (safe-degradation).
- [x] B. Injection: wire `promptinject` to the paper-text input path; score + harden.
- [x] SECURITY.md with threat model, findings, and how to re-run.
- [ ] B. Stretch: a per-paper "trust boundary" note in the run report (model saw untrusted text here).

## 2. smart-dispatch  (Django UI + /forecast + /query RAG API; Docker/k8s)

Attack surface: `frontend/smart_ui/settings.py` (Django config), the REST API,
`data_ingestion` (ERCOT feed parser), the RAG `/query` path.

- [~] A. Semgrep: `p/django` + `p/owasp-top-ten` + custom; **known findings**: hardcoded
  `SECRET_KEY`, `DEBUG = True` in `settings.py` → move to env. Fix + re-scan.
- [~] A. Fuzzing: Hypothesis target on the ERCOT ingestion row parser.
- [~] B. Injection: wire `promptinject` to the `/query` RAG answer path.
- [ ] A. Burp: run the `runbooks/burp-suite.md` passes against the local API; record in SECURITY.md.
- [~] SECURITY.md.

## 3. firstplay  (FastAPI backend + React frontend + extension; LLM autofill)

Attack surface: `app/llm_client.py`, `app/autofill/` (scraped page → fields),
the extension's content handling. Note: not a git repo — keep changes additive
under `firstplay/firstplay-backend/security/` and `tests/security/`.

- [~] A. Semgrep: full-stack scan (Python `p/python` + JS `p/javascript` + `p/owasp-top-ten`).
- [~] A. Fuzzing: Hypothesis target on the page/field extraction parser.
- [~] B. Injection: wire `promptinject` to the autofill source-text path.
- [ ] A. Burp: passes against the local FastAPI app; record findings.
- [~] SECURITY.md.

## 4. study-hub  (data collection; many parsers of untrusted web/Canvas content)

Attack surface: `scripts/adapters.py`, `extract_text.py`, `redact.py`, `ledger.py`
— all parse content fetched from the internet. No model sink, so this is a
tooling-only target (A), and a strong fuzzing one.

- [~] A. Semgrep: custom + `p/python` + `p/secrets`.
- [~] A. Fuzzing: Hypothesis targets on the HTML/Canvas/text parsers (best fuzz targets in the set).
- [~] SECURITY.md (note: no LLM sink, so B is N/A here and that's documented).

## 5. housing, resume  — N/A

- housing is empty; resume is LaTeX. No application surface. The resume gets
  updated to reflect the genuine experience the items above create.

---

## Sequencing

1. Toolkit (done) → 2. research-replication-agent reference integration (done, by hand)
→ 3. smart-dispatch / firstplay / study-hub integrations (parallel, from the reference)
→ 4. Burp/Metasploit lab exercises (manual, your half-day) → 5. resume update.

## Definition of done per project

A project is "done" for the automated part when: `semgrep/scan.sh <proj>` runs
and its findings are triaged in SECURITY.md; `pytest tests/security/` passes
(fuzz targets + injection harness); and, where there's a model sink, the injection
report shows the hardened path resisting the corpus.

---

## Status — completed 2026-11-25

All five projects done for the automated part. 33 security tests pass
(research-replication-agent 7, firstplay 10, study-hub 4 + 1 documented xfail,
smart-dispatch 5, toolkit self-tests 7). Burp/Metasploit remain the manual
half-day exercises (runbooks written).

| Project | SAST (Semgrep) | Fuzzing | Prompt-injection |
|---|---|---|---|
| research-replication-agent | 1 flagged (`pickle.load`) | parsers robust | data-boundary directive added to paper prompts; corpus resisted |
| firstplay | 6 low (SHA1 cache keys, unpinned Actions) | **bug: `parse_ashby_dom` 500s on malformed DOM** | undefended 7 land → hardened 8/8 |
| smart-dispatch | fixed hardcoded `SECRET_KEY` + `DEBUG=True`; 32 triaged | ERCOT parsers robust | no live RAG sink (removed); stand-in resisted |
| study-hub | 1 non-crypto SHA1 (triaged) | **bug: ReDoS in `redact.redact` on whitespace runs** | N/A (no model sink) |

**Two real bugs surfaced by fuzzing**, both documented with a verified fix and
left for Victor to apply (not committed):
- firstplay `app/autofill/ashby.py` `parse_ashby_dom` — undeclared exception
  (HTTP 500) on malformed DOM from the untrusted extension; back-port the
  `parse_ashby_posting` shape checks.
- study-hub `scripts/redact.py` header patterns — catastrophic backtracking
  (2000 newlines = 93s); fix is `\s` → `[ \t]` in the two header anchors.
