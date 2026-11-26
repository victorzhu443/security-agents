# Root-cause analysis — all security issues across every repo

Every issue found in the security effort (research-replication-agent, firstplay,
smart-dispatch, study-hub; toolkit = security-agents), consolidated by **root
cause** rather than symptom. The point: one solution per root cause fixes many
symptoms at once. The next phase designs a complete solution for each RC below.

Status key: **FIXED** = patched + tested in the open PR; **DOC** = documented
with a recommended fix, not yet applied.

Repos: RRA = research-replication-agent · FP = firstplay · SD = smart-dispatch ·
SH = study-hub.

---

## RC-1 — Untrusted input is not validated for safe shape / type / domain / path at the boundary

The code accepts data from an untrusted source and uses its structure or value
without first checking it is well-formed and in-range. A sub-pattern: a
validation fix was applied to one parser but **not propagated to its siblings**.

| # | Symptom | Repo | Status |
|---|---|---|---|
| 1 | `parse_ashby_dom` 500s on malformed DOM — no shape check; its sibling `parse_ashby_posting` was hardened (audit F11) but the fix was never back-ported | FP | FIXED |
| 2 | `/forecast` accepts `marginal_cost = NaN/Inf` — no finiteness check; produces invalid JSON (`NaN` token) | SD | FIXED |
| 3 | Ledger write builds `root / relpath` from a Canvas-controlled filename with no containment → **path traversal** (`../../…`, absolute paths escape) | SH | FIXED |

**Why it recurs:** no shared "validate at the boundary" discipline — each parser
and endpoint trusts the shape/domain of its input. Validation lives ad hoc inside
each function, so a hardening in one place doesn't reach parallel code paths.

## RC-2 — Processing untrusted input has no resource bound (time / memory / size)

The code will read, match, or expand untrusted input of unbounded cost. An
attacker supplies input engineered to exhaust CPU or memory (DoS).

| # | Symptom | Repo | Status |
|---|---|---|---|
| 4 | `redact()` header regex `\s*-?\s*` backtracks ~O(n²) on whitespace runs (2000 newlines = 93s) — **ReDoS** on the logging path | SH | FIXED |
| 5 | `xlsx_text` parses `sharedStrings.xml` with stdlib `ET`, which expands internal entities unbounded — **billion-laughs** memory DoS | SH | FIXED |
| 6 | HTTP fetchers call `r.read()` / `response` with no size cap — a huge body exhausts memory | SH, (FP partially capped) | DOC |
| 7 | ERCOT archive is read fully into memory — **zip-bomb** DoS if the feed is un-pinned | SD | DOC |

**Why it recurs:** "parse it" and "read it" are written for the happy path; the
cost of hostile input (catastrophic regex, entity expansion, giant bodies) is not
part of the mental model.

## RC-3 — Untrusted code / content is executed or deserialized with full ambient authority (no containment)

The strongest root cause. The program runs or deserializes something it does not
control, inside a process that holds real authority (secrets, network, filesystem).

| # | Symptom | Repo | Status |
|---|---|---|---|
| 8 | Finance track runs model-written `pipeline.py` **in-process** (`exec_module` + `run()`) — no subprocess, no timeout, no memory bound, no cwd confinement | RRA | DOC |
| 9 | CS/builder subprocesses inherit the **full environment** and have **open network egress**; memory rlimit is skipped on macOS; the `BLACKLIST` is a passive log, not a control | RRA | Partial (env key scrub FIXED) |
| 10 | `pickle.load` of an artifact (CWE-502) — code execution if the artifact ever originates off-machine | RRA | DOC |

**Why it recurs:** the sandbox was built as a *convenience* (a work dir + a
timeout), not as a *trust boundary*. Isolation (process, egress, env, rlimits)
was never the design center, so most execution paths bypass it entirely.

## RC-4 — Outbound requests are not egress-validated or connection-pinned (SSRF family)

A server-side fetch can be aimed at an internal address, or the validated
identity isn't the one actually connected to.

| # | Symptom | Repo | Status |
|---|---|---|---|
| 11 | `/api/job/url` validates the host, then `httpx` re-resolves independently to connect — **DNS-rebinding TOCTOU** reaches internal services | FP | DOC |
| 12 | `urllib.urlopen` follows redirects with no per-hop re-check — a configured page 302-ing to `169.254.169.254`/`127.0.0.1` is fetched | SH | DOC |
| 13 | `fetch_html_as_text(url)` fetches an operator-supplied URL with no host/scheme guard (low — operator-trust boundary) | RRA | DOC |

**Why it recurs:** the check and the use are separate operations over a mutable
resource (DNS, redirects); the validated result is never **pinned** to the actual
connection, and there is no egress allow-list as a backstop.

## RC-5 — Secrets and environment config are handled in-band or with weak exposure

Sensitive values live in source, or are exposed more widely than needed.

| # | Symptom | Repo | Status |
|---|---|---|---|
| 14 | Django `SECRET_KEY` hardcoded and `DEBUG = True` in `settings.py` | SD | FIXED |
| 15 | The Anthropic API key is inherited by every subprocess that runs generated code — the highest-value exfil target | RRA | FIXED (scrubbed) |
| 16 | Auth-session files (cookies/JWT) written at default umask → mode `0644`, world-readable | SH | DOC |

**Why it recurs:** no single convention for "where secrets come from" (env
injection) and "who may see them" (least exposure: restrictive perms, scrub from
child processes).

## RC-6 — No access control at the service boundary

Endpoints are exposed without authentication, authorization, throttling, or
origin scoping.

| # | Symptom | Repo | Status |
|---|---|---|---|
| 17 | `/forecast` + `/forecast/range` and the Django proxy have **no auth, no rate-limiting**, and **wildcard CORS** (`CORS(app)`) | SD | DOC |

**Why it recurs:** the service was built as an internal, read-only, stateless
tool, so the access-control layer was never added; acceptable today, a latent gap
if it is ever exposed.

## RC-7 — No supply-chain / dependency hygiene

Dependencies drift without an audit or pin-and-update process; CI actions float.

| # | Symptom | Repo | Status |
|---|---|---|---|
| 18 | CVEs in `pypdf`, `urllib3`, `setuptools` (RRA); `flask-cors`, `urllib3`, `requests`, `gunicorn`, … (SD) | RRA, SD | DOC |
| 19 | Declared-but-unused deps increase attack surface (`pypdf` declared, intake uses `pymupdf`) | RRA | DOC |
| 20 | GitHub Actions pinned to mutable tags (`@v4`) instead of commit SHAs | FP (frontend) | DOC |

**Why it recurs:** no `pip-audit`/SCA step in CI and no cadence for bumping or
removing dependencies; nothing fails when a dep goes stale or a CVE lands.

## RC-8 — LLM data and instructions share one channel, and the data-reading model also holds privileged actions (LLM01)

Untrusted content reaches the model together with the app's instructions, and the
model that reads it can also take consequential actions.

| # | Symptom | Repo | Status |
|---|---|---|---|
| 21 | A paper's / scraped page's text can carry instructions that steer extraction, a verdict, or an autofill answer | RRA, FP | Partially mitigated (document-block separation + data-boundary directive) |
| 22 | Excessive agency: the model that reads an untrusted paper is also the one that writes and runs code (ties to RC-3) | RRA | DOC |
| 23 | FP sink wrapper (`harden_untrusted`) exists and is tested but is **not yet wired** into the live `job_parser` / `jev_binder` prompts | FP | DOC |

**Why it recurs:** prompts are assembled as plain text with untrusted content
inlined, and there is no privilege split between "the model that reads data" and
"the model that acts."

## RC-9 — Insecure defaults / missing hardening flags (defense-in-depth, low)

Flagged primitives and deploy settings left at their unsafe or scanner-tripping
default.

| # | Symptom | Repo | Status |
|---|---|---|---|
| 24 | SHA-1 used for non-crypto cache/dedup keys (trips scanners; use SHA-256 or `usedforsecurity=False`) | FP, SH, SD | DOC |
| 25 | `torch.load(weights_only=False)` on a self-produced artifact | SD | DOC |
| 26 | k8s manifests without `securityContext` (`allowPrivilegeEscalation`); Flask dev server binds `0.0.0.0` | SD | DOC |

**Why it recurs:** defaults were accepted without a hardening checklist; each is
low-risk alone but collectively they weaken defense-in-depth.

---

## Per-repo index (so nothing is lost)

- **RRA:** RC-3 (#8,#9,#10) · RC-4 (#13) · RC-5 (#15) · RC-7 (#18,#19) · RC-8 (#21,#22)
- **FP:** RC-1 (#1) · RC-2 (#6) · RC-4 (#11) · RC-7 (#20) · RC-8 (#21,#23) · RC-9 (#24)
- **SD:** RC-1 (#2) · RC-2 (#7) · RC-5 (#14) · RC-6 (#17) · RC-7 (#18) · RC-9 (#24,#25,#26)
- **SH:** RC-1 (#3) · RC-2 (#4,#5,#6) · RC-4 (#12) · RC-5 (#16) · RC-9 (#24)

## Cross-cutting observation

Three root causes explain most of the symptoms:

1. **RC-1 + RC-2 (untrusted input, unchecked for shape and for cost)** is the
   single largest family — every parser/endpoint that reads external data.
2. **RC-3 (running untrusted code without a sandbox)** is the highest *severity*,
   concentrated in RRA but the archetype for how to treat any untrusted execution.
3. **RC-4 (SSRF / TOCTOU)** recurs wherever the code makes an outbound fetch.

A solution that establishes shared primitives — a boundary-validation helper, a
resource-bounded parse wrapper, a real execution sandbox, and a pinned/egress-
controlled HTTP client — would retire most of the list at once. That is the remit
of the solution-design phase.

## Next phase — solution design (per root cause)

For each RC above, design a complete solution: the durable fix (not the symptom
patch), where the shared primitive lives, how it is adopted across repos, and how
it is tested. Fill a `## Solution` block under each RC here as the design lands.
