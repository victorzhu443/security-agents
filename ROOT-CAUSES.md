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

---

# Solution designs (per root cause)

Design principle throughout: fix the **class**, not the instance. Each solution
names (a) the durable fix, (b) the shared primitive and where it lives, (c) how
each repo adopts it, and (d) the test that proves it and keeps it fixed. Shared
primitives live in this repo under `secprim/` so every project imports one
tested implementation instead of re-deriving it.

## Solution RC-1 — Validate at the boundary, once, through shared validators

**Durable fix.** Every function that first touches external data validates
*shape, type, domain and path* before any other logic, by calling shared
validators that raise one declared exception type. Web layers map that one type
to a 400; batch jobs map it to a reported failure. Validation stops being ad hoc
per-function and becomes a visible contract at the edge.

**Primitive — `secprim/boundary.py`:**
- `class MalformedInput(ValueError)` — the single declared failure type.
- `as_dict(v, path)`, `as_list(v, path)`, `as_str(v, path, max_len=None)` — shape
  checks with a dotted path in the message (generalizes firstplay's
  `greenhouse._as_dict/_as_list`).
- `finite_float(v, path, lo=None, hi=None)` — rejects NaN/±Inf/strings/out-of-range.
- `contained_path(root, relpath)` — rejects NUL, absolute paths, and anything
  that resolves outside `root`; returns the safe joined path (generalizes
  study-hub's `_checked_dest`).

**Adoption.** FP: `parse_ashby_dom`/`parse_ashby_posting` import from `secprim`
(delete the local copies). SD: `/forecast` uses `finite_float` for every numeric
param. SH: `Ledger.put`/`observe_file` call `contained_path`. **The sibling
problem** (a fix landing in one parser but not its twins) is solved by the fuzz
harness, not by memory: every parser of untrusted input is registered in that
repo's `tests/security/test_fuzz_parsers.py`, so a sibling that lacks validation
fails its safe-degradation property. Adding a parser without a fuzz entry is the
review-time check.

**Tests.** Unit tests per validator (hostile shapes, NaN/Inf, `../`, absolute,
NUL, IPv6-style weirdness). Per repo: the existing Hypothesis
`assert_robust(parser, allowed=(MalformedInput,…))` is the regression net.

## Solution RC-2 — Bound the cost of processing untrusted input

**Durable fix.** No untrusted byte is read, matched or expanded without a
ceiling on size, time and expansion. Three concrete ceilings cover every symptom.

**Primitive — `secprim/bounded.py`:**
- `bounded_read(stream_or_response, max_bytes)` — streams and raises
  `TooLarge(MalformedInput)` past the cap; never materializes an unbounded body.
  (Fixes SH's uncapped `r.read()`; FP already caps, migrate to this.)
- `safe_xml_fromstring(data, max_bytes)` — rejects any `<!DOCTYPE`/`<!ENTITY`
  (no DTD processing at all), then parses with stdlib ET; optional `defusedxml`
  backend if installed. Real spreadsheets/feeds carry no DTD, so this is lossless.
- `safe_zip_members(zf, max_member_bytes, max_total_bytes, max_ratio=100)` —
  iterates members checking the *declared* uncompressed size and the
  compression ratio before reading; refuses zip-bombs and over-size archives.
- **Regex:** stdlib `re` has no timeout, so the fix is structural: (1) a rule —
  regexes applied to untrusted text use bounded quantifiers and character
  classes that cannot span the delimiter they anchor on (the `\s`→`[ \t]`
  lesson); (2) a test helper `redos_probe(pattern, probes=…)` that times each
  pattern against adversarial runs (`"\n"*N`, `"("*N`, `"a"*N`) under a deadline.
  Optionally the third-party `regex` module with `timeout=` where a pattern is
  genuinely complex.

**Adoption.** SH: `extract_text.xlsx_text` → `safe_xml_fromstring`; fetchers →
`bounded_read`; `redact._PATTERNS` → `redos_probe` test. SD:
`parse_archive`/`parse_dam_archive` → `safe_zip_members` before `zf.read`.
FP: `fetch_html` → `bounded_read`.

**Tests.** Each helper has a "hostile input is refused under the cap" test and a
"benign input passes unchanged" test. The `redos_probe` runs in each repo's
security suite over every regex that sees untrusted text, asserting sub-100 ms
on 10 k-char adversarial runs. Hypothesis `deadline` is already set in the fuzz
harness, so a new cost blow-up fails CI.

## Solution RC-3 — One real execution sandbox, used by every path

**Durable fix.** Model-generated code runs **only** through `Sandbox.run`, and
`Sandbox` is a trust boundary, not a convenience: a separate process, an
allow-listed environment, a private working directory, resource limits, and
**no network egress by default**. The in-process finance path is eliminated.

**Design (RRA `replicator/build/sandbox.py`):**

1. **Kill the in-process path.** `orchestrator._load_pipeline()` stops importing
   `pipeline.py`. Instead the orchestrator writes `cfg`/`seed` to
   `work/input.json` and runs, under the sandbox,
   `python -c "import json,pipeline; json.dump(pipeline.run(**json.load(open('input.json'))), open('out.json','w'))"`
   then loads `work/out.json` (or a parquet for frames). The result contract is a
   file, so the model's code never shares the orchestrator's process, env, open
   handles or `sys.path`.
2. **Allow-listed env, not inherit-minus-denylist.** `secprim/child_env.py`
   `child_env(allow={"PATH","LANG","LC_ALL"}, set={"HOME": tmp, "PYTHONPATH": work, "PYTHONDONTWRITEBYTECODE": "1"})`
   builds the environment from scratch. Nothing from the parent leaks unless
   named. (Upgrades today's `scrub_secrets` denylist.)
3. **Private cwd + temp HOME**, created per run under a tmp root and deleted
   after; the model's `write_file` is already confined to it — now `run_python`
   is too (path-check the `path` arg against the work dir, the one gap found).
4. **Resource limits.** On Linux: `RLIMIT_AS`, `RLIMIT_CPU`, `RLIMIT_NPROC`,
   `RLIMIT_FSIZE` via `preexec_fn`. On macOS `RLIMIT_AS` is unreliable, so keep
   the wall-clock timeout and add an **RSS watchdog** (poll the child's memory,
   kill over the cap) — enforced, not platform-skipped.
5. **Network egress off by default.** The portable, durable boundary is a
   **container**: `docker run --rm --network none --read-only --cap-drop ALL
   --security-opt no-new-privileges --memory 2g --pids-limit 64 --tmpfs /tmp
   -v <work>:/work:rw -w /work <image>`. Data adapters that must fetch run
   *outside* the sandbox (they are trusted code) and hand files in. Where a
   container is unavailable, a **degraded local mode** applies 2–4 above and
   prints an explicit "network is NOT restricted" banner into the run log; it is
   never silent.
6. **Retire the fiction.** The `BLACKLIST` regex either becomes a real
   pre-execution gate (refuse, don't log) or is renamed to what it is — a
   provenance monitor — so nobody mistakes it for containment.
7. **No pickle.** Agent artifacts use `np.save`/`.npz`, parquet, JSON or
   `safetensors`; if a legacy pickle must be read, a restricted `Unpickler` with
   an allow-list of classes.

**Adoption.** RRA only (the archetype); the pattern is reusable for any project
that ever executes untrusted code.

**Tests — defensive containment regressions** (`tests/security/test_sandbox_containment.py`):
a tiny generated program per property, each must fail or be killed: read an env
secret (`<absent>`), write outside the work dir (refused), open a socket
(refused with `--network none`), allocate past the memory cap (killed), fork
loop (pids-limit). Plus: the finance path has no `exec_module` (a grep/AST test),
and every exec site goes through `Sandbox.run` (an import-graph test).

## Solution RC-4 — A pinned, egress-validated fetch primitive

**Durable fix.** Validation and connection operate on the **same** resolved
address: resolve once, validate every address, then connect to the validated IP
(sending the real `Host` and SNI), and repeat per redirect hop. An optional host
allow-list is the backstop for fetchers that only ever talk to known services.

**Primitive — `secprim/safe_fetch.py`:**
```
safe_fetch(url, *, allow_hosts=None, max_bytes=5_000_000, max_redirects=5,
           timeout=10, resolver=socket.getaddrinfo) -> Response
```
- scheme must be `http`/`https` (re-checked on every hop; no downgrade to
  `file:`/`gopher:`/etc.);
- resolve the hostname once via `resolver` (injectable for tests); every address
  must be global and not multicast, else `UnsafeDestination`;
- **pin:** connect to `scheme://<validated-ip><path>` with
  `headers={"Host": hostname}` and `extensions={"sni_hostname": hostname}` so
  TLS SNI and certificate verification still use the real name while the TCP
  connection goes to the address that was validated — this closes the TOCTOU;
- redirects are not auto-followed: each `Location` is resolved against the
  current URL and run through the same pin, up to `max_redirects`;
- body read through `bounded_read(max_bytes)`;
- `allow_hosts` (exact or suffix match) short-circuits everything else for
  fixed-destination fetchers.

**Adoption.** FP: `fetch_html` → `safe_fetch` (closes the DNS-rebinding
residual; keeps the existing per-hop logic but pinned). SH: `urllib.urlopen` in
the web/Canvas fetchers → `safe_fetch(allow_hosts=[canvas, edstem, piazza,
gradescope])` — the allow-list makes redirect-to-internal impossible and adds
the size cap. RRA: `fetch_html_as_text` → `safe_fetch` (and `fetch_arxiv` with
`allow_hosts=["arxiv.org"]`). SD's ERCOT client → `allow_hosts=["ercot.com"]`.

**Tests.** With a fake resolver: public→private **rebinding** (first call
global, second call `127.0.0.1`) must be refused — the pin means the second
lookup never happens; redirect to `169.254.169.254` refused at hop 2; `file://`
in a `Location` refused; IPv4-mapped IPv6 refused; body over cap refused;
allow-list rejects an off-list host. Transport is `httpx.MockTransport`, so the
suite runs offline.

## Solution RC-5 — Secrets come from one place and go to as few places as possible

**Durable fix.** Three conventions, each enforced by code: secrets are read
**only** from the environment (or a secret store) through a loader that fails
fast in production when a required secret is absent; child processes receive an
**allow-listed** environment (RC-3's `child_env`); files that hold secrets are
written with mode `0600`.

**Primitive — `secprim/secrets.py`:**
- `require_secret(name, *, dev_default=None)` — returns the env value; if
  absent, returns `dev_default` only when `APP_ENV in {"dev","test"}`, otherwise
  raises `MissingSecret` at import/startup (so a prod deploy with a missing key
  refuses to boot instead of running on a dev default).
- `write_private(path, data)` — opens with `os.open(path, O_WRONLY|O_CREAT|O_TRUNC, 0o600)`
  under a `0o077` umask, atomically via temp+rename. (Generalizes firstplay's
  `private_json.py`.)
- `child_env` (shared with RC-3).

**Adoption.** SD: `SECRET_KEY = require_secret("DJANGO_SECRET_KEY", dev_default=…)`,
`DEBUG` derived from `APP_ENV`, so the dev default can never ship. RRA:
`child_env` in `Sandbox`/`run_reproduce`. SH: `auth_canvas.py`/`auth_piazza.py`
write session files via `write_private` (these are Victor's scripts; the change
is the one-line write call).

**Tests.** `APP_ENV=prod` + missing secret → `MissingSecret`; dev → default;
`write_private` → `stat().st_mode & 0o777 == 0o600`; child env lacks every
parent key not on the allow-list (RRA has the empirical version already).

## Solution RC-6 — An access-control layer in front of the forecast API

**Durable fix.** The forecast service gets authentication, rate limiting and
scoped CORS, placed so the browser never talks to Flask directly.

**Design (SD):**
1. **Authn:** a bearer/API key checked in a Flask `before_request` for
   `/forecast*` (`require_secret("FORECAST_API_KEY")`); `/health` stays open.
   Durable home is the **ingress** (k8s ingress auth annotation / an auth proxy)
   so the app-level check is defense-in-depth, not the only gate.
2. **The Django dashboard is the only client:** it holds the API key server-side
   (`require_secret`) and proxies, forwarding only the whitelisted params it
   already does. Browsers call Django, never Flask.
3. **CORS:** `CORS(app, origins=[DASHBOARD_ORIGIN])` — or remove CORS entirely
   once only Django calls it (no browser origin needs it).
4. **Rate limit:** `Flask-Limiter` keyed by API key (fallback IP), e.g. 60/min on
   `/forecast`, with the ingress rate limit as the outer layer.

**Tests.** No key → 401; wrong key → 401; valid → 200; burst past the limit →
429; preflight from a foreign origin → no `Access-Control-Allow-Origin`.
(Extends the existing `test_forecast_input_validation.py` Flask test client.)

## Solution RC-7 — Supply-chain hygiene as a CI gate

**Durable fix.** Dependency risk is measured on every push and fails the build
above a threshold; updates arrive as reviewable PRs; actions are immutable.

**Design:**
1. **SCA in CI:** add an `sca` job to each repo's workflow (template in
   `security-agents/.github/workflows/ci.yml`): `pip-audit -r requirements.txt
   --strict` (or against `uv.lock`), `npm audit --audit-level=high` for the FP
   frontend/extension. Fail on high/critical; allow a documented ignore file
   for accepted risks with an expiry date.
2. **Pin and lock:** every Python project has a lockfile (`uv.lock` /
   `requirements.txt` with hashes); unused deps removed (`pypdf` in RRA — intake
   uses `pymupdf`).
3. **Immutable actions:** pin every `uses:` to a 40-char commit SHA, with
   **Dependabot** (`.github/dependabot.yml`, `github-actions` + `pip`/`npm`
   ecosystems, weekly) opening the bump PRs so pins don't rot.
4. **Immediate bumps** from the audit: `pypdf ≥ 6.21.4`, `urllib3 ≥ 2.8.0`
   (RRA); `flask-cors` 4→6, `flask` 2→3, `requests`, `gunicorn` (SD) — the SD
   majors land behind the existing test suite in their own PR.

**Tests.** The CI gate *is* the test: a seeded known-vulnerable pin in a branch
must fail `sca`. A one-time `deptry`/`pip-check` pass removes unused deps.

## Solution RC-8 — Structural data/instruction separation and a reader/actor privilege split

**Durable fix.** Two invariants: (1) untrusted content enters a prompt **only**
as a distinct, fenced data block through a single prompt-assembly chokepoint,
never inlined into instruction text; (2) the model that holds tools or takes
side effects **never receives raw untrusted text** — only the schema-validated
output of a tool-less *reader* model. (Willison's dual-LLM pattern.)

**Primitive — `promptinject/assemble.py`** (extends the existing harness):
- `build_prompt(instructions: str, *, data: list[Untrusted]) -> messages` — the
  only way untrusted content gets into a prompt. Each `Untrusted(text, label)`
  is `harden()`-ed (neutralize + spotlight fence) and the system prompt gets the
  standard data-boundary directive appended automatically. Because there is one
  chokepoint, the LLM01 corpus can be bound to the *real* assembly path in CI.
- `scrub_output(text)` applied by the same module before anything is surfaced.
- A type-level guard: `Untrusted` is a distinct type, so passing a bare `str`
  where data is expected is a lint/type error.

**Adoption.**
- **FP:** `job_parser.parse_jd_text` and `jev_binder`'s prompts assemble through
  `build_prompt(..., data=[Untrusted(job_text,"job posting")])` — this closes
  pending item #23 (the wrapper exists; this is the wiring, in one place).
- **RRA (privilege split):** `extract_spec`/`referee_spec` are the **reader** —
  they see the paper (document block + directive) and have **no tools**. The
  builder loop is the **actor** — its input is the validated `Spec` (pydantic)
  plus the KB, never the PDF or raw paper text; if it needs a quote, the reader
  supplies it as an `Untrusted` block. Combined with RC-3, a paper can at most
  bias the *Spec*, which the existing apply-and-verify loop checks — it can no
  longer directly author a tool call.
- **SD:** when a RAG `/query` returns, retrieved chunks are `Untrusted` blocks
  through `build_prompt`; nothing else is allowed to call the model.

**Tests.** The injection harness runs against `build_prompt` output (the real
path, not a stand-in) — corpus must resist 8/8. A test that the actor's input
type is `Spec`, not `str`/PDF (import-graph + signature check). The existing
directive-presence test stays.

## Solution RC-9 — A hardening checklist, enforced by the Semgrep ruleset

**Durable fix.** Each default is fixed once, and a rule in
`security-agents/semgrep/rules.yml` makes the regression a CI failure.

**Design — new rules + the one-time fixes:**
- `weak-hash-non-crypto`: `hashlib.sha1(`/`md5(` without
  `usedforsecurity=False` → fix: SHA-256 for new keys, `usedforsecurity=False`
  where the digest must stay stable (FP ×4, SH ×1, SD).
- `torch-load-unsafe`: `torch.load(` without `weights_only=True` → fix in SD.
- `flask-dev-bind-all`: `app.run(host="0.0.0.0")` outside a container → prod
  uses gunicorn behind the ingress (SD).
- **k8s:** add `securityContext: {runAsNonRoot: true, allowPrivilegeEscalation:
  false, readOnlyRootFilesystem: true, capabilities: {drop: [ALL]}}` to the SD
  deployments; Semgrep's `p/kubernetes` pack enforces it.

**Tests.** The ruleset's own fixture tests (a positive and a negative snippet per
rule) in `security-agents/tests/test_rules.py`; CI `sast` job runs the pack on
every repo.

---

## Adoption order (one PR per repo per step, as before)

1. **Toolkit first** (`security-agents`): ship `secprim/` (boundary, bounded,
   child_env, secrets, safe_fetch), `promptinject/assemble.py`, the new Semgrep
   rules, CI `sca` template — all with tests. Everything below imports these.
2. **RRA:** RC-3 sandbox redesign (biggest severity cut) + RC-8 reader/actor
   split + RC-7 bumps.
3. **FP:** RC-4 `safe_fetch` (closes DNS-rebinding) + RC-8 wiring (#23) +
   RC-1 shared validators + RC-9 hashes/actions.
4. **SH:** RC-2 (`safe_xml`, `bounded_read`, `redos_probe`) + RC-4 allow-listed
   fetch + RC-5 `write_private` + RC-1 `contained_path`.
5. **SD:** RC-6 access control + RC-5 `require_secret` + RC-2 `safe_zip` +
   RC-9 (torch, k8s, hashes) + RC-7 dependency majors.

---

## Status update — 2026-11-26

All nine root causes have landed fixes in the per-repo `security/root-causes`
PRs (see DESIGN.md §7 for PR numbers and verification). Status by RC:

| RC | Status | Where |
|---|---|---|
| RC-1 boundary validation | **FIXED** (shared `secprim.boundary`; parser registry rule per repo; structural fuzz found + closed 4 more wrong-type crashes in FP) | all four repos |
| RC-2 resource bounds | **FIXED** (`bounded_read`/`safe_xml`/`safe_zip_members`; `redos_probe` + `size_sweep` over every untrusted regex/parser; 9 quadratic regexes replaced) | all four repos |
| RC-3 execution sandbox | **FIXED locally**; container backend built but **untested end to end** | RRA |
| RC-4 pinned fetch | **FIXED** (every content/caller-derived fetch through `safe_fetch`; fixed-host adapters allow-listed; one `HEAD` probe residual) | all four repos |
| RC-5 secrets | **FIXED** (`require_secret` fails closed after toolkit PR #4; `child_env` allow-list; `write_private` at every session write) | SD, RRA, SH |
| RC-6 access control | **FIXED** (bearer gate, counting limiter, scoped CORS, Django-only client, ingress rate limits) | SD |
| RC-7 supply chain | **FIXED** (SCA + SAST + security tests per repo, SHA-pinned actions, Dependabot, expiring ignore list); dependency **majors** remain as their own PRs | all repos + toolkit |
| RC-8 LLM separation | **FIXED** (every FP sink hardened + directive + output scrub; RRA reader/actor split verified; all three paper prompts carry the directive) | FP, RRA |
| RC-9 hardening defaults | **FIXED** except SD `torch.load` artifact split (documented follow-up) | FP, SH, SD |
