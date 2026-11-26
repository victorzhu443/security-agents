# Security system design — built on the existing codebase

This is the exhaustive, step-by-step design behind the solutions in
`ROOT-CAUSES.md`. It is written as a system design: start from the system as it
exists, decide the cross-cutting architecture, design each root-cause fix as a
component with interfaces and data flow, fit it to the real files, then choose
what to build and list every edit. Threat context is kept categorical (see
`ROOT-CAUSES.md`); this document is about the defensive engineering.

Repos: **RRA** research-replication-agent · **FP** firstplay(-backend) ·
**SD** smart-dispatch · **SH** study-hub · **SA** security-agents (this repo).

---

## 0. Method

1. **Inventory** each repo: components, where external data enters, where
   authority lives (secrets, network, filesystem, model calls, code execution).
2. **Draw the trust boundaries** that inventory implies.
3. **Decide the cross-cutting architecture** once: how shared code is
   distributed, how failures surface, how CI enforces.
4. **Per root cause:** current state (real files) → target component design →
   fit to existing code (reuse / replace / remove) → ordered edit plan → risks.
5. **Select features**: now / next / defer, with the reason.
6. **Edit manifest**: the complete list of files to add, change, remove.
7. **Verification plan**: how each layer is proven and kept proven.

---

## 1. The system as it is

### 1.1 Components and where external data enters

| Repo | Components | External data enters at | Authority held |
|---|---|---|---|
| **RRA** | `cli.py` → `orchestrator.py` (stages: intake, spec, build, run, verify, report) · `spec/extract.py` (model reads paper) · `build/builder.py` (model writes code) · `build/sandbox.py` (runs it) · `templates/cs_eval.py` (CS run) · `data/adapters/*` (fetch datasets) | paper PDF (`spec/intake.py` → `LLM.paper_block`), HF/dataset payloads, operator CLI URL | **executes model-generated code**; Anthropic key in env; open network; user's filesystem |
| **FP** | FastAPI `app/main.py` + routers (`job`, `resume`, `autofill`, `analysis`, `pipeline`) · `app/chains/*` (LangChain prompts) · `app/autofill/*` (parsers, binder) · extension + frontend | caller-supplied URL (`/api/job/url`), uploaded resume, **scraped page / DOM extract posted by the extension**, form fields | server-side HTTP fetch; model calls; DB |
| **SD** | Flask `backend/phase_5_1_forecast_api.py` (`/forecast`, `/forecast/range`, `/health`) · Django `frontend/smart_ui` (dashboard proxies to Flask) · `data_ingestion/*` (ERCOT archives) · model artifacts | query params on `/forecast*`; ERCOT archive bytes (fixed host) | DB; model artifact load; served to a browser |
| **SH** | `scripts/gather.py` → `sync_*.py` → `adapters.py` → `ledger.py` (writes to `courses/<slug>/`) · `extract_text.py` · `redact.py` · auth scripts (sessions) | **fetched Canvas/Ed/Piazza/web content and attachment filenames** | writes files under the hub; holds session cookies/JWTs; logs |
| **SA** | `semgrep/`, `promptinject/`, `fuzzing/`, `secprim/` (new), CI | — (library) | — |

### 1.2 Trust boundaries (what the design must enforce)

```
            untrusted                         trusted (app code)                  privileged
  ┌──────────────────────┐   boundary A   ┌──────────────────────┐  boundary B  ┌──────────────────┐
  │ paper / page / DOM / │ ─ validate ──▶ │ parsers, prompt      │ ─ confine ─▶ │ model w/ tools,  │
  │ archive / query args │   & bound      │ assembly, handlers   │   & pin      │ exec, fetch, FS, │
  └──────────────────────┘                └──────────────────────┘              │ secrets          │
                                                                                └──────────────────┘
```

- **Boundary A** (RC-1, RC-2): every parser/handler validates shape and bounds
  cost *before* using external data.
- **Boundary B** (RC-3, RC-4, RC-5, RC-8): privileged operations — running code,
  fetching, holding secrets, model actions — are reached only through confined,
  pinned, least-privilege primitives.
- **Service edge** (RC-6) and **supply chain** (RC-7, RC-9) wrap the whole.

### 1.3 What already exists and is reused (not re-invented)

| Existing code | Status | Role in the design |
|---|---|---|
| FP `app/autofill/greenhouse.py` `_as_dict/_as_list/MalformedPayload` | correct | the model for `secprim.boundary`; FP keeps `MalformedPayload` as an alias |
| SH `ledger.Ledger._checked_dest` | correct (fixed this effort) | delegates to `secprim.contained_path` |
| FP `app/routers/job.py` `assert_public_url` + manual redirect loop | strong, one TOCTOU gap | replaced by `secprim.safe_fetch` (same semantics + pinning) |
| RRA `build/sandbox.py` `Sandbox.run/python/python_file`, `scrub_secrets` | partial | **kept as the interface**; internals hardened; becomes the only exec path |
| FP per-router `except MalformedPayload → HTTPException(400)` (`autofill.py:261`) | correct, per-router | generalized to one global handler |
| SA `promptinject.defense.harden/scrub_output`, `promptinject.harness` | done | `assemble.build_prompt` is the chokepoint that calls them |
| per-repo `tests/security/` + Hypothesis fuzz suites | done | the regression net that enforces Boundary A |

---

## 2. Cross-cutting architecture decisions

### 2.1 How shared code reaches each repo

**Options.** (A) git dependency pinned to a tag; (B) vendor `secprim/` into each
repo; (C) private package index. **Decision: (A)** —
`security-agents @ git+https://github.com/victorzhu443/security-agents@v0.1.0`
in each repo's `requirements.txt` / `pyproject.toml`, with the editable sibling
install (`pip install -e ../security-agents`) documented for local dev. Pinning
to a tag makes every repo reproducible; the private repo is reachable with the
same git credentials the user already has. (B) drifts; (C) is overhead with no
benefit at this scale.

**Safety valve kept:** each repo's `security.py` (`replicator/security.py`,
`app/security.py`, `smart_dispatch_security.py`) already imports the toolkit
with a self-contained fallback. The apps never hard-fail if the toolkit is absent.

### 2.2 One failure type, one HTTP mapping

All boundary failures are `secprim.MalformedInput` (a `ValueError`). Each
framework maps it once:

| Framework | Where | Mapping |
|---|---|---|
| FastAPI (FP) | `app/main.py` `@app.exception_handler(MalformedInput)` | 400 `{"detail": str(e)}` |
| Flask (SD) | `backend/phase_5_1_forecast_api.py` `@app.errorhandler(MalformedInput)` | 400 JSON `{"error": ..}` |
| Django (SD) | `frontend/smart_ui/dashboard/views.py` try/except around proxy call | 400 |
| Batch (SH, RRA) | existing try/except at the call site (`sync_canvas`, orchestrator stages) | reported failure, job continues |

Per-router `except MalformedPayload` blocks in FP stay (they add context) but
become redundant rather than load-bearing.

### 2.3 Enforcement lives in CI

Three jobs per repo, templated from SA `.github/workflows/ci.yml`:
`security-tests` (`pytest tests/security/`), `sast` (Semgrep custom + packs),
`sca` (`pip-audit`/`npm audit`). A design is "adopted" only when all three run
on the repo.

### 2.4 Library layout (SA)

```
security-agents/
  secprim/            RC-1,2,3,4,5 primitives (boundary, bounded, child_env, secrets, safe_fetch)
  promptinject/       corpus, harness, defense, assemble  (RC-8)
  fuzzing/            fuzz_lib (regression net for Boundary A)
  semgrep/rules.yml   RC-9 rules + LLM01 sink rule
  .github/workflows/  ci.yml template (security-tests, sast, sca)
  tests/              primitive tests, rule fixture tests
```

---

## 3. Per-root-cause designs

Each: **Current** (real code) · **Target** (component, interface, flow) ·
**Fit** (reuse/replace/remove) · **Edit plan** (ordered, with tests) · **Risk**.

### 3.1 RC-1 — Boundary validation

**Current.** FP validates shape in `greenhouse._as_dict/_as_list` (and now
`ashby.parse_ashby_dom`); SD `/forecast` now checks `math.isfinite`; SH
`_checked_dest` checks path containment. Three good local implementations, no
shared one, and no mechanism that makes a *new* parser get validation.

**Target.** `secprim.boundary` = `MalformedInput`, `as_dict`, `as_list`,
`as_str`, `finite_float`, `contained_path`. Interface contract: *pure, raise
`MalformedInput` with a dotted path, return the validated value.* Data flow:
external value → validator → typed value → rest of function. Nothing after the
validator handles raw external shape.

**Fit.** FP: `greenhouse.py` becomes
`from secprim import MalformedInput as MalformedPayload, as_dict as _as_dict, as_list as _as_list`
(zero call-site churn). SD: `/forecast*` → `finite_float(request.args.get(...), "marginal_cost")`,
`hours` → `finite_float(..., lo=1, hi=168)` then `int`. SH: `_checked_dest` body
→ `return contained_path(self.root, relpath)` (keep the method; it re-raises as
`MalformedInput`, a `ValueError`, so existing `except ValueError` still works).

**The sibling mechanism.** New parsers get validated because each repo's
`tests/security/test_fuzz_parsers.py` is the **registry** of untrusted-input
parsers: a parser not listed there is a review failure; a listed parser without
validation fails `assert_robust`. Document this rule in each `SECURITY.md`.

**Edit plan.** (1) SA: `secprim/boundary.py` + `tests/test_boundary.py` ✔ built.
(2) FP: alias import in `greenhouse.py`; global `MalformedInput` handler in
`main.py`. (3) SD: `finite_float` in both handlers; Flask errorhandler.
(4) SH: delegate `_checked_dest`. (5) Each: add the "parser registry" note.

**Risk.** Low. Behavior-preserving for valid input; tests already pin the
hostile cases.

### 3.2 RC-2 — Resource bounds

**Current.** SH `xlsx_text` now rejects DTD text; SH fetchers read unbounded;
SD `parse_archive` reads a whole member into memory; FP caps body size inline;
`redact` regex fixed by hand. No shared ceilings, no regex cost test.

**Target.** `secprim.bounded` = `bounded_read(src, max_bytes)` (streams any
response/file/iterable, counts actual bytes, raises `TooLarge`),
`safe_xml_fromstring` (DTD-free parse, `defusedxml` backend if present),
`safe_zip_members(zf, max_member_bytes, max_total_bytes, max_ratio)` (budget +
name check *before* reading), `redos_probe(pattern)` (test-time cost assertion).
Flow: the ceiling is applied at the first byte, so cost is bounded before
content is interpreted.

**Fit.** SH: `extract_text.xlsx_text` → `safe_xml_fromstring`; web fetch
`r.read()` → `bounded_read(r, MAX)`; `tests/security` gains
`redos_probe` over `redact._PATTERNS`. SD: wrap `zf.infolist()` iteration in
`safe_zip_members` in `parse_archive`/`parse_dam_archive`. FP: `fetch_html`'s
inline cap → `bounded_read` (via `safe_fetch`, §3.4).

**Edit plan.** (1) SA: `secprim/bounded.py` + tests ✔ built. (2) SH three
sites + probe test. (3) SD two parsers (+ a test with an over-budget synthetic
zip). (4) FP via §3.4.

**Risk.** Low; caps are generous for legitimate data and tested with benign
inputs.

### 3.3 RC-3 — Execution sandbox (RRA)

**Current (exact).** `Sandbox.run(argv, timeout_s, env, tag)` →
`subprocess.run(cwd=workdir, env=scrub_secrets({**os.environ, **env, PYTHONHASHSEED}), preexec_fn=_limits if not darwin)`.
`_limits` sets only `RLIMIT_AS`. `BLACKLIST` only appends to `blacklist_hits`.
`orchestrator._load_pipeline()` imports `work/pipeline.py` **in-process**
(`spec_from_file_location` + `sys.path.insert` + `exec_module`) and is called
from `run_fn_for` (finance `mod.run`), `smoke` (`mod.run(cfg,0)` + attribute
checks), and `orchestrator.py:402` (`mod.raw_data()`). `cs_eval.run_reproduce`
uses its own `Popen(["bash","reproduce.sh"], env=env)` with a kill watchdog.
`builder.py:85` constructs `Sandbox(workdir)` for tool calls.

**Target design — `Sandbox` becomes the single trust boundary.**

*Interface (kept, extended):*
```
Sandbox(workdir, *, mem_gb=8, timeout_s=300, network: bool = False,
        backend: "auto"|"container"|"local" = "auto")
  .run(argv, timeout_s=None, env=None, tag="") -> ExecResult
  .python(script, ...) / .python_file(rel, args, ...)
  .call(module="pipeline", fn="run", kwargs: dict) -> Any   # NEW: file-based RPC
```

*Component 1 — backend selection.* `auto` picks `container` when Docker is
available, else `local` and writes a one-line banner into the run log:
"sandbox backend=local: network is NOT restricted". Never silent.

*Component 2 — `container` backend.* One `docker run` per call:
`--rm --network none --read-only --cap-drop ALL --security-opt no-new-privileges
--memory <mem> --pids-limit 64 --tmpfs /tmp -v <workdir>:/work:rw -w /work
--env-file <allow-listed env> <image>`. The image is the project's pinned
Python with its locked deps (built once from `uv.lock`). Data adapters run
**outside** (trusted code) and place files in `workdir` first.

*Component 3 — `local` backend (hardened).* `env = secprim.child_env(allow=DEFAULT_ALLOW, set={"PYTHONPATH": workdir, "PYTHONHASHSEED": "0"}, home=tmp_home)`
(allow-list replaces `scrub_secrets`' denylist; `scrub_secrets` stays as a
second check via `assert_no_secrets`). `preexec_fn` sets `RLIMIT_CPU`,
`RLIMIT_NPROC`, `RLIMIT_FSIZE`, and `RLIMIT_AS` where supported. On macOS an
**RSS watchdog thread** polls the child (`psutil`) and kills it over `mem_gb`.
Wall-clock timeout unchanged.

*Component 4 — `.call()` file-based RPC (removes in-process exec).* Writes
`workdir/_call.json` = `{module, fn, kwargs}`, runs under the sandbox a fixed
runner script `_runner.py` (shipped by RRA, copied into `workdir`) that imports
`module`, calls `fn(**kwargs)`, and serializes the result to `workdir/_result.json`
(JSON; `pandas.DataFrame` → parquet file + path in JSON). The orchestrator loads
the result. Only JSON/parquet crosses the boundary — never a live module object.

*Component 5 — one exec path.* `cs_eval.run_reproduce` keeps its watchdog
semantics but obtains `env` from `child_env` and, in container mode, runs
through `Sandbox.run(["bash","reproduce.sh"])`. `run_python`'s `path` argument
is checked with `contained_path(workdir, path)` (the one gap found).

*Component 6 — honesty about the monitor.* `BLACKLIST` is renamed
`PROVENANCE_MONITOR` and documented as the author-code-isolation signal it is.

*Component 7 — no pickle.* `papers/.../assemble.py` artifacts move to
`np.savez`/parquet; a `_runner.py` helper offers `save_result`/`load_result` so
generated code has an easy safe format.

**Fit.** The `Sandbox` class and `ExecResult` are kept, so `builder.py` is
untouched. `_load_pipeline` is deleted; its three call sites become
`self.sandbox.call("pipeline", "run", {"cfg": cfg, "seed": seed})`,
`self.sandbox.call("pipeline", "raw_data", {})`, and `smoke`'s attribute check
becomes `self.sandbox.call("_runner", "has_fns", {"module": "pipeline", "fns": [...]})`.

**Edit plan (ordered).**
1. SA: `secprim/child_env.py` ✔ built.
2. RRA `build/sandbox.py`: add `backend`, `network`, `.call()`, container
   backend, hardened local backend, RSS watchdog, `PROVENANCE_MONITOR` rename.
   Tests: `tests/security/test_sandbox_env_scrub.py` (exists) +
   `test_sandbox_call.py` (round-trip a `pipeline.run` through `.call`).
3. RRA `build/_runner.py` (new) + `templates/*` instruct generated code to use
   `save_result`.
4. RRA `orchestrator.py`: remove `_load_pipeline`; replace the three call sites.
   Test: `test_no_inprocess_exec.py` — an AST scan asserting no `exec_module`/
   `spec_from_file_location` in `replicator/`.
5. RRA `templates/cs_eval.py`: `env=child_env(...)`; container path.
6. RRA `build/builder.py`: `contained_path` on `run_python.path`.
7. RRA `papers/batch/.../assemble.py`: drop pickle.
8. RRA `Dockerfile.sandbox` + `make sandbox-image`.
9. RRA `SECURITY.md`: document backend selection and the banner.

**Risk / rollout.** Medium: the finance path changes shape (file RPC). Mitigate
with the existing `smoke` stage as the acceptance test and a feature flag
`REPLICATOR_SANDBOX_BACKEND=local|container` for one release. Rollback = flag.

### 3.4 RC-4 — Pinned, egress-validated fetch

**Current (exact).** FP `job.py`: `assert_public_url(url)` resolves via
`socket.getaddrinfo`, rejects non-global/multicast, is called per hop inside a
manual redirect loop in `fetch_html` (`httpx.AsyncClient(follow_redirects=False)`),
with body caps. Gap: `client.get(current)` resolves again. SH: `urllib.urlopen`
on config URLs, auto-follows redirects, uncapped read. RRA `fetch_html_as_text`:
no guard (operator URL).

**Target.** `secprim.safe_fetch(url, *, allow_hosts, max_bytes, max_redirects,
timeout, resolver, transport, headers) -> SafeResponse`. Flow per hop: parse →
scheme check → allow-list check → `resolve_and_validate` (once) → connect to the
**validated IP** with `Host` + `sni_hostname` set to the real name → on redirect,
`urljoin` and repeat → `bounded_read`. `resolver`/`transport` are injectable so
the suite is offline. Sync (`httpx.Client`); FP's async handler calls it via
`run_in_threadpool`, which the router already does for CPU-bound parsing.

**Fit.** FP: `fetch_html` body → `safe_fetch(url, max_bytes=MAX_HTML_BYTES,
max_redirects=MAX_REDIRECTS, timeout=timeout).text`; keep `assert_public_url`
only as the pre-check for a fast 400 message (optional). SH: a tiny
`scripts/http.py` `fetch(url)` → `safe_fetch(url, allow_hosts=HOSTS,
max_bytes=…)` with `HOSTS` built from `config/sources.json` + `canvas.json`;
`adapters`/`sync_*` call it instead of `urlopen`. RRA: `fetch_html_as_text` →
`safe_fetch`; `fetch_arxiv` → `allow_hosts=["arxiv.org"]`. SD ERCOT client →
`allow_hosts=["ercot.com"]`.

**Edit plan.** (1) SA: `secprim/safe_fetch.py` + `tests/test_safe_fetch.py`
(fake resolver + `httpx.MockTransport`) ✔ built. (2) FP `job.py`. (3) SH
`http.py` + call sites. (4) RRA `spec/intake.py`. (5) SD ingestion client.

**Risk.** Low–medium: IP-pinned TLS depends on `sni_hostname` (httpx ≥ 0.23);
pin httpx. Proxies/CDNs that require the hostname in the TCP target (rare) would
fail closed — acceptable for these fetchers.

### 3.5 RC-5 — Secrets

**Current (exact).** SD `settings.py:9-10` env-gated with dev defaults (fixed
this effort, but a prod deploy without the env var still boots on the dev key).
RRA `scrub_secrets` denylist. SH auth scripts write session files at default
umask.

**Target.** `secprim.secrets.require_secret(name, dev_default, env)` — dev
default only when `APP_ENV` is dev/test, else `MissingSecret` at startup;
`write_private(path, data)` — 0600, atomic, umask-safe; `child_env` (§3.3).

**Fit.** SD `settings.py`: `SECRET_KEY = require_secret("DJANGO_SECRET_KEY", dev_default="dev-only-smart-dispatch")`,
`DEBUG = not is_production()` (with `DJANGO_DEBUG` override). SH
`auth_canvas.py`/`auth_piazza.py`: the session-file write → `write_private`
(one-line change each; these scripts are the user's to run, the edit is
mechanical). RRA via `child_env`.

**Edit plan.** (1) SA `secprim/secrets.py` + tests ✔ built. (2) SD settings
+ a test that `APP_ENV=production` without the var raises. (3) SH two
scripts + a mode test. (4) Document `APP_ENV` in each README.

**Risk.** Low; the only behavior change is *refusing to boot in prod on a
missing secret*, which is the point.

### 3.6 RC-6 — Access control at the service edge (SD)

**Current (exact).** `CORS(app)` (wildcard) at `phase_5_1_forecast_api.py:354`;
`/forecast`, `/forecast/range` read `request.args` with no auth or throttle;
Django `dashboard/views.py` proxies to `settings.FORECAST_API_URL`.

**Target.** Layered: (1) ingress authn (k8s ingress annotation / auth proxy) as
the outer gate; (2) app-level `@app.before_request` requiring
`Authorization: Bearer <FORECAST_API_KEY>` on `/forecast*` (`/health` open),
key via `require_secret`; (3) Django holds the key (`require_secret`) and is the
only client — browsers never call Flask; (4) `CORS(app, origins=[DASHBOARD_ORIGIN])`
or removed once only Django calls; (5) `Flask-Limiter` 60/min keyed by key/IP.

**Fit.** Additive: one `before_request`, one `CORS(...)` arg change, one header
in the Django proxy's request, `Flask-Limiter` decorator on the two routes,
`k8s-ingress.yaml` annotations.

**Edit plan.** (1) Flask API: auth hook + limiter + CORS scope; extend
`tests/security/test_forecast_input_validation.py` with 401/429/CORS cases.
(2) Django proxy: send bearer. (3) `k8s-ingress.yaml`: auth + rate annotations.
(4) `.env.example`: `FORECAST_API_KEY`, `DASHBOARD_ORIGIN`.

**Risk.** Medium only operationally (key must be provisioned before deploy);
behind the `APP_ENV` dev default the local flow is unchanged.

### 3.7 RC-7 — Supply chain

**Current.** No SCA in CI; CVEs present (`pypdf`, `urllib3` in RRA;
`flask-cors`, `flask`, `requests`, `gunicorn` in SD); `pypdf` declared but
unused in RRA; FP frontend actions pinned to `@v4` tags.

**Target.** CI `sca` job (`pip-audit --strict` against the lockfile; `npm audit
--audit-level=high` for FP JS), an `audit-ignore.toml` with expiry for accepted
risks, Dependabot for `pip`/`npm`/`github-actions` weekly, all `uses:` pinned to
commit SHAs, unused deps removed.

**Fit.** Additive workflow files; dependency bumps in their own PR per repo
behind the existing test suites (SD's `flask` 2→3 and `flask-cors` 4→6 are
majors — run `tests/` + the new security suite).

**Edit plan.** (1) SA `ci.yml`: add `sca` job template. (2) Each repo: copy
`sca`, add `.github/dependabot.yml`. (3) RRA: `uv remove pypdf`; bump `urllib3`,
`setuptools`; `uv lock`. (4) SD: bump majors in a dedicated PR. (5) FP frontend:
SHA-pin actions.

**Risk.** Medium for SD majors (API changes in flask-cors 6); isolated PR.

### 3.8 RC-8 — Prompt assembly chokepoint + reader/actor split

**Current (exact).** FP `job_parser.py`: `ChatPromptTemplate.from_messages([... "{job_text}" ...])`
(line 16–52), `.partial(format_instructions=…)` (70), `parse_jd_text(job_text)`
invokes with `{"job_text": job_text}` (92) — the scraped text is a template
variable inside instruction text. `jev_binder` assembles answer prompts
similarly. RRA: `extract_spec` passes the paper as a document block (good) and
the builder loop holds `run_python`/`write_file` tools. `app/security.py`
(`harden_untrusted`) exists but is unwired (#23).

**Target.** `promptinject.assemble` = `Untrusted(text, label)` (distinct type),
`build_prompt(instructions, *, data: Sequence[Untrusted], system) -> messages`
(every block `harden()`-ed, directive always appended; bare `str` in `data` is a
`TypeError`), `render`, `assembled_target` (binds the LLM01 corpus to the real
assembly in CI). **Reader/actor rule:** a model with tools receives only
schema-validated reader output, never an `Untrusted` block.

**Fit — FP (LangChain).** Keep the template; change what is interpolated:
`parse_jd_text` passes `{"job_text": harden_untrusted(job_text)}` and the system
message gains the directive via `build_prompt`'s `DIRECTIVE` constant (template
system message += `DIRECTIVE`). Minimal diff, same chain. `jev_binder`: the
label/option/stored-answer strings go through `harden_untrusted` at the one
place they are formatted into the prompt; model output through `scrub_output`
before it is returned to the extension. A test binds `assembled_target` to the
parse prompt.

**Fit — RRA (privilege split).** `extract_spec`/`referee_spec` are the reader
(already tool-less; directive present). The builder's prompts are audited so
their inputs are the `Spec` (pydantic) + KB; where a paper quote is needed the
reader supplies it as an `Untrusted` block through `build_prompt`. A test
asserts the builder entry point's signature takes `Spec`, not a path/str.

**Fit — SD.** No live sink; `smart_dispatch_security.py` already wraps; when
RAG returns, chunks are `Untrusted` blocks through `build_prompt`.

**Edit plan.** (1) SA `promptinject/assemble.py` + tests ✔ built. (2) FP
`job_parser.py`, `jev_binder.py`, test. (3) RRA builder prompt audit + signature
test. (4) Update each `SECURITY.md` (#23 closed).

**Risk.** Low–medium: hardening mutates the text the model sees (fence tokens,
redacted control phrases). For FP job text this is acceptable; for RRA the paper
already enters as a document block, so no mutation of paper content occurs.

### 3.9 RC-9 — Hardening defaults via Semgrep

**Current.** SHA-1 keys (FP ×4, SH ×1, SD), `torch.load(weights_only=False)`
(SD), k8s deployments without `securityContext`, Flask dev bind.

**Target.** Three new rules in `semgrep/rules.yml` (`weak-hash-non-crypto`,
`torch-load-unsafe`, `flask-dev-bind-all`) + `p/kubernetes` in `scan.sh` for SD;
one-time fixes.

**Edit plan.** (1) SA rules + fixture tests. (2) FP/SH/SD hash swap (SHA-256 for
new keys; `usedforsecurity=False` where a digest must stay stable). (3) SD
`torch.load(..., weights_only=True)`; `securityContext` block in both k8s
deployments; gunicorn in the Dockerfile `CMD`.

**Risk.** Low; SHA-256 swap changes cache-key values once (cache miss, not a
correctness issue) — note in each PR.

---

## 4. Feature selection

| # | Feature | RC | Value | Effort | Risk | Decision |
|---|---|---|---|---|---|---|
| 1 | `secprim` primitives + tests | 1,2,3,4,5 | very high (unlocks all) | S | low | **NOW** ✔ built |
| 2 | `promptinject.assemble` chokepoint | 8 | high | S | low | **NOW** ✔ built |
| 3 | RRA sandbox: `.call()` file RPC, remove in-process exec, allow-list env, local hardening | 3 | **highest severity cut** | M | medium | **NOW** (next PR) |
| 4 | RRA container backend + image | 3 | high (real egress control) | M | medium | **NEXT** (after 3; needs Docker on the box) |
| 5 | FP `safe_fetch` in `/api/job/url` | 4 | high (closes TOCTOU) | S | low | **NOW** |
| 6 | FP wire `harden_untrusted` (#23) | 8 | high | S | low | **NOW** |
| 7 | SH `safe_fetch` allow-list + `bounded_read` + `safe_xml` + `redos_probe` | 2,4 | high | S | low | **NOW** |
| 8 | SH `write_private` for sessions | 5 | medium | XS | low | **NOW** |
| 9 | SD `require_secret` + Flask/Django 400 mapping + `finite_float` | 1,5 | medium | S | low | **NOW** |
| 10 | SD access control (auth, limiter, CORS scope, ingress) | 6 | high if ever exposed | M | medium (ops) | **NEXT** |
| 11 | SD `safe_zip_members` | 2 | medium | XS | low | **NOW** |
| 12 | CI `sca` + Dependabot + SHA-pinned actions (all repos) | 7 | high, compounding | S | low | **NOW** |
| 13 | RRA dep bumps (`pypdf` removal, `urllib3`) | 7 | medium | XS | low | **NOW** |
| 14 | SD dependency majors (`flask`, `flask-cors`) | 7 | medium | M | medium | **NEXT** (own PR) |
| 15 | RC-9 Semgrep rules + one-time fixes | 9 | medium | S | low | **NOW** |
| 16 | RRA reader/actor audit + signature test | 8 | medium | S | low | **NOW** |
| 17 | Egress allow-list for RRA data adapters inside container | 3 | medium | M | medium | **DEFER** (after 4) |
| 18 | Private package index for `secprim` | — | low | M | — | **NOT DOING** (git-tag pin suffices) |

Rationale in one line: do everything that is small, low-risk and closes a
reachable issue now; sequence the two medium-risk structural changes (sandbox
RPC, then container; SD access control) each in its own PR behind a flag; defer
only what depends on the container existing.

---

## 5. Edit manifest (complete)

### security-agents (SA) — ✔ built in this step unless marked
- **add** `secprim/{__init__,boundary,bounded,child_env,secrets,safe_fetch}.py`
- **add** `promptinject/assemble.py`
- **add** `tests/{test_boundary,test_bounded,test_child_env_secrets,test_safe_fetch,test_assemble}.py`
- **add** `DESIGN.md` (this), **edit** `ROOT-CAUSES.md` (solutions ✔), `README.md` (layout)
- **edit** `pyproject.toml`: package `secprim`; optional dep `httpx`
- **edit** `semgrep/rules.yml`: + `weak-hash-non-crypto`, `torch-load-unsafe`, `flask-dev-bind-all` — *todo*
- **edit** `.github/workflows/ci.yml`: + `sca` job template — *todo*

### research-replication-agent (RRA)
- **edit** `replicator/build/sandbox.py` (backend, `.call`, allow-list env, limits, watchdog, rename monitor)
- **add** `replicator/build/_runner.py`; **add** `Dockerfile.sandbox`; **edit** `Makefile`
- **edit** `replicator/orchestrator.py` (remove `_load_pipeline`; 3 call sites → `.call`)
- **edit** `replicator/templates/cs_eval.py` (`child_env`; container path)
- **edit** `replicator/build/builder.py` (`contained_path` on `run_python.path`)
- **edit** `replicator/spec/intake.py` (`safe_fetch`)
- **edit** `papers/batch/resnet/work/assemble.py` (no pickle)
- **edit** `pyproject.toml` (`security-agents` git dep; remove `pypdf`; bump `urllib3`); `uv lock`
- **add** `tests/security/{test_sandbox_call,test_no_inprocess_exec,test_builder_signature}.py`
- **add** `.github/workflows/security.yml`, `.github/dependabot.yml`; **edit** `SECURITY.md`

### firstplay-backend (FP)
- **edit** `app/routers/job.py` (`fetch_html` → `safe_fetch`)
- **edit** `app/autofill/greenhouse.py` (alias to `secprim`)
- **edit** `app/main.py` (global `MalformedInput` handler)
- **edit** `app/chains/job_parser.py`, `app/autofill/jev_binder.py` (harden at the format site; scrub output; directive)
- **edit** `app/autofill/{__init__,jev_binder,scale}.py` (SHA-256 / `usedforsecurity=False`)
- **edit** `requirements.txt` (`security-agents` git dep; pin `httpx`)
- **add** `tests/security/{test_safe_fetch_integration,test_prompt_assembly}.py`
- **add** `.github/workflows/security.yml`, `.github/dependabot.yml`; **edit** `../firstplay-frontend/.github/workflows/test.yml` (SHA pins); **edit** `../SECURITY.md`

### smart-dispatch (SD)
- **edit** `backend/phase_5_1_forecast_api.py` (`finite_float`; `errorhandler`; `before_request` auth; limiter; CORS scope)
- **edit** `frontend/smart_ui/settings.py` (`require_secret`, `APP_ENV`), `frontend/smart_ui/dashboard/views.py` (bearer header; 400 mapping)
- **edit** `data_ingestion/ingest_ercot_history.py` (`safe_zip_members`), ERCOT client (`allow_hosts`)
- **edit** `forecasting_model/phase_3_5_save_model.py` (`weights_only=True`)
- **edit** `k8s-forecast-deployment.yaml`, `k8s-forecast.yaml` (`securityContext`), `k8s-ingress.yaml` (auth/rate annotations), `Dockerfile` (gunicorn)
- **edit** `requirements.txt` (git dep; majors in a separate PR), `.env.example`
- **add** `tests/security/{test_access_control,test_zip_budget,test_settings_prod}.py`
- **add** `.github/workflows/security.yml`, `.github/dependabot.yml`; **edit** `SECURITY.md`

### study-hub (SH)
- **add** `scripts/http.py` (`fetch` = `safe_fetch` with allow-list from config)
- **edit** `scripts/adapters.py`, `scripts/sync_*.py` (use `http.fetch`), `scripts/extract_text.py` (`safe_xml_fromstring`), `scripts/ledger.py` (`_checked_dest` → `contained_path`), `scripts/adapters.py:230` (hash)
- **edit** `scripts/auth_canvas.py`, `scripts/auth_piazza.py` (`write_private`)
- **edit** `requirements`/README (git dep)
- **add** `tests/security/{test_fetch_allowlist,test_redos_probe,test_session_mode}.py`
- **add** `.github/workflows/security.yml`, `.github/dependabot.yml`; **edit** `SECURITY.md`

---

## 6. Verification plan

| Layer | Proof | Kept proven by |
|---|---|---|
| Primitives (SA) | unit tests: hostile inputs refused, benign pass; `safe_fetch` with fake resolver + `MockTransport` | SA CI `test` job |
| Boundary A per repo | Hypothesis `assert_robust` over every registered parser; `redos_probe` over every untrusted regex | repo `security-tests` job |
| Boundary B — sandbox | env scrub (exists) + `.call` round-trip + AST "no in-process exec" + container smoke when Docker present | RRA `security-tests` |
| Boundary B — fetch | FP/SH integration tests against `MockTransport`; redirect + size cases | repo `security-tests` |
| Prompt assembly | LLM01 corpus against `assembled_target` on the real prompt (8/8); directive-presence tests | repo `security-tests` |
| Service edge (SD) | 401/429/CORS cases on the Flask test client | SD `security-tests` |
| Defaults | Semgrep rule fixtures (positive/negative snippet each) | `sast` job |
| Supply chain | `pip-audit --strict` / `npm audit` fail on seeded CVE | `sca` job |

**Definition of done per repo:** the three CI jobs exist and are green; the
repo's `SECURITY.md` lists no RC item as "DOC" that §4 marked NOW; and the
per-repo PR diff touches only the files in §5.

---

## 7. Status — implementation and verification complete (2026-11-26)

Every root cause has an implementation PR per repo, each independently verified
(own test run in a clean worktree + direct check of every named defect), then a
**per-area cross-repo verification wave** (five reviewers, one per security
area, read-only) found further defects in every repo and in one toolkit
primitive, all fixed in one consolidated round per repo and re-verified.

| Repo | PRs (stacked: baseline → root-causes) | Verified |
|---|---|---|
| research-replication-agent | #1 → #2 | 105 security / 126 whole suite |
| smart-dispatch | #19 → #20 | 83 security / 205 repo (+37 skipped) |
| study-hub | #1 → #2 | 103 (isolated hub; live tree untouched) |
| firstplay-backend (+ frontend) | #36 → #37 (+ frontend #6) | 49 security / 1,340 full suite |
| security-agents (toolkit) | #1 CI, #2 fuzzing, #3 SAST, #4 secrets, #5 fuzz_lib | #1 CI green; others 70–93 tests |

**Found by the verification wave and fixed:** CS track ran outside the sandbox
(RRA); `ingest_recent.py` (the live cron) bypassed the pinned fetch and the
rate limiter never counted rejected requests (SD); content-derived Piazza links
fetched with no host check, session files created world-readable, XML size
checked after decompression (SH); `resume_parser` sink unhardened and the
autofill binder fenced without the directive (FP); **`require_secret` failed
open on any non-prod label** (toolkit, PR #4); the reusable `sca` job audited the
wrong interpreter (toolkit, PR #1 fix).

**Pin dependency (must precede merging repo PRs):** the fix rounds use
`fuzzing.fuzz_lib.size_sweep` and `secprim.is_dev`, which exist only after
toolkit PRs #2 and #4 → merge toolkit PRs → tag `v0.1.1` → bump each repo's
`security-agents@v0.1.0` pin to `v0.1.1` → merge repo PRs (baseline first).

**Documented follow-ups (not blocking):** RRA container backend end-to-end,
generated-artifact pickle, a `HEAD` probe on a fixed MNIST host; SD `model.pt`
scaler split (`weights_only=True`), `flask`/`flask-cors`/`scikit-learn` majors;
FP backend dependency CVEs and frontend `npm audit` highs (dependency-bump PRs);
convergence of each repo's inline CI on `templates/security.yml@v0.1.1`;
Burp Suite / Metasploit remain manual lab exercises.

**Process lesson recorded:** several agents sharing one git checkout stepped on
each other's staged files; every later agent worked from an isolated worktree.
Rule: one worktree per concurrent agent.

## 8. Visibility (2026-11-26)

The toolkit repository was made **public** after the toolkit PRs merged and
`v0.1.1` was tagged. Consequences: the `TOOLKIT_TOKEN` secret in §2.1/§3.7 and
`CI-SETUP.md` is optional (anonymous HTTPS installs work); the project repos'
inline workflows were updated to use the token only when present. The analysis
documents here name weaknesses in the project repos by file and line; the window
in which those were public but unmerged closes when the per-repo PRs land.
