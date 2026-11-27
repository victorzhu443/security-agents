# Open-source survey — what we adopt, what we reference, what we reject

Six components surveyed in parallel on **2026-11-27** against the shared rubric
(`templates/SURVEY-RUBRIC.md`): vulnerability **data**, non-LLM **static** detectors, agent
**harnesses**, **verifiers** and security eval suites, reproducible **environments** and
sandboxes, and **statistics / reporting / disclosure**. 160 candidates, every row checked
against its own repository or documentation on that day (GitHub API for license and last push;
READMEs, rule sources, pricing pages and dataset manifests read directly). Nothing was
installed; every description is categorical.

**Facts verified against repos on 2026-11-27; re-survey before each new class.** Version
numbers, prices, free tiers and maintenance states below are snapshots of that day.

## 1. Purpose and the principle

We are building a defensive security agent that finds vulnerabilities and proposes fixes in
Python repositories, measured by lab-grade evals, one vulnerability class at a time (first:
P4 egress / SSRF, CWE-918). The framework decision is already made: **Harbor** is the task,
sandbox and runner layer.

The principle that decided every row: **adopt data, infrastructure and baselines freely;
build only the contribution; reference whatever overlaps it.** The contribution is the
security graders, the per-class agents and the measurement discipline. A dataset, a sandbox
provider, a statistics convention or a generic coding agent is somebody else's work we should
stand on. A competing grader or a competing security agent is something to read and compare
against, never to depend on, because depending on it would make the measurement circular.

Three questions drove the survey: what exists that we were about to rebuild; what licenses let
us ship; and where the field is genuinely empty (those gaps, §5, are what we build).

## 2. Adopt

Thirty-five distinct components (39 table rows; GitHub Advisory Database, PatchEval and the
Harbor registry / viewer appear in two surveys each and are merged here). "Pinned version" is
what was current on the survey date; pin it in the `calib` extra or the task Dockerfile when
first used, and record the pin where the row says.

| name | component | what it does | license | pinned version (2026-11-27) | how we use it | caveat |
|---|---|---|---|---|---|---|
| Harbor | harness · data · stats | Task format (`instruction.md`, `task.toml`, `environment/`, `solution/`, `tests/`), separate verifier sandbox, per-phase network policy, runner, 45 pre-integrated agents, ATIF trajectories, `dataset.toml` registry (80 datasets), local `harbor view` | Apache-2.0 | v0.27.0 (2026-11-21); ATIF schema v1.8 | The runner, task format and viewer; our dataset is a `dataset.toml` manifest; `harbor view` is the only Phase 1 results viewer | Active API (0.x): graders stay pure functions independent of it. No security dataset exists in the registry — ours is the first. Harbor Hub (hosted) has no stated free tier; revisit at Phase 6 |
| Harbor RewardKit (`harbor-rewardkit`) | verifiers | Verifier toolkit: weighted `@criterion` functions, `command_succeeds`, multi-reward subdirectories, unprivileged `Worker`, writes `/logs/verifier/reward.json` + `reward-details.json` | Apache-2.0 | 0.2.4 | Reward plumbing; our five graders (recall, FPR, fix, claim fidelity, scope) become criteria in a multi-reward `tests/` tree; judge criteria stay off | Python ≥ 3.12; young package (0.x) — one adapter absorbs an API move. LLM-judge criteria exist; the verifier must never enable them |
| Terminus-2 (in Harbor) | harness | Harbor's reference *external-loop* agent: loop outside the box, tmux session, LiteLLM, writes ATIF | Apache-2.0 | ships with Harbor v0.27.0 | Template for our `BaseAgent` class agents (keys stay outside the container) and a free third baseline (`-a terminus-2`) | No dedicated docs page; read the source and tests |
| mini-swe-agent | harness | Bash-only, one-command-per-step, model-agnostic (LiteLLM) coding agent | MIT | v2.4.6 (pushed 2026-11-23) | Primary same-model generic baseline (`-a mini-swe-agent --ak version=…`); isolates our agent spec from the model | Harbor installs latest unless `version` is passed — always pass it. ATIF v1.7 emitter |
| OpenHands / OpenHands SDK | harness | Full-featured autonomous coding agent (terminal, file editor, task tracker, browser) | MIT | v1.46.0 / SDK v1.64.1 (2026-11-25) | Heavyweight generic baseline (`-a openhands-sdk`) | Slow venv install — bake with `--install-only`; pin `version` |
| OSV.dev (API + GCS dump) | data | Aggregated advisory database in OSV JSON; per-ecosystem zips, `modified_id.csv` for incremental sync, REST API | Code Apache-2.0; PyPI data CC-BY-4.0 (via GHSA / PYSEC) | PyPI `all.zip` 38 MB, 27,101 records on 2026-11-27 | Primary ingest for `evals/calib/advisories.py`: one offline zip; 266 CWE-918 PyPI records, 179 with a fix link | Only 1,534 of 9,666 fixed records carry `GIT` ranges — parse `references[type=FIX]` / commit / PR URLs; PR URLs must be resolved to merge commits. 123 of the 179 CWE-918 records were published in 2026 and cluster in AI-framework packages |
| GitHub Advisory Database (GHSA) | data · stats | Reviewed advisories in OSV format with `database_specific.cwe_ids` and FIX references, per ecosystem, git-cloneable | CC-BY-4.0 | pushed 2026-11-27 | The CWE-label source; consumed through the OSV dump, raw repo as fallback (no API key needed) | Same JSON as OSV — do not ingest twice |
| PyPA advisory-database (PYSEC) | data | PYSEC YAML/OSV records for PyPI with community triage; most `GIT` fixed-commit ranges come from here | CC-BY-4.0 | pushed 2026-11-25 | Arrives inside the OSV dump; no separate ingest | Mostly NVD-derived; 8,025 records |
| NVD CVE API 2.0 | data | Authoritative CVE records: CWE, CVSS, `Patch`-tagged references, published dates | US government, public domain | API 2.0 | Fallback only: fill CWE / date where a GHSA record lacks `cwe_ids` | Rate-limited (5 req / 30 s, 50 with a key per NVD docs); needs an adapter and throttling; not a primary feed |
| PatchEval / PatchEval-Verified | data · verifiers | 1,000 CVEs (Py/Go/JS) with fix commits; 230 dockerised (`ghcr.io` images) with a PoC-based `fix-run.sh` oracle (security test + functionality tests must both pass) | Apache-2.0 | Verified manifest 2026-07-24; repo pushed 2026-10-19; Inspect pins `c8cc29e` | Seed / held-out set for the next classes (CWE-22, 77/78, 94): 70 Python CVEs with fix commit, vulnerable and fixed function, and a runnable fix oracle we did not write | Only **1** CWE-918 record (CVE-2024-0243, langchain) — not Phase 1 data. ~2 GB per image (≈150 GB for the Python subset). Public since 2025: needs the disclosure-date contamination split |
| Semgrep CE + Community rules | static | Pattern + single-function taint SAST; five Python CWE-918 rules (`python.flask.security.injection.ssrf-requests`, `tainted-url-host`, `python.django.security.injection.ssrf.*`) | Engine LGPL-2.1; rules "Semgrep Rules License v1.0" (internal use only, **no redistribution**) | pushed 2026-11-27; already wired | Primary non-LLM SSRF baseline, intra-file taint; `--config p/python` fetched at run time; JSON/SARIF | **Never vendor `semgrep-rules` into this public repo.** Pro rules and cross-file taint need a logged-in Semgrep account — out of scope for an offline sandbox |
| CodeQL (queries + CLI) | static | Whole-program interprocedural taint SAST; Python `py/full-ssrf` (default suite) and `py/partial-ssrf` (`python-security-extended.qls`), path-problem output | Queries MIT; **CLI proprietary** (permitted for OSI-licensed codebases and academic research; no hosting or redistribution) | pushed 2026-11-27 | Second, strongest SSRF baseline (cross-file) over our OSS CVE-fix corpus, run as a batch inside our own containers | **Never redistribute the CodeQL CLI**; never run it inside a product or hosted service; ~1 GB install, minutes per repo (`codeql database create --language=python`) |
| Pysa | static | Interprocedural taint analysis for Python; stock rules 5012 "Potential SSRF" and 5053 (partial SSRF); Django/Flask/requests models | MIT | mid-migration out of archived facebook/pyre-check into github.com/meta/Pysa (pushed 2026-11-25; still `pip install pyre-check`; requires Pyrefly) | Third independent SSRF baseline after a **one-day spike**; the only interprocedural engine with a stock SSRF rule under a license we could ship | Gate: if `pyrefly check` / `pyre analyze` fail on > 25 % of calibration repos, drop to reference. Needs `.pyre_configuration` and a clean type check |
| Bandit | static | AST pattern checks, no data flow; request-adjacent B310 / B113 / B501 | Apache-2.0 | pushed 2026-11-09; already wired | Sink-only lower bound ("floor") and the cheap HTTP-call inventory for the bare-model baseline | Not an SSRF detector on its own; ruff's S-rules are the same signal and were rejected as redundant |
| pip-audit | static | SCA for Python environments / requirements against the PyPI Advisory DB or OSV; `--fix`; JSON / CycloneDX / Markdown | Apache-2.0 | pushed 2026-11-27; already wired | Stays the dependency-vulnerability detector | Needs a resolvable requirements set; if that bites inside containers, osv-scanner (reads lockfiles offline) is the promotion candidate |
| Hypothesis | static | Property-based testing library | MPL-2.0 (file-level copyleft; fine as a dependency) | pushed 2026-11-27; already wired | For P4 its role is on the **fix grader**: property-test proposed URL/host allowlist validators against generated host spellings and schemes | Not detection |
| Atheris | static | Coverage-guided fuzzing for Python + native extensions (libFuzzer); Python 3.11–3.14 | Apache-2.0 | 3.0.0 (pushed 2026-06-17) | Keep for parsing / memory classes | Irrelevant to SSRF (a design flaw, not a crash). Needs LLVM on macOS; fine in Linux containers |
| SWE-bench Verified (methodology) | verifiers | Human-validation rubric: two 0–3 axes (*underspecified issue*, *unfair tests*), multiple raters, drop at ≥ 2; 68.3 % of SWE-bench filtered | SWE-bench MIT; **dataset card states no license** | Harbor registry `swebench-verified 1.0` (500 tasks) | Validity gate for our advisory tasks: "underspecified advisory" and "unfair hidden test", two raters, keep ≤ 1. Copied, not installed | Not a security dataset; confirm the dataset license before copying any sample |
| uv `--exclude-newer` | envs | Resolver cutoff: only distributions uploaded before an RFC 3339 date are considered; per-package exemptions; works for `uv pip install/compile` and `uv lock` | Apache-2.0 / MIT | pushed 2026-11-26 | `uv pip install --exclude-newer=<fix-commit date>` in every task Dockerfile install step: a 2021 commit resolves against 2021 PyPI with one flag and no proxy | Needs PEP 700 `upload-time` (PyPI has it); git dependencies unaffected; legacy `setup.py` that uv refuses falls back to pypi-timemachine (reference) |
| Official `python:<ver>-slim` images | envs | Per-minor-version Debian / Alpine images; built for 3.11–3.16; EOL tags stay pullable but frozen | MIT | pushed 2026-11-10 | Interpreter of the commit's era as the task base image | EOL images carry archived apt mirrors — pin `deb.debian.org` → `archive.debian.org` when `apt-get` fails |
| uv-managed Python (`uv python install`, python-build-standalone) | envs | Prebuilt CPython on demand from `.python-version` / `--python`; catalogue frozen per uv release | uv Apache-2.0 / MIT; PBS MPL-2.0 | PBS lists 3.11–3.16 | Second interpreter source when the `python:` tag is wrong or a patch version matters | Interpreters < 3.11 exist only in past PBS releases — verify `uv python list` first |
| Docker (local, Harbor `--env docker`) | envs | Harbor's default runtime: Compose, egress-control sidecar with every network policy mode, host-mounted logs | Engine Apache-2.0 | docker CLI + compose v2 plugin | The containment and network phases of the plan run here (and on the hosted providers with policy parity) | — |
| colima | envs | Docker daemon in a Lima VM on macOS; `vz` backend, Rosetta for x86_64 images | MIT | pushed 2026-10-13 | Harbor's default `docker` env on the Mac at $0; local results labelled *local* | docker / compose CLIs installed separately |
| Modal (Harbor `--env modal`) | envs | Hosted sandboxes; Compose + all network policy modes | Client Apache-2.0 | Starter plan: $0 + **$30/month recurring free credit**; 2 core + 4 GiB ≈ $0.38/h ≈ 79 sandbox-hours/month | The recurring hosted runtime for train / validation runs | Only provider with a recurring free tier inside a $200/month total; prices are the survey-day snapshot |
| Daytona (Harbor `--env daytona`) | envs | Hosted sandboxes; Harbor's reference remote provider (Compose, SSH streaming, all network policy modes) | **Service; OSS repo archived 2026-06, license pulled** | **$200 one-time signup credit**; 2 vCPU + 4 GiB ≈ $0.166/h ≈ 1,200 sandbox-hours | **Burst only**: spend the one-time credit on the sealed-split and parallel runs, nothing recurring | OSS core moved to a private codebase; do not build anything on its client that Harbor does not already wrap |
| OSV schema | stats · data | JSON vulnerability-record format (`id, affected[].ranges, severity, credits[FINDER/REPORTER], references, database_specific`); JSON Schema + Python validator | Apache-2.0 | 1.9.2 (pushed 2026-11-26) | One record type for advisory **ingest** and for discovery-mode **findings**; `credits` carries attribution | — |
| GitHub private vulnerability reporting (PVR) | stats (disclosure) | Private report → maintainers; REST `POST /repos/{o}/{r}/security-advisories/reports` (`summary, description, vulnerabilities[], cwe_ids, severity`) | Free on public repos | documented GitHub product | The disclosure channel for discovery mode (Roadmap 6 / Phase 8); OSV record → PVR body adapter | Rate-limited 5 / repo / day, 25 / day; only when the target has PVR enabled — the target's `SECURITY.md` decides, else its listed contact |
| OpenSSF OSS Vulnerability Guide | stats (disclosure) | Finder guide, maintainer guide, runbook, `SECURITY.md` / embargo / disclosure-notification templates | CC-BY-4.0 | pushed 2026-08-19 | Our disclosure runbook and report template come from here, not written fresh | Slow cadence; no tests (text) |
| `statistics` / `math` stdlib (current `evals/metrics.py`) | stats | Wilson (`math.sqrt`), exact McNemar (`math.comb`), paired percentile bootstrap (`random`), pass^k, Miller CLT / clustered SE | PSF | in place | Keep as the runtime estimator set; runtime stays `hypothesis + pyyaml` | "stdlib" means "unverified" unless `tests/test_stats.py` checks every number against the two oracles below |
| scipy.stats (`bootstrap`, `binomtest`) | stats | BCa / percentile bootstrap CIs, paired resampling, exact binomial | BSD-3 | 1.18 (pushed 2026-11-27) | **Dev / test oracle only** under a `dev` extra | Pulls numpy; not a runtime dependency. BCa returns NaN on degenerate (all-tied) data — another reason the runtime uses percentile intervals |
| statsmodels (`proportion_confint(method="wilson")`, `mcnemar(exact=True)`) | stats | Wilson / Jeffreys / Agresti-Coull CIs, exact / chi2 McNemar | BSD-3 | pushed 2026-11-27 | **Dev / test oracle only**; with scipy covers every function we hand-roll | Heavy (pandas, patsy) |
| Inspect AI metrics conventions | stats | `stderr(cluster=key)`, `bootstrap_stderr`, `ci_wilson`, `grouped(metric, key)`; recommends Wilson for binary scores | MIT (conventions; package not adopted) | docs 2026-11-27 | Name our fields the same way: SE clustered by task, `grouped` by split / condition / contamination bin, Wilson for binary rates | We run on Harbor, not Inspect — conventions only |
| Miller 2024, "Adding Error Bars to Evals" (arXiv 2411.00640) | stats | CLT SE, clustered SE (up to 3× naive), paired differences, K-resample variance rule, power formula | paper | — | The power note and the K-trials-per-task rule in the card; cited in the Power section | "Bootstrap unnecessary unless complicated estimator" — our percentile bootstrap over per-task differences is the simple case |
| Hugging Face dataset-card template | stats (reporting) | Markdown + YAML front matter: Details, Uses / Out-of-Scope, Structure, Creation, Bias / Risks / Limitations, Citation | Apache-2.0 | pushed 2026-11-27 | Skeleton for `evals/cards/calib-egress.md`; we add Splits, Contamination, Power, Exclusions, Not measured | Dataset card, not eval card — the added sections are ours |
| Datasheets for Datasets / Model Cards (Gebru et al.; Mitchell et al.) | stats (reporting) | Question lists: motivation, composition, collection, preprocessing, uses, distribution, maintenance | papers | — | Checklist to audit the card against; nothing to install | The HF template is their operationalised form |

### License guardrails (keep every one)

- **semgrep-rules are not vendored.** Fetch `p/python` at run time; the rules license forbids redistribution.
- **The CodeQL CLI is not redistributed** and runs only as a batch baseline in our own containers over OSI-licensed GitHub-hosted repositories; never inside a product or hosted service.
- **Sample licenses to confirm before copying a single sample:** the SWE-bench Verified dataset card (no license stated), CodeIPI samples (none in the README), SeCodePLT (no LICENSE anywhere; rejected for that reason).
- **Daytona** is a service with its OSS license pulled; consume it only through Harbor's `--env daytona`.
- **CERT Guide to CVD** may be redistributed unchanged but not remixed into our docs — cite it.
- TruffleHog (AGPL) and the LGPL / MPL tools are fine as invoked CLIs or dependencies; nothing copyleft is vendored.

## 3. Reference

Sixty-eight distinct items (71 table rows; Inspect Evals and OSS-Fuzz appear in two surveys,
and the CyberSecEval Inspect ports are folded into the CyberSecEval row). These are read,
compared against, or mined for a pattern — never depended on. ARVO is here rather than under
Reject: its *data* is C/C++ (rejected by the data survey) but its *task layout* is the template
the environments survey wants copied.

| name | component | what to learn from it | why not depend |
|---|---|---|---|
| CVEfixes | data | Cross-check fix-commit links and per-file language tags for pre-2024 CVEs; the CVE→commit→file→method schema | Frozen at v1.0.8 (2024-07-23): misses the 2024–26 CWE-918 records; OSV supersedes for ingest |
| CVEProject/cvelistV5 | data | Official CVE List JSON 5 (CNA-supplied CWE + references) | Redundant with NVD / GHSA for our fields; CVE terms of use, no SPDX |
| VulnerableCode (aboutcode) | data | Aggregator DB + API of vulnerabilities and fixed versions | Package-version centric; OSV already aggregates the same sources |
| MoreFixes | data | CVEfixes successor with confidence-scored fix commits (v4 2026-06-20) | Postgres dump with an unstated data license; Python share unpublished — use only if OSV FIX refs miss a commit |
| Inspect Evals (UK AISI) | data · harness · verifiers | Eval collection; `cyberseceval_4` port explicitly dropped autopatching "without source + build/test/validation loop" — the bar our fix grader meets | No Python fix-commit data; cyber evals are CTF / exploit / QA; not a harness |
| BountyBench | data | 40 real bounties on 25 systems, many Python targets; Detect / Patch task shapes | Mixed offensive / defensive (Exploit tasks); own harness and per-bounty containers; stalled since 2025-08. Mine Python Patch tasks as a later held-out set via adapter |
| AutoPatchBench (PurpleLlama / CyberSecEval 4) | data | Differential-fuzzing patch verification design | C/C++ fuzzer-crash cases from ARVO |
| SEC-bench | data | Base / instance / eval image hierarchy as a model for our Harbor task images | C/C++ only (`lang` column) |
| PyVul | data | Cross-check our candidate list against its 1,157 commit-level Python vulns | No license file; 7 stars |
| CVE-Bench (NAACL 2025 repair; Wang / Liu / Xiao) | data | Repair-environment design over 509 CVEs (Py / Java / JS / PHP from CVEfixes) | Paper only; no code release found |
| VulnRepairEval | data | PoC-oracle yield: 23 Python CVEs survived out of 400+ — the attrition rate to expect | Paper only; no code release found |
| AIxCC challenge projects | data | DARPA challenge repos and CRS code | C / Java; no Python targets; mixed MIT / AGPL / none |
| OpenGrep | static | Cheapest A/B for "does cross-file taint change SSRF recall": fork of Semgrep CE 1.100 running the same rules with cross-function and cross-file taint | Young fork (Dec 2024); its own rules fork unverified. Promote to adopt only if Semgrep CE intra-file misses appear in calibration |
| Bearer CLI | static | Fourth SSRF datapoint if wanted (`python_lang_http_url_using_user_input`, CWE-918; SARIF) | Elastic License 2.0 (not OSI) keeps it out of the shipped toolkit |
| Trivy | static | One binary for SCA + secrets + image scan of our own Harbor images | Not needed for P4; candidate for the class-blind / router phase |
| osv-scanner | static | Offline lockfile / SBOM scanning against OSV.dev | Overlaps pip-audit; promote only if pip-audit's resolved-environment need bites in containers |
| Grype + Syft | static | SBOM generation + vulnerability matching | Same role as Trivy; pick one SBOM stack later |
| gitleaks | static | Regex / entropy secrets scanning of files and git history; stable, offline | Adopt when the hardcoded-credentials class arrives; feature-complete, "security patches only" |
| TruffleHog | static | 800+ secret detectors | Live credential verification makes outbound calls — must run `--no-verification` in a no-egress sandbox; AGPL; gitleaks is the simpler fit |
| detect-secrets | static | Baseline-file secrets detection with 27 plugins | Designed for pre-commit baselines, not one-shot repo scans; slow release cadence |
| Joern | static | Code-property-graph platform with a Python frontend; taint via CPGQL | No stock Python SSRF query — writing one competes for our build time; JVM + Scala |
| Pyrefly | static | Meta's Rust type checker; Pysa's type provider | Only as Pysa's dependency; no security rules |
| OpenSSF Scorecard | static | Repo-hygiene score (branch protection, pinned deps, fuzzing, SAST present) | Not detection; possible covariate when characterising calibration repos |
| OSS-Fuzz (project harnesses + `infra/`) | static · envs | Its Python project harnesses are the worked Atheris examples; `build_specified_commit.py` / `bisector.py` are the "build at commit + reproduce + bisect" pattern with date-indexed base images | The cluster and image hierarchy are its own; irrelevant to SSRF |
| SWE-agent | harness | Best-documented ACI (tool bundles: `bin/`, `config.yaml`, `install.sh`, windowed file viewer); `-a swe-agent` for a "classic ACI" ablation | Self-declared maintenance-only; superseded by mini-swe-agent per its own docs; EnIGMA CTF mode is offensive capability, not our target |
| Terminal-Bench 2.0 / 4.1 | harness | Task-authoring design reference; `harbor run -d terminal-bench-sample@2.0` is the one-command smoke test that runner + baselines work | Not security data |
| LangGraph | harness | Graph orchestration; Harbor runs a user-supplied graph in-container | Loop-in-box orchestration we do not need for a single-agent loop; revisit for multi-class composition |
| Inspect AI (framework) | harness | `sandbox_agent_bridge` (API keys stay on the host behind a loopback proxy); `Score` shape with an explicit *unscored* state; timeout classification (program overrun vs sandbox failure); 10 MB front-truncated exec output; human-agent baseline | Direct competitor to Harbor at the runner layer — adopting it is a re-architecture. Its metrics *conventions* are adopted (§2) |
| Claude Agent SDK | harness | Claude Code's loop as a library (MCP tools, hooks, permissions, subagents) | Baseline already covered by Harbor's `-a claude-code`; building class agents on it means provider lock-in and loop-in-box |
| OpenAI Agents SDK | harness | Guardrails pattern | OpenAI-centric; nothing Harbor + LiteLLM do not already give; no Harbor adapter |
| Inspect SWE | harness | Runs vendor CLIs inside an Inspect sandbox with model calls proxied to the host — the key-stays-on-host pattern | Needs Inspect; 43 stars, no tagged release |
| BrowserGym | harness | Benchmark = task subclass; env / agent / benchmark cleanly separated | Web domain; light maintenance |
| WebArena | harness | One evaluator config per task with several evaluator types — matches our per-task `reward.json` plan | Frozen; itself points to AgentLab / BrowserGym |
| Meta CyberSecEval 4 — ICD, FRR, prompt-injection sets (and the Inspect ports, CyberMetric / SecQA / CTI MCQs) | verifiers | ICD's CWE-keyed semgrep + regex rules as a sibling of our rules and a sanity oracle on agent-proposed fixes; the Inspect port's note that AutoPatch was dropped for lacking a build / test loop | Grades *generated snippets*, not repository findings; prompt-injection grading is model-judged (the opposite of our canary design); knowledge MCQs irrelevant; project "may change significantly", 99 open issues |
| Inspect Evals — CodeIPI (`ipi_coding_agent`) | verifiers | Closest public analogue of our P8 design: 35 injected + 10 benign Python tasks, three deterministic attack-success checks (canary in output / tool calls, `CANARY_EXEC_<id>`, SHA-256 of workspace files), FPR on clean tasks — candidate P8 data | Grader overlaps our P8 harness; Inspect task format (adapter); sample license not stated; small n, no paper |
| Inspect Evals — AgentDojo (ethz-spylab) | verifiers | Measurement shape: benign utility, utility under attack, targeted ASR on one table; formal utility functions, explicitly not LLM judges | Grades the *agent under attack*, not an agent that finds unhardened sinks; own environment model; upstream slow since 2026-06 |
| Inspect Evals — AgentThreatBench | verifiers | OWASP Agentic Top-10 scenarios with clean baselines; utility and security each 0/1 | Same reason as AgentDojo, smaller and newer |
| Inspect Evals — CASTLE | verifiers | 6 vulnerable : 4 clean per CWE and penalised-FP scoring (+5 TP, +2 TN, −1 FP) — the precedent for our FPR metric and negative-control ratio | C, synthetic, single-file; 0 stars |
| garak (NVIDIA) | verifiers | Trigger-string detector pattern (our canary design) and the encoding probe family for corpus ideas | Targets a model or REST endpoint, not a Python callable; much of the corpus is jailbreak-oriented; promptinject probe / detector competes with our harness |
| PyRIT (Microsoft) | verifiers | Ships a CyberSecEval prompt-injection scorer and a garak scorer — the field converges on replaying those corpora, confirming our corpus-replay design | Adaptive multi-turn attack orchestration beyond P8's fixed-corpus design; HTTP target adapter needed; scorers compete |
| promptfoo | verifiers | CI harness for our *apps'* regression evals later; deterministic assertions | Red-team graders model-judged and partly run on a remote generation endpoint — conflicts with "no model calls" in the verifier and with offline sandboxes; Node toolchain |
| mutmut | verifiers | Baseline-derived timeout formula `(baseline + c) × m`; type-checker filtering of trivially-detectable mutants; test-suite-strength covariate per repo | Generic operators cannot express "revert this security fix"; pytest-only, fork-based, Linux / WSL. `evals/mutate.py` stays |
| cosmic-ray | verifiers | Operator catalogue with security-relevant entries (`remove_decorator`, `exception_replacer`) as seeds when `mutate.py` grows | Same reasons as mutmut; config-heavy, Celery |
| Podman (Harbor `--env podman`) | envs | Daemonless fallback local runtime with full network policies | Open Harbor issues on the compose-provider banner breaking agent install (#3035, #3128, #3480) |
| gVisor (`runsc`) | envs | Syscall-level isolation as a Docker runtime; compose-overlay pattern for setting `runtime:` | Linux only; hardening reference for a CI host |
| Kata Containers (Harbor `--env kata`) | envs | KVM microVM boundary for agent / verifier | Linux + `/dev/kvm` only; Harbor's Kata env **rejects network policies** — loses our network phases |
| E2B (Harbor `--env e2b`) | envs | Hosted Firecracker-style sandboxes with DI / host / wildcard / IP policies | Hobby tier: $100 one-time, **1-hour session cap** (tight for build + agent + verify); Pro $150/month would be 75 % of the budget; no Compose; open Dockerfile-build issues |
| SWE-bench harness / image builder | envs | Base → env → instance image layering; per-repo / version map of Python version + install command for its 12 Python repos | Harness itself is replaced by Harbor; slow since 2026-09 |
| SWE-smith | envs | Install-recipe discovery for 250+ Python repos — the closest existing answer to our `RepoConfig` auto-detection | A guide and per-repo images, not an importable library; Linux only |
| ARVO | envs (data rejected) | **The template for our task layout**: paired `-vul` / `-fix` images, PoC baked in as the hidden test, fix verified by rerun; 6,100+ reproducible OSS-Fuzz vulns, 81 % reproduce | Data is sanitizer-crash C/C++ — wrong language and class for Python web CWEs |
| pixi `exclude-newer` | envs | Conda + PyPI date cutoff (uses uv as a library) | Only if a target repo needs conda-native compiled deps |
| PDM `pdm lock --exclude-newer` | envs | Same date-cutoff capability as uv | Needs a PDM project; redundant |
| pypi-timemachine | envs | Local PyPI proxy hiding releases after a cutoff — the fallback when a legacy `setup.py` must install under plain pip | Alpha-quality, single maintainer; an extra process in the build |
| anthropics/sandbox-runtime (`srt`) | envs | Process-level sandbox (Seatbelt / bubblewrap) with deny-by-default network through a domain allowlist; could wrap host-side local-mode runs on the Mac | Not a container or VM; beta research preview; not a Harbor sandbox substitute |
| nixpkgs pinning (+ nix-versions) | envs | Interpreter and system-library pinning Nix-style | Nix inside every task image; no PyPI date resolution |
| Firecracker | envs | Hardening vocabulary; what the hosted providers build on | Linux / KVM only; consumed through providers, never run |
| Every Eval Ever (EEE) schema | stats | JSON schema for eval runs with converters from HELM / lm-eval / Inspect; emit a record later if we publish | Generic results schema with no security fields; new (June 2026); do not shape `summary.json` around it yet |
| Harbor Hub (hosted) | stats | Job upload / share / compare, leaderboards | Needs account + API key; **no free tier stated anywhere**; nothing in Phase 1 needs sharing — revisit at Phase 6 |
| errorbars (PyPI) | stats | `tests/oracles.py` and Monte Carlo coverage tests as the model for ours; CR2 clustered SE, Holm-corrected leaderboards | Created 2026-09, 0 stars, single author, no releases; competes with our `stats.py` |
| lm-evaluation-harness reporting | stats | One convention: every point estimate ships with a `_stderr` / `_ci95` sibling field | Different runner |
| HELM `Stat` / summarize outputs | stats | Per-instance stats file beside the aggregate (`per_instance_stats.json`) so paired tests stay recomputable | Different runner; slow since 2026-09 |
| CERT Guide to CVD | stats (disclosure) | Timelines, roles, multi-party disclosure cases | CMU copyright: redistribute unchanged, no derivatives outside internal use — cite, never remix |
| disclose.io `dioterms` | stats (disclosure) | Safe-harbor clause for our own repo's `SECURITY.md` | Recipient-side policy text; we are the finder |
| GitHub `SECURITY.md` convention | stats (disclosure) | Discovery mode reads the *target's* `SECURITY.md` first to pick the channel | Nothing to build; already in `secure-project` |
| SARIF 2.1.0 + `sarif-tools` | stats | A `findings → SARIF` exporter is a cheap later add-on for maintainers | Per-finding format without oracle / claim fields; not a Phase 1 report format |
| BenchmarkCards (IBM / Notre Dame) | stats | Compare its section list against our card once | One commit on main; the LLM auto-fill tool is not wanted |
| Evaluation Cards (arXiv 2606.09809) | stats | "Minimal reproducibility fields" list as a checklist for `summary.json` | Paper only (June 2026); no code |
| BenchChecker (USENIX Security 2026) | stats | The right contamination *method* for closed models: repository-presence probe (prefix completion) + patch-presence test via repo history; a cheap Phase 2 addition | No released code; results on open models only; our date-based `cutoffs.yaml` bin stays the primary control |

## 4. Reject

Forty-four rows (49 table rows; CyberGym and CVE-Bench (UIUC) each appeared twice, and ten
offensive-capability items from the data and verifier surveys collapse into one row). One
further row, Harbor's ~25 other hosted `--env` providers, was **not surveyed** (no free tier
verified; revisit only if the Modal and Daytona credits run out).

| name | component | reason |
|---|---|---|
| Offensive-capability evals: CyberGym, CVE-Bench (UIUC), Cybench, 3CB, GDM CTFs, InterCode-CTF, ExploitBench, TarantuBench, b3, MCPTox | data · verifiers | Offensive capability (exploitation, PoC generation, CTF), not our target; several are C/C++ fuzz corpora |
| Vul4J | data | Java; GPL-3.0 |
| CleanVul | data | No license; function pairs, not repo tasks; test changes filtered out |
| Safety DB (pyup) | data | CC BY-NC-SA 4.0 (non-commercial); redundant with OSV |
| CrossVul | data | Frozen 2021; superseded by OSV / CVEfixes |
| PrimeVul | data | C/C++; function-level only; dormant since 2024-09 |
| SecRepoBench | data | C/C++; secure code completion, not fix tasks |
| Big-Vul (MSR'20) | data | C/C++; dead since 2021 |
| Devign | data | C; function-level labels, no fix commits |
| MegaVul | data | No Python; GPL-3.0 |
| ReposVul | data | No license file; unmaintained since 2024-11 |
| PySecDB | data | Gated, non-commercial access; dormant since 2023 |
| SecBench.js | data | JavaScript; no license |
| DiverseVul | data | C/C++; no license |
| ruff S-rules (flake8-bandit) | static | Same sink-only signal as Bandit, which we already run with more plugins |
| Snyk Code | static | Cloud-only proprietary engine needing credentials and egress from the sandbox; 100 tests/month is below one k=3 calibration run |
| SonarQube Community Build | static | Taint analysis (SSRF rule S5144) is only in paid editions; server + scanner + DB for no SSRF signal |
| Dlint | static | No SSRF-relevant rule; subsumed by Bandit |
| safety (pyup) | static | 3.x CLI requires a pyup account for the DB; pip-audit covers the need with open data |
| pyright | static | No security rules and no pyright-based security tool exists; Pysa's types come from Pyrefly |
| Pyre | static | Archived 2026-06-26; replaced by Pyrefly, Pysa moved to its own repo |
| pyt (python-taint) | static | Unmaintained since 2020 by its own README; superseded by Pysa |
| Aider | harness | No commits since 2026-05-22; edit-oriented (needs named files), not an exploring agent; Harbor adapter installs an unpinned latest |
| smolagents | harness | Code-as-action design with no terminal / repo agent and no Harbor adapter; executing model-written code is the opposite of our containment stance |
| SeCodePLT | verifiers | No license in repo or on the dataset card; dormant since 2025-09. Watch the card: a licensed `python_vulnerability_detection` split could seed per-CWE negatives |
| NeMo Guardrails | verifiers | A runtime defence, not an evaluator; relevant only as a recognisable mitigation shape in P8 rules |
| Rebuff (Protect AI) | verifiers | Archived 2025-05; its canary-token check is what our harness already implements |
| LLM Guard (Protect AI) | verifiers | Archived runtime filter with unmaintained models |
| Harbor registry `binary-audit` (and `swtbench-verified`, `vmax-tasks`) | verifiers | Wrong artefact type (backdoors in compiled binaries; JS tasks); confirms no security dataset exists in the registry yet |
| Apple `container` (Harbor `--env apple-container`) | envs | VM isolation on the Mac but **no network policy support** — the no-network / allowlist phases would be unenforceable; pre-1.0; no Compose |
| uv2nix / pyproject.nix | envs | Needs a `uv.lock` in the target; years-old commits have none |
| pip-tools (`pip-compile`) | envs | Pins against today's index with no date cutoff; `uv pip compile --exclude-newer` supersedes it |
| Runloop (Harbor `--env runloop`) | envs | $50 one-time credit, roughly double Daytona's price, fewer Harbor capabilities |
| pyenv (in Docker) | envs | Redundant with `python:` tags + uv-managed Python; minutes per image to build from source |
| poetry2nix | envs | Needs a `poetry.lock` at the target commit; Nix overhead |
| conda-lock / mamba | envs | Locks today's solve, not the commit's era; our targets are PyPI projects |
| nsjail / bubblewrap | envs | Linux-only process sandboxes below the container layer Harbor already gives |
| MLflow | stats | Free and good, but a second system of record for results we already get from Harbor + `summary.json` |
| Weights & Biases Weave | stats | Hosted; 1 GB/month ingestion cap; sends trajectories off-box; adds nothing over `harbor view` |
| RFC 9116 `security.txt` + `sectxt` | stats (disclosure) | Web-site contact discovery; our targets are repos, which carry `SECURITY.md` |
| Croissant / `mlcroissant` | stats | Metadata for ML loaders, not for a Docker task suite; heavy deps; a JSON-LD stub would be decoration |
| Google `model-card-toolkit` | stats | Archived 2023; TensorFlow-centric |
| LLMSanitize | stats | Dead since 2024-08; model-side methods need open weights or vLLM — our models are API-only |
| llm-decontaminator (LMSYS) | stats | Dead since 2023; requires access to the training corpus, which we never have for API models |

## 5. Gaps — what nobody has built (these are our contributions)

Each gap was searched for explicitly and confirmed empty across the Harbor registry, Inspect
Evals, Papers with Code, OSV and the papers' reference lists. They are the plan's contribution,
not something to fill by adoption.

1. **A Python-repository vulnerability-detection task set with negative controls, graded by
   deterministic, location-aware recall and FPR.** CASTLE has the metric shape but is C and
   single-file; SeCodePLT is function-level, unlicensed and dormant; PatchEval links PoC oracles
   but not the maintainers' tests, so `fix_test` must be derived from each fix commit's test
   diff; no Python vul/fix image pairs exist (ARVO is C/C++); no human-validated security task
   set in the SWE-bench Verified sense exists (PatchEval-Verified is verified for
   *reproducibility*, not specification clarity or test fairness). Harbor's registry has no
   security dataset of any kind — ours would be the first.
2. **A permissive-licensed, stable, cross-file Python taint engine with a stock SSRF rule.**
   CodeQL's CLI terms are restrictive, Semgrep's cross-file taint is paid, Pysa is mid-migration,
   OpenGrep is young, Joern has no Python SSRF query. Pysa is the closest. Corollary: **no
   published SSRF numbers exist for any of these tools on a Python benchmark**, so our baseline
   scores will be the first and have nothing prior to compare against.
3. **Contamination detection for closed (API-only) models on code benchmarks.** BenchChecker is
   the right method but has no released code; LLMSanitize and llm-decontaminator are dead or
   need the training corpus. The date-based `cutoffs.yaml` bin stays the primary control; a
   repository-presence probe is a cheap Phase 2 addition.

Smaller empties, recorded so no one searches twice: a prompt-injection eval whose target is a
Python callable with deterministic canary grading (CodeIPI targets the coding agent, not the
app); a curated fix-reversion mutation tool (`evals/mutate.py` stays); a Python-first
external-loop agent on Harbor other than Terminus-2; a macOS runtime with both VM isolation and
Harbor network policies; prebuilt interpreters < 3.11 in python-build-standalone's current list;
date-pinned resolution under plain pip (only alpha-quality pypi-timemachine); an importable
"install recipe at commit" library (SWE-smith is a guide); a security-specific eval card or
finding schema carrying oracles, claim fidelity, scope and FPR; a public artifact for CVE-Bench
(NAACL repair), VulnRepairEval or RepoPairBench; pyright-based security tooling; a fuzzing
approach relevant to SSRF (none — it is a design flaw, not a crash class).

## 6. Changes to the plan

Consolidated from all six reports and deduplicated. Section names refer to the current plan
(`Framework decision`, `Phase 1 design` and its subsections, `Spending gates`, `Build order`,
`Verification`, `Risks`, `Roadmap`) and to `EVALS-PLAN.md` where noted.

**Phase 1 design › `evals/calib/advisories.py` (ingest)**
1. OSV PyPI dump is the single ingest source (one 38 MB zip, offline); GHSA records are the CWE
   source via the OSV mirror; NVD is a fallback for CWE / date gaps only. Drop any plan to
   query GHSA and OSV separately.
2. Fix-commit extraction must parse `references[type=FIX]`, `/commit/` and `/pull/` URLs, not
   just `affected[].ranges[type=GIT]` (only 1,534 of 9,666 fixed records use GIT ranges); PR
   URLs are resolved to merge commits. CVEfixes is a cross-check for pre-2024 CVEs only.

**Phase 1 design › `split.py` and `Risks` (stratification, contamination)**
3. 123 of the 179 CWE-918 fixed records were published in 2026 and cluster in AI-framework
   packages (langchain-core, chainlit, pydantic-ai, …): stratify by project × library, cap any
   single project's share of positives, keep the pre/post-cutoff bins. The ≥ 60 gate is met
   three times over, but the set is not representative without the cap.
4. Contamination: no API-model-compatible checker exists; the date-based bin stays primary.
   Add BenchChecker's repository-presence probe as a cheap Phase 2 check. PatchEval's CVEs are
   all public since 2025 and need the disclosure-date split when adopted.

**Phase 1 design › `build.py` and `Task schema` (environments)**
5. Task image = `FROM python:<era>-slim` (uv-managed Python when the tag is wrong) +
   `uv pip install --exclude-newer=<fix-commit date>` on every install step. This replaces the
   `python:3.12-slim` + hand-written install steps the current `env.dockerfile` uses.
6. Copy ARVO's shape: paired vulnerable / fixed images, the PoC or fix test as the hidden
   verifier, fix confirmed by rerun; Harbor's `[environment].docker_image` can point at prebuilt
   pairs. SEC-bench's base / instance / eval image hierarchy is the model for image layering.
7. Expect `apt-get` failures in EOL base images (archived mirrors): pin `deb.debian.org` →
   `archive.debian.org` when needed. Verify `uv python list` before relying on interpreters
   < 3.11. Legacy `setup.py` installs that uv refuses fall back to pypi-timemachine.
8. `fix_test` is derived from each fix commit's test diff — no dataset links maintainers'
   tests to fixes (PatchEval links PoC oracles). Already in the plan; now confirmed as the only
   route.

**Phase 1 design › `Graders for calib tasks` (verifier)**
9. RewardKit is the reward layer: the five graders become `@criterion` functions in a
   multi-reward `tests/` tree (one subdirectory per dimension → `reward.json`),
   `command_succeeds` wraps the hidden fix test, judge criteria stay off, version pinned,
   graders kept as pure functions in `evals/calib/verify.py`.
10. Mirror Inspect's `Score` shape in `reward.json`: `value` (dict allowed), `answer`,
    `explanation`, `reason`, `metadata`, and an explicit **unscored** state excluded from
    metrics. Classify timeouts (program overrun vs sandbox failure) and output truncation as
    first-class grader inputs so a hung test is never scored as a miss.
11. Hypothesis's P4 role is on the fix grader: property-test proposed URL / host allowlist
    validators against generated host spellings and schemes. It is not a detector.
12. Negative controls follow CASTLE's precedent (6 vulnerable : 4 clean per class, FP
    penalised); CodeIPI's three deterministic attack-success checks and benign-control ratio
    are the shape for the P8 class later.

**Phase 1 design › validity gate (`build.py` co-selection)**
13. Human validity rubric = SWE-bench Verified's two axes, *underspecified advisory* and
    *unfair hidden test*, each 0–3, two raters, keep ≤ 1 (drop at ≥ 2). Confirm the SWE-bench
    Verified dataset-card license before copying any sample text.

**Phase 1 design › `Prompt conditions` and baselines**
14. Non-LLM baselines for P4, all run offline in the Harbor container and graded by the same
    recall grader as the agents: Semgrep CE `p/python` (five CWE-918 rules, intra-file taint),
    CodeQL `py/full-ssrf` + `py/partial-ssrf` via `python-security-extended` (interprocedural,
    strongest), Bandit as the sink-only floor. Pysa gets a one-day spike with a drop gate
    (> 25 % of calibration repos failing `pyrefly check` / `pyre analyze` → reference).
    OpenGrep is the A/B for cross-file taint only if Semgrep intra-file misses show up.
15. Agent baselines are Harbor's pre-integrated agents: `mini-swe-agent` (same model as ours →
    isolates the agent spec from the model), `openhands-sdk` (heavyweight generic),
    `claude-code` (vendor), `terminus-2` (free), plus the controls `oracle` (runs
    `solution/solve.sh` → validity gate on every task) and `nop` (does nothing → the grader's
    false-positive floor and recall-of-zero check). These replace the hand-written reference
    and no-op legs. Aider is dropped (stalled, unpinned install).
16. Record a condition difference: our external-loop agent runs `no-network` with keys outside
    the box; the installed baselines need `allowlist` and receive keys inside the container.

**Framework decision › class agents**
17. Write class agents as `BaseAgent` modelled on Terminus-2 (external loop via
    `environment.exec`, ATIF v1.8, validated with `harbor.utils.trajectory_validator`). Not on
    the Claude Agent SDK (provider lock-in, loop-in-box) and not on LangGraph.

**Build order / Verification (reproducibility)**
18. Harbor pins **no** default agent versions: always pass `--ak version=…` and `--model`
    explicitly; bake baselines with `--install-only`; pin image digests, not tags; the one-command
    smoke test is `harbor run -d terminal-bench-sample@2.0 -a <agent>`.
19. License guardrails become repo policy: never vendor `semgrep-rules` (fetch `p/python` at run
    time); never redistribute the CodeQL CLI or run it outside our own containers over the OSS
    corpus; TruffleHog, if ever used, runs `--no-verification`.

**Spending gates (sandbox time)**
20. Sandbox time is $0 within credits; model calls remain the $200. Local runs on colima
    (`--env docker`, labelled *local*); recurring hosted runs on Modal's $30/month free credit
    (≈ 79 sandbox-hours at 2 core / 4 GiB, full network-policy parity); Daytona's one-time $200
    (≈ 1,200 sandbox-hours) is spent on the sealed-split and parallel runs only. E2B's 1-hour
    cap and Runloop's price rule them out; Apple `container` is rejected for lacking network
    policies. gVisor / Kata / Firecracker are Linux-CI hardening to cite, not to run on the Mac.

**Statistics kit / Metrics, reporting, gates**
21. Keep stdlib estimators; add `scipy` and `statsmodels` under a `dev` extra as test-time
    oracles in `tests/test_stats.py` (`proportion_confint(method="wilson")`,
    `mcnemar(exact=True)`, `binomtest`) the way `errorbars/tests/oracles.py` does. Runtime stays
    `hypothesis + pyyaml`.
22. Adopt Inspect's naming (`stderr` clustered by task, `grouped` by split / condition /
    contamination bin, Wilson for binary rates), lm-eval's rule that every point estimate ships
    a `_ci95` sibling, and HELM's per-instance file beside the aggregate so paired tests are
    recomputable from `summary.json`.
23. No published SSRF numbers exist for any baseline tool on a Python benchmark: the card's
    **Not measured** section must say the baseline scores have no external comparison.

**Cards**
24. `evals/cards/calib-egress.md` = HF dataset-card headings + Splits, Contamination, Power
    (Miller 2024 formula, K-trials rule), Exclusions, Not measured; audit it once against the
    Datasheets / Model Cards question lists and the BenchmarkCards section list.

**Roadmap 6 / EVALS-PLAN Phase 8 (discovery mode, disclosure)**
25. The internal finding record is an OSV JSON record (`credits` for attribution); the runbook
    and report template are the OpenSSF OSS Vulnerability Guide's finder guide and templates;
    the channel is GitHub private vulnerability reporting via REST, chosen by reading the
    target's `SECURITY.md` first, falling back to its listed contact; CERT CVD is cited, not
    remixed. A `findings → SARIF` exporter and an EEE record are later add-ons if we publish.
26. `harbor view` is the only viewer; Harbor Hub is revisited at Phase 6 (no free tier stated).

**Roadmap 3 (next class)**
27. PatchEval-Verified's 70 Python CVEs (fix commit + PoC oracle, Apache-2.0) seed the next
    classes (CWE-22, 77/78, 94), not P4 (one CWE-918 record). BountyBench's Python Patch tasks
    are a later held-out candidate via adapter.

**EVALS-PLAN Layer 2 (`evals/mutate.py`)**
28. `mutate.py` stays (curated fix reversions, per-property kill rate). Borrow mutmut's
    baseline-derived timeout formula and type-checker mutant filtering, and cosmic-ray's
    `remove_decorator` / `exception_replacer` operators as a seed catalogue.

## 7. Appendix — the six per-component surveys, verbatim

The tables below are the surveyors' reports as written on 2026-11-27, unchanged, so every
score, evidence phrase, count and link is preserved (the only edit is that heading levels are
shifted down two so the document outline stays valid). Where the consolidated tables above and
an appendix row disagree in wording, the appendix is the primary record.


### A.1 Data (`survey-data.md`)

### Survey — DATA: vulnerability datasets and feeds with fix commits, for Python eval tasks

Date: 2026-11-27. Read-only survey; every row verified against the repo/API today (GitHub API
metadata via `gh api`, OSV PyPI dump downloaded and counted, PatchEval manifest downloaded and
counted). Scores 0–2 per rubric criterion; total /12.

#### Measured facts (primary sources, today)

- **OSV PyPI dump** (`gs://osv-vulnerabilities/PyPI/all.zip`, 38 MB): 27,101 records (12,114 MAL,
  8,025 PYSEC, 6,950 GHSA, 12 OSV; 642 withdrawn). 9,666 non-malware records carry a fix link
  (1,534 via `affected[].ranges[type=GIT]` with a `fixed` commit; 9,654 via `references[type=FIX]`
  or a `/commit/` `/pull/` URL). **CWE-918: 266 records, 179 with a fix link**; by publish year
  2019–2023: 27, 2024: 16, 2025: 13, **2026: 123** (AI-framework spike: langchain-core,
  chainlit, pydantic-ai, calibre-web, nltk, unoconv …). Top PyPI CWEs: 22 (539), 79 (519),
  400 (348), 20 (322), 200 (314), 94 (270), **918 (266)**, 502 (251), 770 (211), 78 (145).
- **PatchEval-Verified** (`patcheval/datasets/patcheval_verified.json`): 230 CVEs = Go 83, JS 77,
  **Python 70**; each row has `cve_id, cwe_info, repo, patch_url (fix commit), vul_func, fix_func,
  image_url` (ghcr.io image with the vulnerable repo + a strengthened PoC test, `fix-run.sh`).
  Python CWEs: 73/22 (15 each), 77/78/94 (11 each), 601/269/285/250 (6), 89 (5) … **CWE-918: 1**
  (CVE-2024-0243, langchain). Python CVE years 2015–2025, 11 in 2024, 3 in 2025.
- **Harbor registry** (`registry.json`, 80 datasets): no vulnerability/fix-commit dataset.
  Only security entry is `binary-audit` (46 tasks, backdoors in compiled binaries). Python
  repo-task precedents: `swebench-verified`, `swesmith`, `featurebench`, `swtbench-verified`.
- **Inspect Evals** (`src/inspect_evals/`): cyber evals are `cybench, cybergym, cve_bench
  (UIUC exploitation), cyberseceval_2/3/4, gdm_*_ctf, threecb, sevenllm, sec_qa, cti_realm,
  agent_threat_bench`. `cyberseceval_4` explicitly omits the autopatching prototype. No Python
  fix-commit dataset.

#### Candidates

| name | link | what it does | maint | lic | fit | kind | qual | switch | total | decision | reason |
|---|---|---|---|---|---|---|---|---|---|---|---|
| OSV.dev (API + GCS dump) | https://osv.dev · https://google.github.io/osv.dev/data/ | Aggregated advisory DB in OSV JSON; per-ecosystem zips, `modified_id.csv` for incremental sync, REST API | 2 (pushed 2026-11-26) | 2 (code Apache-2.0; PyPI data CC-BY-4.0 via GHSA/PYSEC) | 2 (266 CWE-918 PyPI, 179 with fix link) | 2 data | 2 (OpenSSF schema, API docs, wide use) | 2 (offline JSON zip; plan already names it) | 12 | **adopt** | Primary ingest source; one 38 MB zip, continuous export |
| GitHub Advisory Database | https://github.com/github/advisory-database | Curated GHSA records in OSV format, `database_specific.cwe_ids`, FIX references | 2 (pushed 2026-11-27) | 2 (CC-BY-4.0) | 2 (6,950 PyPI GHSA records with CWE ids) | 2 data | 2 | 2 (same JSON, arrives inside the OSV dump) | 12 | **adopt** | CWE labels + reviewed fix refs; consume via OSV mirror, raw repo as fallback |
| Harbor dataset registry | https://github.com/harbor-framework/harbor (`registry.json`) | Task-dir/`dataset.toml` format and 80 adapters; precedents for Python repo tasks | 2 (pushed 2026-11-25) | 2 (Apache-2.0) | 1 (format yes, no security data) | 2 infra | 2 | 2 | 11 | **adopt** | Format already decided; nothing to ingest, ours would be the first security dataset there |
| PatchEval / PatchEval-Verified | https://github.com/bytedance/PatchEval · HF `ByteDance/PatchEval` | 1,000 CVEs (Py/Go/JS) with fix commits; 230 dockerised with PoC-based `fix-run.sh` oracle | 2 (Verified 2026-07-24; pushed 2026-10-19) | 2 (Apache-2.0) | 2 (70 Python CVEs, fix commit + vuln/fixed function + runnable oracle) | 2 data + task images | 2 (paper 2511.11019, images on ghcr) | 1 (adapter to Harbor task dirs; ~2 GB/image, ≈150 GB for Python) | 11 | **adopt** (next class / held-out) | Only 1 CWE-918, so not Phase 1 primary; ready-made validation set for CWE-22/78/94 and the only Python set with linked tests |
| PyPA advisory-database | https://github.com/pypa/advisory-database | PYSEC YAML/OSV records for PyPI, community triage, GIT ranges on some | 2 (pushed 2026-11-25) | 2 (CC-BY-4.0) | 1 (8,025 records, mostly NVD-derived; adds GIT fixed ranges) | 2 data | 1 | 2 (inside OSV dump) | 10 | **adopt** via OSV | No separate ingest; source of most `GIT` fixed-commit ranges |
| NVD CVE API 2.0 | https://nvd.nist.gov/developers/vulnerabilities | Authoritative CVE records: CWE, CVSS, `Patch`-tagged references, published dates | 2 | 2 (US gov, public domain) | 1 (no ecosystem mapping; rate-limited: 5 req/30 s, 50 with key per NVD docs — page not fetchable here, from docs as known) | 2 data | 2 | 1 (adapter; key + throttling) | 10 | **adopt** (fallback only) | Fill CWE/date where a GHSA record lacks `cwe_ids`; not a primary feed |
| CVEfixes | https://github.com/secureIT-project/CVEfixes · Zenodo 10.5281/zenodo.4476563 | SQLite of CVE→fix commit→file→method, 27 languages incl. Python; v1.0.8 to 2024-07-23 | 1 (last push 2024-07-30) | 2 (MIT code, CC BY 4.0 data) | 1 (no tests; stale: misses the 2024–26 CWE-918 records) | 2 data | 2 (paper, many users, schema) | 1 (SQL dump join) | 9 | reference | Cross-check fix-commit links and per-file language tags for pre-2024 CVEs; OSV supersedes for ingest |
| CVEProject/cvelistV5 | https://github.com/CVEProject/cvelistV5 | Official CVE List as JSON 5 (CNA-supplied CWE + references) | 2 (pushed 2026-11-27) | 1 (CVE terms of use, no SPDX) | 1 | 2 data | 2 | 1 | 9 | reference | Redundant with NVD/GHSA for our fields |
| VulnerableCode (aboutcode) | https://github.com/aboutcode-org/vulnerablecode | Aggregator DB + API of vulnerabilities and fixed package versions | 2 (pushed 2026-11-27) | 2 (Apache-2.0) | 1 (package-version centric) | 2 | 1 | 1 | 9 | reference | OSV already aggregates the same sources |
| MoreFixes | https://github.com/JafarAkhondali/Morefixes · Zenodo 20776007 | CVEfixes successor: CVE→fix commits with confidence `score`, NVD 2.0 feeds, v4 2026-06-20 | 2 (pushed 2026-09-25) | 1 (MIT/Apache for modifications; Postgres dump licence not stated) | 1 (multi-language, no tests; counts not published in README) | 2 data | 1 (PROMISE 2024 paper) | 1 (Postgres dump) | 8 | reference | Use if OSV FIX refs miss commits for a CVE; verify Python share first |
| Inspect Evals (UK AISI) | https://github.com/UKGovernmentBEIS/inspect_evals | Eval collection; cyber evals are CTF/exploit/QA; `cyberseceval_4` omits autopatching | 2 (pushed 2026-11-26) | 2 (MIT) | 0 (no Python fix-commit data) | 2 infra | 2 | 0 | 8 | reference | Nothing to adopt for data; watch for a future patching eval |
| BountyBench | https://github.com/bountybench/bountybench · bountytasks | 40 real bounties on 25 systems; Detect/Exploit/Patch tasks; many Python targets (django, fastapi, gradio, mlflow, langchain, llama_index, vllm, gunicorn, setuptools, zipp…) | 1 (last push 2025-08) | 2 (Apache-2.0) | 1 (Detect+Patch fit; Exploit does not) | 1 mixed (data + own grader) | 2 (paper 2505.15216) | 1 (own harness, per-bounty containers) | 8 | reference | Mixed offensive/defensive; mine Python Patch tasks as a later held-out set via adapter |
| ARVO | https://github.com/n132/ARVO | 6,100+ reproducible OSS-Fuzz vulns, `-vul`/`-fix` images, located patches | 2 (pushed 2026-09-14) | 2 (BSD-2) | 0 (C/C++) | 2 | 2 | 0 | 8 | reject | C/C++ only, sanitizer crashes, no Python |
| AutoPatchBench (PurpleLlama / CyberSecEval 4) | https://github.com/meta-llama/PurpleLlama (CybersecurityBenchmarks/datasets/autopatch) | 142 (lite 120) C/C++ fuzzer-crash patching cases from ARVO; differential-fuzzing patch check | 2 (pushed 2026-11-20) | 2 (MIT for CybersecurityBenchmarks) | 0 (C/C++) | 1 (benchmark with its own patch verifier) | 2 | 0 | 7 | reference | C/C++; read its patch-verification design only |
| SEC-bench | https://github.com/SEC-bench/SEC-bench · HF `SEC-bench/SEC-bench` | 600 instances (eval 300 / cve 200 / oss 100), PoC + patch tasks, base/instance/eval images | 2 (pushed 2026-01-27) | 2 (MIT) | 0 (`lang` column: only `c++`) | 1 mixed | 2 (NeurIPS 2025) | 0 | 7 | reference | C/C++ only; image hierarchy is a model for our Harbor task images |
| PyVul | https://github.com/billquan/PyVul | 1,157 commit-level + 2,082 function-level Python vulns from GHSA/Huntr/Snyk, LLM-cleansed labels | 1 (pushed 2025-12-11, 7 stars) | 0 (no licence file) | 2 (Python-only, commit-level) | 2 | 1 (MSR 2026 paper; no tests) | 1 | 7 | reference | No licence; use only to cross-check our candidate list |
| Vul4J | https://github.com/tuhh-softsec/Vul4J | Reproducible Java vulns with PoC tests | 2 (pushed 2026-10-27) | 1 (GPL-3.0) | 0 (Java) | 2 | 2 | 0 | 7 | reject | Java |
| CleanVul | https://github.com/yikun-li/CleanVul | 8,092 LLM-filtered vuln-fix function pairs (Java/Py/C/C++/C#/JS) with commit URLs | 2 (pushed 2026-08-20) | 0 (no licence) | 1 | 2 | 1 | 1 | 7 | reject | No licence; function pairs, not repo tasks; test changes filtered out |
| Safety DB (pyup) | https://github.com/pyupio/safety-db | Curated insecure PyPI package versions | 2 (pushed 2026-11-01) | 0 (CC BY-NC-SA 4.0) | 1 | 2 | 1 | 1 | 7 | reject | Non-commercial licence; redundant with OSV |
| CrossVul | https://zenodo.org/records/4734050 | 5,131 CVEs / 40+ languages, file changes + commit messages (2021) | 0 (2021) | 2 (CC BY 4.0) | 1 | 2 | 1 | 1 | 7 | reject | Frozen 2021; superseded by OSV/CVEfixes |
| CyberGym | https://github.com/sunblaze-ucb/cybergym | PoC-generation tasks from ARVO/OSS-Fuzz | 2 | 2 (Apache-2.0) | 0 | 0 | 2 | 0 | 6 | reject | Offensive capability, not our target; C/C++ |
| CVE-Bench (UIUC, exploitation) + `inspect_evals/cve_bench` | https://github.com/uiuc-kang-lab/cve-bench | Web-app exploitation benchmark | 2 | 2 (Apache-2.0) | 0 | 0 | 2 | 0 | 6 | reject | Offensive capability, not our target |
| PrimeVul | https://github.com/DLVulDet/PrimeVul | C/C++ function-level detection dataset, paired vuln/patched functions | 0 (2024-09) | 2 (MIT) | 0 | 2 | 2 | 0 | 6 | reject | C/C++; function-level only |
| SecRepoBench | https://github.com/ai-sec-lab/SecRepoBench | 318 secure code-completion tasks in 27 C/C++ repos (from ARVO) | 2 (pushed 2026-09-03) | 2 (MIT) | 0 | 1 | 1 | 0 | 6 | reject | C/C++; code completion, not fix tasks |
| Big-Vul (MSR'20) | https://github.com/ZeoVan/MSR_20_Code_vulnerability_CSV_Dataset | C/C++ CVE code changes CSV | 0 (2021) | 2 (MIT) | 0 | 2 | 1 | 0 | 5 | reject | C/C++; dead since 2021 |
| Devign | https://github.com/epicosy/devign | C function-level vuln labels (graph NN) | 0 (2024-01) | 2 (MIT) | 0 | 2 | 1 | 0 | 5 | reject | C; no fix commits |
| MegaVul | https://github.com/Icyrockton/MegaVul | C/C++/Java function-level dataset | 1 (2025-01) | 1 (GPL-3.0) | 0 | 2 | 1 | 0 | 5 | reject | No Python; GPL |
| ReposVul | https://github.com/Eshe0922/ReposVul | 6,134 CVEs repo-level, C/C++/Java/Python, untangled patches | 0 (2024-11) | 0 (no licence file; badge points elsewhere) | 1 | 2 | 1 | 1 | 5 | reject | No licence, unmaintained |
| PySecDB | https://github.com/SunLab-GMU/PySecDB · HF `sunlab/PySecDB` | 1,258 Python security commits, 119 CWEs (ICSME'23) | 0 (2023-07) | 0 (gated, non-commercial) | 1 | 2 | 1 | 1 | 5 | reject | Gated non-commercial access |
| SecBench.js | https://github.com/cristianstaicu/SecBench.js | JS vulnerabilities with exploits | 2 (2026-08) | 0 (none) | 0 (JS) | 2 | 1 | 0 | 5 | reject | JavaScript |
| DiverseVul | https://github.com/wagner-group/diversevul | C/C++ function-level dataset (RAID'23) | 0 (2024-10) | 0 (no licence) | 0 | 2 | 2 | 0 | 4 | reject | C/C++; no licence |
| CVE-Bench (NAACL 2025 repair; Wang/Liu/Xiao) | https://aclanthology.org/2025.naacl-long.212 | 509 CVEs (Py/Java/JS/PHP from CVEfixes) in a repair environment | 0 (no code release found) | 0 | 2 | 1 | 1 | 0 | 4 | reference | Paper only; design reference for repair environments |
| VulnRepairEval | https://arxiv.org/abs/2509.03331 | 23 Python CVEs, PoC-based repair judgement | 0 (no code release found) | 0 | 2 | 1 | 1 | 0 | 4 | reference | Paper only; shows PoC-oracle yield (23 of 400+ CVEs) |
| AIxCC challenge projects | https://github.com/aixcc-public · Team-Atlanta/theori releases | DARPA AIxCC challenge repos (C, Java) and CRS code | 1 | 1 (mixed MIT/AGPL/none) | 0 | 1 | 1 | 0 | 4 | reference | C/Java; no Python targets |

#### Recommended for Phase 1

Ingest from the **OSV PyPI dump** (one zip, CC-BY-4.0) and treat **GHSA records** as the CWE
source; the dump alone yields 179 CWE-918 PyPI records with a fix link, three times the plan's
≥60 gate — but 123 of them were published in 2026 and cluster in AI-framework packages, so
stratify by library and use the 2024–25 cutoff bins the plan already has. Parse fix links from
`references[type=FIX]`/commit/PR URLs (only 1,534 of 9,666 fixed records use `GIT` ranges);
PR URLs need resolving to merge commits. **PatchEval-Verified** (Apache-2.0, 70 Python CVEs with
fix commits and runnable PoC oracles) is the only Python set with linked tests — adopt it as the
seed/held-out set for the next classes (CWE-22, 78/77, 94), not for CWE-918 (one record). NVD
is a fallback for CWE/date gaps only.

#### Gaps: nothing found for …

- A Python fix-commit dataset that **links the maintainers' tests** to the fix (PatchEval links
  PoC oracles, not upstream tests); `fix_test` must be derived from each fix commit's test diff.
- Any Harbor-registry or Inspect-Evals dataset of Python vulnerability-fix tasks.
- A public artifact for the two closest academic benchmarks (CVE-Bench NAACL repair,
  VulnRepairEval) or for RepoPairBench (100 Python vuln-fix pairs, DREA 2026 paper).
- A licensed Python-only commit-level dataset (PyVul has no licence; PySecDB is gated NC).
- CWE-918 Python tasks with pre-built containers from anyone; we build them.

### A.2 Static analysis, detectors, SCA, secrets, fuzzers (`survey-static.md`)

### Survey — static analysis, detectors, SCA, secrets, fuzzers (Python)

Component: non-LLM detectors usable (a) as tools an agent can call inside the Harbor sandbox and
(b) as **non-LLM baselines**, especially for the first class, P4 egress / SSRF (CWE-918).
Date: 2026-11-27. Every row verified against the project's own repo/docs today (GitHub API for
license + last push; README/LICENSE/rule sources read directly). Read-only; nothing installed.

Scoring per the shared rubric, 0–2 each: Maintained (M), License (L), Fit (F), Kind (K),
Quality (Q), Switching (S). "SSRF baseline" column: **YES** = taint/data-flow rule for CWE-918 with
a user-controlled source and an HTTP-client sink; **floor** = sink-only (no source), usable as the
naive lower bound; **no** = not applicable to SSRF.

#### Table (sorted by decision, then total)

| name | link | what it does | M | L | F | K | Q | S | total | SSRF baseline | decision | reason |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Semgrep CE + Community rules | github.com/semgrep/semgrep · github.com/semgrep/semgrep-rules | Pattern + single-function taint SAST; Python rules for CWE-918: `python.flask.security.injection.ssrf-requests`, `python.flask.security.injection.tainted-url-host` (mode: taint), `python.django.security.injection.ssrf.ssrf-injection-requests`, `ssrf-injection-urllib`, `python.django.security.injection.tainted-url-host` | 2 (pushed 2026-11-27) | 1 (engine LGPL-2.1; rules "Semgrep Rules License v1.0": internal use only, **no redistribution**) | 2 | 2 | 2 (4k commits, tests per rule, large user base) | 2 (already in use; JSON/SARIF) | 11 | **YES** (intra-file/intra-function only) | **adopt** | Primary SSRF baseline; already wired in. Fetch rules at run time (`--config p/python`); do **not** vendor `semgrep-rules` into the public repo. Pro rules + cross-file taint need a logged-in Semgrep Code account (free ≤10 contributors) — out of scope for an offline sandbox. |
| Bandit | github.com/PyCQA/bandit | AST pattern checks, no data flow; request-adjacent: B310 `urllib_urlopen` (scheme audit, tagged CWE-22), B113 request without timeout, B501 verify=False | 2 (2026-11-09) | 2 (Apache-2.0) | 1 | 2 | 2 | 2 (in use) | 11 | **floor** (sink enumeration, no source) | **adopt** | Keep as the naive sink-only lower bound and as the cheap "HTTP-call inventory" feed for the bare-model baseline. Not an SSRF detector on its own. |
| pip-audit | github.com/pypa/pip-audit | SCA for Python envs/requirements against PyPI Advisory DB or OSV; `--fix`; json/cyclonedx/markdown output | 2 (2026-11-27) | 2 (Apache-2.0) | 2 (SCA) | 2 | 2 (PyPA, Trail of Bits) | 2 (in use) | 12 | no | **adopt** | Already used; stays the dependency-vuln detector. Needs a resolvable requirements set — see osv-scanner note if that bites in containers. |
| Hypothesis | github.com/HypothesisWorks/hypothesis | Property-based testing library | 2 (2026-11-27) | 1 (MPL-2.0, file-level copyleft; fine as a dependency) | 1 | 2 | 2 | 2 (in use) | 10 | no (fix-side aid) | **adopt** | Already used. For P4 its role is on the fix grader: property-test proposed URL/host allowlist validators against generated host spellings and schemes, not detection. |
| Atheris | github.com/google/atheris | Coverage-guided fuzzing for Python + native extensions (libFuzzer); Python 3.11–3.14 | 1 (pushed 2026-06-17; last tag 3.0.0) | 2 (Apache-2.0) | 1 | 2 | 2 | 2 (in use) | 10 | no | **adopt** (keep) | Already used; irrelevant to SSRF (a design flaw, not a crash). Keep for parsing/memory classes. Needs LLVM on macOS; fine in Linux containers. |
| CodeQL (queries + CLI) | github.com/github/codeql · github.com/github/codeql-cli-binaries | Whole-program interprocedural taint SAST; Python `py/full-ssrf` (precision high, default suite) and `py/partial-ssrf` (precision medium, `python-security-extended.qls`), both CWE-918, path-problem output (source→sink) | 2 (2026-11-27) | 1 (queries MIT; **CLI is proprietary**: permitted for OSI-licensed codebases and "academic research"; automated/CI DB generation only for GitHub.com-hosted OSS; forbidden on non-OSS code; no hosting/redistribution) | 2 | 2 | 2 | 1 (per-repo `codeql database create --language=python`, ~1 GB install, minutes per repo; SARIF) | 10 | **YES** (strongest: cross-file) | **adopt** | Second, stronger SSRF baseline. Our corpus is OSS CVE-fix repos on GitHub, which the CLI terms cover; run it as a batch baseline, never inside a product or hosted service. Ship the CLI only into our own containers. |
| Pysa | github.com/meta/Pysa (moved out of archived facebook/pyre-check) | Interprocedural taint analysis for Python; stock rules 5012 "Potential SSRF" (UserControlled → HTTPClientRequest*) and 5053 (user data into URL-like string, partial SSRF); ships Django/Flask/requests models | 1 (pushed 2026-11-25 but mid-migration: 37 stars, no releases, still installed as `pip install pyre-check`, now requires Pyrefly) | 2 (MIT) | 2 | 2 | 1 (docs on pyre-check.org; migration churn) | 1 (needs `.pyre_configuration`, `pyrefly check` clean, taint model path; `pyre analyze` + SAPP for output) | 9 | **YES** (interprocedural; the only fully permissive-licensed one) | **adopt** (after a one-day spike) | Third independent SSRF baseline and the only one we could redistribute whole. Gate: if `pyrefly check` / `pyre analyze` fail on >25% of calibration repos, drop to reference. |
| OpenGrep | github.com/opengrep/opengrep | Fork of Semgrep CE 1.100 (Dec 2024) by Aikido, Endor Labs, Orca et al.; claims cross-function **and cross-file** taint; runs Semgrep-syntax rules | 2 (2026-11-27) | 1 (LGPL-2.1) | 2 | 2 | 1 (3.4k stars; inherited tests; young) | 2 (drop-in CLI for the same rules) | 10 | YES (cross-file, same rules) | reference | Cheapest A/B for "does cross-file taint change SSRF recall" with identical rules. Promote to adopt only if Semgrep CE intra-file misses show up in calibration. Its own rules fork (`opengrep-rules`) not verified. |
| Bearer CLI | github.com/Bearer/bearer | Data-flow SAST, Python supported; `python_lang_http_url_using_user_input` ("Unsanitized user input in HTTP request (SSRF)", CWE-918); SARIF | 2 (2026-11-27) | 1 (Elastic License 2.0: internal use OK, no hosted service, not OSI) | 2 | 2 | 1 (no paper; moderate tests) | 2 (single Go binary) | 10 | YES | reference | Fourth datapoint if wanted; non-OSI license keeps it out of the shipped toolkit. |
| Trivy | github.com/aquasecurity/trivy | SCA (fs/repo/container image), IaC misconfig, secrets, licenses, SBOM; json/sarif/cyclonedx | 2 (2026-11-27) | 2 (Apache-2.0) | 1 | 2 | 2 | 2 | 11 | no | reference | Not needed for P4. Candidate for the class-blind/router phase (one binary gives SCA + secrets + image scan of our own Harbor images). |
| osv-scanner | github.com/google/osv-scanner | Lockfile/SBOM/container scanning against OSV.dev; `--offline` local DB; guided remediation (experimental) | 2 (2026-11-26) | 2 (Apache-2.0) | 1 | 2 | 2 | 2 | 11 | no | reference | Overlaps pip-audit. Promote if pip-audit's need for a resolved environment is a problem inside containers (osv-scanner reads lockfiles offline). Call-graph reachability is not Python (unverified: docs say Go/Rust). |
| Grype + Syft | github.com/anchore/grype · github.com/anchore/syft | SBOM generation (Syft) + vuln matching (Grype); SARIF/cyclonedx/spdx | 2 (2026-11-27) | 2 (Apache-2.0) | 1 | 2 | 2 | 2 | 11 | no | reference | Same role as Trivy; pick one SBOM stack later, not now. |
| gitleaks | github.com/gitleaks/gitleaks | Regex/entropy secrets scanning of files and git history; json/csv/junit/sarif | 1 (feature-complete, "security patches only"; author moved to Betterleaks) | 2 (MIT) | 1 | 2 | 2 | 2 | 10 | no | reference | Adopt when the hardcoded-credentials class arrives; stable, offline, MIT. |
| TruffleHog | github.com/trufflesecurity/trufflehog | 800+ secret detectors with live credential verification | 2 (2026-11-25) | 1 (AGPL-3.0; fine as an invoked CLI) | 1 | 2 | 2 | 2 | 10 | no | reference | Verification makes outbound network calls — must run `--no-verification` in a no-egress sandbox. gitleaks is the simpler fit. |
| detect-secrets | github.com/Yelp/detect-secrets | Baseline-file secrets detection, pre-commit hook, 27 plugins | 1 (last release v1.5.0 2024-05; pushed 2026-04) | 2 (Apache-2.0) | 1 | 2 | 2 | 2 | 10 | no | reference | Designed for pre-commit baselines, not one-shot repo scans; slower cadence than gitleaks. |
| Joern | github.com/joernio/joern | Code-property-graph platform; `pysrc2cpg` Python frontend (docs: maturity High); taint via CPGQL queries | 2 (2026-11-27) | 2 (Apache-2.0) | 1 | 2 | 1 (querydb has no Python scanners; SSRF query would be hand-written) | 0 (JVM, Scala query language) | 8 | possible, but unwritten | reference | Research-grade platform; no stock Python SSRF query, so it competes for our build time. |
| Pyrefly | github.com/pyrefly-org/pyrefly | Meta's Rust type checker (replaces Pyre); Pysa's type provider | 2 (2026-11-27) | 2 (MIT) | 0 | 2 | 2 | 1 | 9 | no | reference | Only as Pysa's dependency. No security rules. |
| OpenSSF Scorecard | github.com/ossf/scorecard | Repo-hygiene score (branch protection, pinned deps, fuzzing, SAST present) | 2 (2026-11-27) | 2 (Apache-2.0) | 0 | 2 | 2 | 2 | 10 | no | reference | Not detection; possible covariate when choosing/characterizing calibration repos. |
| OSS-Fuzz | github.com/google/oss-fuzz | Google's continuous fuzzing infrastructure; Python projects via Atheris | 2 (2026-11-27) | 2 (Apache-2.0) | 0 | 2 | 2 | 0 | 8 | no | reference | Its Python project harnesses are the worked examples for Atheris; the cluster itself is irrelevant. |
| ruff S-rules (flake8-bandit) | github.com/astral-sh/ruff · docs.astral.sh/ruff/rules | Ports of Bandit checks (S310, S113, S501…); no data flow | 2 (2026-11-27) | 2 (MIT) | 1 | 2 | 2 | 2 | 11 | floor | reject | Redundant with Bandit, which we already run and which has more plugins. Same sink-only signal twice buys nothing. |
| Snyk Code | github.com/snyk/cli · docs.snyk.io | Proprietary cloud SAST; Python supported (45 rules incl. "Server-Side Request Forgery (SSRF)", CWE-918); CLI Apache-2.0 | 2 | 0 (engine proprietary SaaS; Free plan 100 Code tests/month, 5 projects) | 2 | 2 | 1 (closed, no paper) | 1 (account + network from inside the sandbox) | 8 | YES, but | reject | Cloud-only engine needs credentials and egress from the sandbox and 100 tests/month is below one k=3 calibration run. |
| SonarQube Community Build | github.com/SonarSource/sonarqube | Self-hosted code-quality server; Python rules | 2 (2026-11-27) | 1 (LGPL-3.0) | 0 | 2 | 2 | 0 (server + scanner + DB) | 7 | no | reject | Taint analysis ("cross-function and cross-file tracking", SSRF rule S5144) is listed only for Developer/Enterprise on the pricing comparison; Community Build is not in that table. No SSRF signal without a paid edition. |
| Dlint | github.com/dlint-py/dlint | flake8 security plugin (e.g. `bad_requests_use` for verify=False, urllib3 misuse) | 1 (2026-10-20; 179 stars) | 2 (BSD-3) | 0 | 2 | 1 | 2 | 8 | no | reject | No SSRF-relevant rule; subsumed by Bandit. |
| safety (pyup) | github.com/pyupio/safety | SCA against pyup DB | 2 (2026-11-05) | 1 (Apache/MIT code, but 3.x CLI requires a pyup account for the DB) | 1 | 2 | 1 | 1 | 8 | no | reject | Account-gated data; pip-audit covers the need with open data. |
| pyright | github.com/microsoft/pyright | Type checker | 2 | 2 (MIT) | 0 | 2 | 2 | 2 | 10 | no | reject | No security rules and no pyright-based security tool found; type info for Pysa comes from Pyrefly. |
| Pyre | github.com/facebook/pyre-check | Type checker (archived 2026-06-26) | 0 (archived) | 2 (MIT) | 0 | 2 | 1 | 0 | 5 | no | reject | Archived; replaced by Pyrefly. Pysa moved to its own repo (see above). |
| pyt (python-taint) | github.com/python-security/pyt | CFG/dataflow taint for Flask/Django, claims SSRF detection | 0 (README: "no longer maintained"; last push 2020-12) | 1 (GPL-2.0) | 2 | 2 | 1 | 1 | 7 | historically YES | reject | Dead for five years; superseded by Pysa. |

#### Recommended for Phase 1

Run **three non-LLM SSRF baselines** over the same calibration tasks, all offline in the Harbor
container, graded by the same recall grader as the agents: **Semgrep CE** (`p/python`, intra-file
taint; already wired), **CodeQL** (`py/full-ssrf` + `py/partial-ssrf` via `python-security-extended`,
interprocedural; OSS-corpus and research use are inside the CLI terms), and **Bandit** as the
sink-only floor. Spike **Pysa** for one day; it is the only interprocedural engine with a stock SSRF
rule under a license we could ship. Keep pip-audit, Hypothesis and Atheris as they are.

#### Gaps: nothing found for …

- A permissive-licensed, *cross-file* taint engine with a stock Python SSRF rule that is already
  stable: CodeQL's CLI terms are restrictive, Semgrep's cross-file taint is paid, Pysa is mid-migration,
  OpenGrep is young. Pysa is the closest.
- Any pyright-based security tooling (none exists).
- A Python SSRF *benchmark* that these tools have been scored against (the baselines will have to
  be scored on our calibration set; no prior numbers to compare to).
- A fuzzing approach relevant to SSRF (none; it is a design flaw, not a crash class).
- SonarQube/Snyk-class taint analysis that runs without a server, an account or egress.

### A.3 Agent harnesses, scaffolds and baseline agents (`survey-harness.md`)

### Survey — agent harnesses, scaffolds and baseline agents

Component: harnesses / scaffolds / baseline agents for a Harbor-based security-agent eval.
Verified 2026-11-27 against each project's repo (GitHub API: license, last push, releases,
commits since 2026-05-27) and its own docs. Scores 0–2 per rubric criterion; total /12.
"Baseline on Harbor" = can be run as `harbor run -a <id>` on our tasks today.

| name | link | what it does | maint. | license | fit | kind | quality | switching | total | decision | reason |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Harbor | github.com/harbor-framework/harbor | Task format + sandbox + runner + 45 pre-integrated agents + ATIF trajectories + dataset registry | 2 (v0.27.0 2026-11-21; push 11-25) | 2 Apache-2.0 | 2 | 2 infra | 2 (docs, tests, 80-dataset registry, Terminal-Bench lineage) | 2 adopted | 12 | adopt | Already the task/sandbox/runner layer; confirmed agent list below |
| mini-swe-agent | github.com/SWE-agent/mini-swe-agent | Bash-only, one-command-per-step, model-agnostic (LiteLLM) coding agent | 2 (v2.4.6; 41 commits/6 mo; push 11-23) | 2 MIT | 2 | 2 baseline | 2 (SWE-bench Verified >74%, docs, tests) | 2 `-a mini-swe-agent` pre-integrated | 12 | adopt | Primary same-model generic baseline; ACI is one documented bash action, nothing to argue about |
| OpenHands / OpenHands SDK | github.com/All-Hands-AI/OpenHands, github.com/All-Hands-AI/agent-sdk | Full-featured autonomous coding agent (terminal, file editor, task tracker, browser) | 2 (v1.46.0 / SDK v1.64.1, 2026-11-25) | 2 MIT | 2 | 2 baseline | 2 (94k stars, docs, tests, tool API documented) | 2 `-a openhands` / `-a openhands-sdk` | 12 | adopt | Heavyweight generic baseline; use `--install-only` image because the venv install is slow |
| Terminus-2 (in Harbor) | harbor/src/harbor/agents/terminus_2 | Harbor's reference *external* agent: loop outside the box, tmux session, LiteLLM, writes ATIF | 2 (ships with Harbor) | 2 Apache-2.0 | 2 | 2 baseline + template | 1 (code + tests; no dedicated doc page in llms.txt) | 2 `-a terminus-2` | 11 | adopt | Template for our `BaseAgent` reader/actor agent and a third baseline for free |
| SWE-agent | github.com/SWE-agent/SWE-agent | YAML-configured agent with documented ACI tool bundles (bin/ + config.yaml + install.sh), SWE-ReX docker runtime | 1 (self-declared maintenance-only; 24 commits/6 mo; last release v1.1.0 2025-05) | 2 MIT | 2 | 2 baseline | 2 (NeurIPS 2024, docs, tests) | 2 `-a swe-agent` (clone at revision) | 11 | reference | Superseded by mini-swe-agent per its own docs; run only for a "classic ACI" ablation. Has an offensive CTF mode (EnIGMA) — not our target |
| Terminal-Bench 2.0 / 4.1 | github.com/harbor-framework/terminal-bench (old laude-institute repo frozen) | Terminal task suite that runs on Harbor; `terminal-bench@2.0`, `terminal-bench-pro@1.0`, `terminal-bench-sample@2.0` in registry | 2 (new repo push 11-27; old repo 1 commit/6 mo) | 2 Apache-2.0 | 1 | 2 data | 2 | 2 `harbor run -d terminal-bench-sample@2.0` | 11 | reference | Design reference for task authoring; `terminal-bench-sample@2.0` is the one-command smoke test that our runner + baselines work. Not security data |
| LangGraph | github.com/langchain-ai/langgraph | Graph orchestration for agents; Harbor runs a user-supplied Python/JS graph inside the container | 2 (cli 0.4.44 2026-11-25) | 2 MIT | 1 | 1 mixed | 2 | 2 `-a langgraph` | 10 | reference | Orchestration we don't need for a single-agent loop; graph runs inside the box (loop-in-box). Revisit for multi-class composition only |
| Inspect AI | github.com/UKGovernmentBEIS/inspect_ai | UK AISI eval framework: sandboxes (docker/k8s/modal/daytona), scorers, react agent, agent bridge, human agent, limits | 2 (0.3.292 2026-11-23; push 11-27) | 2 MIT | 1 | 2 infra | 2 (docs, tests, AISI users) | 0 (same layer as Harbor; re-architecture) | 9 | reference | Direct competitor to Harbor at the runner layer; borrow patterns (below), do not depend |
| Claude Agent SDK | github.com/anthropics/claude-agent-sdk-python | Claude Code's loop as a library (bundled CLI; Read/Write/Edit/Bash/Glob/Grep; MCP tools; hooks; permissions; subagents) | 2 (v0.2.189 2026-11-25) | 2 MIT pkg (use governed by Anthropic Commercial Terms) | 1 | 1 mixed | 2 | 1 (external loop would need MCP tools over `environment.exec`) | 9 | reference | Baseline already covered by Harbor's `-a claude-code`; building our class agents on it means provider lock-in and loop-in-box |
| OpenAI Agents SDK | github.com/openai/openai-agents-python | Agent/Runner/handoffs/guardrails/sessions/tracing; LiteLLM adapter; sandbox agents (local unix, docker) | 2 (v0.26.0 2026-11-24) | 2 MIT | 1 | 1 mixed | 2 | 1 (not Harbor-integrated; BaseAgent wrapper needed) | 9 | reference | OpenAI-centric; nothing Harbor + LiteLLM don't already give. Guardrails pattern worth reading |
| Inspect SWE | github.com/meridianlabs-ai/inspect_swe | Runs claude_code / codex_cli / gemini_cli / kimi_code / opencode / mini_swe_agent / antigravity inside an Inspect sandbox with model calls proxied to the host | 2 (495 commits) | 2 MIT | 1 | 2 baseline | 1 (43 stars, no tagged release) | 0 (needs Inspect) | 8 | reference | Same idea as Harbor's installed agents; its key-stays-on-host proxy is the pattern to borrow |
| Inspect Evals | github.com/UKGovernmentBEIS/inspect_evals | Eval collection incl. cyber evals (CyBench, GDM capability evals; CTF-style, Dockerised) | 2 (push 11-26) | 2 MIT | 0 | 2 data | 2 | 0 | 8 | reference | Not a harness; its cyber evals are offensive-capability measures, not our target. Pointer for the datasets component only |
| BrowserGym | github.com/ServiceNow/BrowserGym | Gym env for web tasks; wraps MiniWoB/WebArena/WorkArena/AssistantBench; AgentLab companion | 1 (7 commits/6 mo; push 11-18) | 2 Apache-2.0 (LICENSE file; GitHub API shows NOASSERTION) | 0 | 2 infra | 2 | 0 | 7 | reference | Web domain. Design lesson: benchmark = `AbstractBrowserTask` subclass, env/agent/benchmark cleanly separated |
| WebArena | github.com/web-arena-x/webarena | Self-hosted web sites + 812 tasks; accessibility-tree obs; per-example config with functional evaluators | 0 (0 commits/6 mo; canonical frozen impl, points to AgentLab) | 2 Apache-2.0 | 0 | 2 data | 2 | 0 | 6 | reference | Frozen. Design lesson: one evaluator config per task, several evaluator types — matches our per-task `reward.json` grader plan |
| Aider | github.com/Aider-AI/aider | Terminal pair-programming editor; `--message`/`--yes` non-interactive; Python API explicitly unsupported | 1 (0 commits since 2026-05-22; last release v0.86.0 2025-08) | 2 Apache-2.0 | 1 | 2 baseline | 2 (polyglot benchmark, docs) | 2 `-a aider` (installs *latest* via curl script, unpinned) | 10 | reject | Stalled 6 months; edit-oriented, needs named files, not an exploring agent; Harbor adapter installs an unpinned latest |
| smolagents | github.com/huggingface/smolagents | CodeAgent (actions written as Python code) + ToolCallingAgent; sandboxes via E2B/Docker/Modal | 2 (39 commits/6 mo; last release v1.26.0 2026-05-29) | 2 Apache-2.0 | 0 | 1 mixed | 2 | 1 (no Harbor adapter) | 8 | reject | Code-as-action design, no terminal/repo agent, no Harbor integration; executing model-written code is the opposite of our containment stance |

#### Per-candidate notes (baseline on Harbor? · ACI documented? · license · maintenance)

**Harbor pre-integrated agents (docs.harborframework.com/agents/pre-integrated-agents.md, confirmed
against `src/harbor/models/agent/name.py` at v0.27.0).** 45 ids: `oracle nop acp claude-code
cline-cli cortex-code terminus terminus-1 terminus-2 aider codex cursor-cli gemini-cli
antigravity-cli rovodev-cli goose grok-build hermes junie mini-swe-agent nemo-agent swe-agent
opencode openclaw openhands openhands-sdk antigravity-sdk kimi-code kimi-cli langgraph deerflow
mimo mcode pi qwen-coder copilot-cli code-puppy devin trae-agent computer-1 eve fx fx-dev dspy-rlm
vibe muse-code strands fabric opencode-v2 kiro-cli`. **No default versions are pinned in the
docs.** Each `BaseInstalledAgent` takes a `version` kwarg (`--ak version=…`); when none is given
it installs latest, or reuses what the image already has (`claude-code`, `codex`, `opencode`).
Only the ACP bridge adapters are pinned in source (claude-code ACP 0.16.2, codex ACP 1.12.0).
Install paths seen in source: mini-swe-agent `uv tool install --python 3.12 mini-swe-agent[==v]`;
openhands-sdk `uv` venv at `/opt/openhands-sdk-venv` (python 3.12); openhands venv python 3.13;
swe-agent `git clone … revision=<version>` into `/opt/sweagent-venv`; aider `curl aider.chat/install.sh`
(latest, no pin); claude-code `npm install -g @anthropic-ai/claude-code`. ATIF converters:
swe-agent emits ATIF-v1.5, mini-swe-agent ATIF-v1.7; current schema is **ATIF-v1.8** (v1.0–v1.8
accepted; agent writes `self.logs_dir / "trajectory.json"` with `capabilities.atif = true`;
validate with `python -m harbor.utils.trajectory_validator`). Custom agents: `--agent
module.path:ClassName`; `BaseAgent` (external loop, `environment.exec`) implements `name()`,
`version()`, `setup()`, `run(instruction, environment, context)`; `BaseInstalledAgent` implements
`install()` (image-bakeable) + `configure()` (per-trial) + `run()`. Example: `examples/agents/marker_agent.py`.
Harbor's own LLM client is `harbor.llms.lite_llm.LiteLLM` + `harbor.llms.chat.Chat` (used by Terminus-2).
Also in the tree: `rewardkit` (judge criteria for verifiers) — overlaps our grader contribution, reference only.

- **mini-swe-agent** — baseline: yes (`-a mini-swe-agent`, kwargs `version`, `config_file`,
  `cost_limit`, `max_tokens`, litellm model registry). ACI: documented and trivially small — bash
  only, no function calling, linear history; system prompt via YAML. MIT. Active (v2.4.6 tagged,
  41 commits in 6 months, push 2026-11-23).
- **OpenHands / agent-sdk** — baseline: yes (`-a openhands` headless CLI; `-a openhands-sdk`
  with `config`, `skill_paths`, `max_iterations`). ACI: documented (Action / Observation /
  Executor / `ToolDefinition`; built-ins `TerminalTool`, `FileEditorTool`, `TaskTrackerTool`,
  `BashTool`, `get_default_tools()`; workspaces local/docker/k8s/remote). MIT. Very active.
- **Terminus-2** — baseline: yes (`-a terminus-2`). ACI: tmux terminal with XML/JSON command
  parsers, source-documented. Apache-2.0 (Harbor). Maintained with Harbor.
- **SWE-agent** — baseline: yes (`-a swe-agent`, `SWEAGENT_CONFIG` for native YAML). ACI: the
  best-documented of all (tool bundles: `bin/`, `config.yaml`, `install.sh`, `state_command`;
  windowed file viewer, search, search-and-replace editors). MIT. Maintenance-only by its own
  statement, though still committed to (24 commits/6 mo).
- **Aider** — baseline: yes (`-a aider`, unpinned install). ACI: edit formats documented;
  scripting via `--message`, `--yes`; Python API "not officially supported". Apache-2.0.
  **No commits since 2026-05-22**, last release 2025-08.
- **Claude Agent SDK** — baseline: via Harbor's `-a claude-code`, not via the SDK. ACI: Claude
  Code toolset (Read/Write/Edit/Bash/Glob/Grep/WebSearch), MCP custom tools, hooks, permission
  modes; `pip install claude-agent-sdk` bundles the CLI; Python ≥3.10. MIT package, Anthropic
  Commercial Terms govern use. Active (v0.2.189, 2026-11-25). Claude models only.
- **OpenAI Agents SDK** — baseline: no Harbor adapter (would need a `BaseAgent` wrapper). ACI:
  function tools + hosted tools + sandbox agents (unix local / docker). MIT. Active (v0.26.0).
- **smolagents** — baseline: no Harbor adapter. ACI: `@tool` functions; CodeAgent writes Python.
  Apache-2.0. Commits active, last tagged release 2026-05-29.
- **LangGraph** — baseline: yes (`-a langgraph`, runs your graph file in-container, Python or
  Node). ACI: none of its own (you bring tools). MIT. Active.
- **Inspect AI** — baseline: not on Harbor; it *is* a runner. Sandboxes: docker/local/k8s/
  modal/daytona/openshell/proxmox/vagrant; `network_mode: none` by default; `exec` output cap
  10 MB front-truncated; `SandboxTimeoutError.reason` distinguishes program overrun from sandbox
  failure. Scorers: `@scorer(metrics=[…])`, `Score(value, answer, explanation, reason, metadata)`,
  `Value` may be a dict, `Score.unscored()` for NaN, epoch reducers. Agents: `react()`, agent
  bridge (`agent_bridge` in-process; `sandbox_agent_bridge` = loopback proxy inside the
  container so API keys never enter the box), human agent for human baselining. MIT, active.
- **Inspect SWE** — the Inspect analogue of Harbor's installed agents (claude_code, codex_cli,
  gemini_cli, kimi_code, opencode, mini_swe_agent, antigravity). MIT, small project.
- **Terminal-Bench** — baseline: it is data; `harbor run -d terminal-bench-sample@2.0 -a <agent>`.
  tbench.ai now documents 4.1.0 via `harbor run -d terminal-bench/terminal-bench@4.1.0`; the old
  `tb` CLI repo (laude-institute) has 1 commit in 6 months and points to Harbor. Apache-2.0.
- **BrowserGym / WebArena** — web harnesses, design reference only. BrowserGym Apache-2.0 (LICENSE
  file), light maintenance; WebArena Apache-2.0, frozen since 2025-11 and itself recommends
  AgentLab/BrowserGym. Lesson kept: task = config + evaluator(s); env/agent/benchmark separated.

#### What to borrow from Inspect without adopting it

1. `sandbox_agent_bridge` pattern: model API keys stay on the host, the agent in the box talks to
   a loopback proxy. Harbor's installed agents instead receive keys inside the container via auth
   resolution; our external `BaseAgent` keeps keys outside by construction — keep it that way, and
   run our agent phase `no-network` while baselines need `allowlist` (record this as a condition
   difference).
2. `Score` shape: `value` (dict allowed) + `answer` + `explanation` + `reason` + `metadata`, and an
   explicit "unscored" state excluded from metrics — mirror in `reward.json`.
3. Timeout classification (program overrun vs sandbox failure) and output-truncation caps as
   first-class grader inputs, so a hung test is never scored as a miss.
4. Human-agent baseline for human calibration of a sealed slice, later.
5. Pin image digests, not tags, for reproducibility.

#### Recommended for Phase 1

Harbor as adopted; baselines `mini-swe-agent` (same model as our agent → isolates the agent spec
from the model), `openhands-sdk` (heavyweight generic), `claude-code` (vendor agent), plus Harbor's
free controls `oracle` (runs `solution/solve.sh` → validity gate on every task) and `nop` (does
nothing → the grader's false-positive floor and the recall-of-zero sanity check). Write our class
agents as `BaseAgent` modelled on Terminus-2 (external loop, `environment.exec`, ATIF v1.8).
Always pass `--ak version=…` and `--model` explicitly, and bake baselines with `--install-only`.

#### Gaps

Nothing found for: a Python-first *external-loop* (keys-outside-the-box) agent on Harbor other than
Terminus-2 — every other pre-integrated agent runs its loop inside the container; a pre-integrated
agent with a documented minimal file-viewer/search ACI that is still actively developed (SWE-agent
has it but is maintenance-only; mini-swe-agent dropped it on purpose); any harness-level security
baseline (none of the 45 agents is security-specialised — that is the contribution, as intended).
Side finding for the datasets component: Harbor registry has `binary-audit@1.0` (backdoor-finding in
compiled binaries), and Python repo-repair sets in Harbor format (`swebench-verified`, `swesmith`,
`humanevalfix`, `quixbugs`, `swtbench-verified`) that are good task-format exemplars for `build.py`.

### A.4 Verifiers, graders and security eval suites (`survey-verifiers.md`)

### Survey: verifiers, graders and security eval suites

Component: VERIFIERS, GRADERS AND SECURITY EVAL SUITES. Surveyed 2026-11-27 against each
project's own repo/docs (GitHub API for license, last push and latest release; docs pages for
grading mechanics). Scores follow the shared rubric: six criteria 0–2, total /12. "Grader"
column says whether verdicts come from code (deterministic) or from a model judge.

Context for fit: our verifier runs in Harbor's separate sandbox and writes `reward.json` with
recall / FPR / fix / claim fidelity / scope for Python repositories. Our P8 class is
LLM-separation: an instruction embedded in untrusted content must never change the output of
*our own* apps; we already own a canary-based harness (`promptinject/`). Our `evals/mutate.py`
is fix-reversion mutation testing (does the security regression net catch a reintroduced bug).

#### Table

| name | link | what it does | grader | maintained | license | fit | kind | quality | switching | total | decision | reason |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| Harbor RewardKit (`harbor-rewardkit` 0.2.4) | https://docs.harborframework.com/rewardkit/quick-start · `packages/rewardkit` in harbor-framework/harbor | Verifier toolkit for Harbor tasks: `rewardkit /tests` runs weighted criteria (files, commands, JSON/CSV/SQLite, HTTP, ATIF trajectory) in parallel, optional overlayfs isolation, unprivileged `Worker` for untrusted code, writes `/logs/verifier/reward.json` + `reward-details.json`; multi-reward via subdirectories | both: programmatic criteria are code; judge criteria (TOML) are LLM/agent judges with `samples`/median, `agreement`, `guard` against grader-injection | 2 (harbor pushed 2026-11-25, v0.27.0 2026-11-21) | 2 (Apache-2.0, own LICENSE file) | 2 (exactly the reward-writing layer our graders sit on; multi-reward dirs map to recall/fpr/fix/claim/scope) | 2 (infrastructure) | 2 (docs, tutorial, examples, in-repo tests; young package, v0.2.x) | 2 (our graders become `@criterion` functions; `command_succeeds` wraps the fix-test run) | 12 | **adopt** | Reward plumbing is theirs; we write only the security criteria. Pin the version; keep graders pure functions so a 0.x API move costs one adapter. Python >= 3.12. |
| SWE-bench Verified (methodology + dataset) | https://openai.com/index/introducing-swe-bench-verified/ · HF `princeton-nlp/SWE-bench_Verified` · Harbor registry `swebench-verified 1.0` (500 tasks) | Human-validated 500-task subset: 1,699 samples, 3 annotators each, 0–3 rubrics for *underspecified issue* and *unfair tests*, drop at score >= 2 or any "other major issue" flag; 68.3% filtered. Grading is FAIL_TO_PASS / PASS_TO_PASS unit tests | deterministic (tests) | 2 (Harbor adapter maintained; SWE-bench repo active) | 2 (SWE-bench MIT; dataset card states no license — note) | 2 (the validity-gate design we need for our advisory tasks: two rubric axes, severity threshold, multiple raters, difficulty recorded but not used to filter) | 2 (data + methodology; Harbor adapter is infrastructure) | 2 (paper, public annotations, widely used) | 2 (methodology is copied, not installed; Harbor already ships the dataset) | 12 | **adopt (methodology)** | Use its rubric for our validity gate: "underspecified advisory" and "unfair hidden test" scored 0–3 by two raters, keep <= 1. Not a security dataset. |
| Meta CyberSecEval 4 — Insecure Code Detector (ICD) and FRR | https://github.com/meta-llama/PurpleLlama/tree/main/CybersecurityBenchmarks | Suite of LLM cyber-risk benchmarks. Defensive-usable pieces: ICD (bundled semgrep + regex rules keyed to CWEs, 8 languages incl. Python) grades *insecure code generation* (instruct/autocomplete); MITRE-FRR grades over-refusal by regex. Also: prompt-injection set (textual + visual), interpreter abuse, spear phishing, AutoPatchBench (C/C++ fuzz-crash repair), CyberSOCEval MCQ | mixed: ICD, FRR, canary exploit, AutoPatch, CyberSOCEval deterministic; MITRE, prompt injection, interpreter abuse, phishing = LLM judge | 1 (commits to the dir through 2026-11-13, but a June-2025 note says the project "may change significantly"; ICD benchmarks removed from the default run list; 99 open issues) | 2 (MIT, `CybersecurityBenchmarks/LICENSE`) | 1 (grades *generated snippets*, not repository findings; ICD rules are a reusable CWE-pattern oracle; prompt-injection grading is model-judged, the opposite of our P8 design) | 1 (data + a rule set we could reuse; the prompt-injection judge is a competing grader) | 2 (papers CSE 1–4, tests, large user base) | 1 (ICD rules extractable as semgrep; test data is JSON prompts, not Harbor tasks) | 8 | **reference** | Read ICD's CWE rule set as a sibling of our semgrep rules and as a sanity oracle on agent-proposed fixes; its prompt-injection tests target base models with a judge, not our canary-in-app design. |
| Inspect Evals — CodeIPI (`ipi_coding_agent`) | https://github.com/UKGovernmentBEIS/inspect_evals/tree/main/src/inspect_evals/ipi_coding_agent | 45 tasks (35 injected via issue text / code comments / README / config, 10 benign): does a coding agent follow planted instructions while fixing a Python bug. Reports injection-resistance, task completion and FPR on clean tasks | mostly deterministic (canary in output/tool calls, `CANARY_EXEC_<id>` marker, SHA-256 of workspace files); one `model_graded_qa` only for the "did it flag the injection" metric | 2 (inspect_evals v0.30.0 2026-11-23, pushed 2026-11-26) | 2 (MIT) | 2 (P8-shaped: canary + negative controls + FPR, agent in sandbox, Python/pytest) | 1 (data + grader design; grader overlaps our P8 harness) | 1 (new eval, no paper cited, small n) | 1 (Inspect task format; porting 45 samples into Harbor task dirs is an adapter) | 9 | **reference → candidate data for P8** | Closest public analogue of our P8 positive/negative task design; borrow its three deterministic attack-success checks and its benign-control ratio. Dataset license not stated in README — check before copying samples. |
| Inspect Evals — AgentDojo (and ethz-spylab/agentdojo) | https://github.com/ethz-spylab/agentdojo · `inspect_evals/agentdojo` | Prompt-injection benchmark for tool-using agents: 98 user tasks / 36 injection tasks across Workspace+, Slack, Travel, Banking; metrics benign utility, utility under attack, targeted ASR | deterministic (formal utility functions check environment state, explicitly not LLM judges) | 1 (upstream last push 2026-06-02; Inspect port current) | 2 (MIT) | 1 (adjacent: grades the *agent* being attacked, we grade an agent that *finds* unhardened sinks; its utility-vs-security pairing matches our P8 "utility alongside safety" metric) | 2 (data + infra) | 2 (NeurIPS 2024 D&B, tests, 1.1k stars) | 1 (own env model; adapter needed) | 9 | **reference** | Steal the measurement shape (utility, utility-under-attack, ASR on one table); not a source of Python-repo tasks. |
| Inspect Evals — AgentThreatBench | `inspect_evals/agent_threat_bench` | 24 scenarios mapping OWASP Agentic Top-10 (ASI01 goal hijack, ASI06 memory poisoning) with clean baselines; utility and security each 0/1 | deterministic (rule checks on answers, tool calls, recipients) | 2 (in current release) | 2 (MIT) | 1 (adjacent to P8; targets agent behaviour not code) | 2 (data) | 1 (community contribution, no paper) | 1 (Inspect format) | 9 | **reference** | Same reason as AgentDojo, smaller and newer. |
| Inspect Evals — PatchEval (external, bytedance/PatchEval pinned c8cc29e) | https://github.com/bytedance/PatchEval · `register/patcheval` | Automated vulnerability repair on 230 real CVEs (2015–2025) in Python, JavaScript, Go; agent submits a unified diff; `fix-run.sh` runs PoC security tests + functionality tests, both must pass | deterministic (tests) | 2 (pushed 2026-10-19) | 2 (Apache-2.0) | 2 (exactly our *fix* grader shape on advisory-derived tasks; the Python subset is a ready-made fix-rate baseline set, and its PoC tests are candidate hidden tests) | 2 (data + baseline) | 2 (paper, dockerized "verified" subset, 240 stars) | 1 (own harness; convert per-CVE Docker + tests into Harbor task dirs) | 11 | **adopt (data, later phase)** | Pull the Python CVEs that fall in a class we are measuring (check P4/CWE-918 count); its PoC test is a fix oracle we did not have to write. Not for Phase 1 P4 unless the CWE-918 count is non-trivial. Contamination: all public, need the disclosure-date split. |
| Inspect Evals — CyberGym | https://github.com/sunblaze-ucb/cybergym · `inspect_evals/cybergym` | 1,507 instances from 188 OSS-Fuzz/ARVO projects: given a description, produce a PoC that crashes the vulnerable build; "new vuln" if it also crashes the fixed build | deterministic (routes PoC to vulnerable and fixed builds) | 1 (pushed 2026-08-28) | 2 (Apache-2.0) | 0 (PoC generation on C/C++ fuzz targets; exploit-adjacent, not Python detection) | 2 | 2 (paper, 1k stars) | 0 | 7 | **reject** | Offensive-leaning capability (PoC generation), C/C++ fuzz corpus, not our target. |
| Inspect Evals — CASTLE (external, AI-Sec-dev/inspect-eval-castle) | `register/castle` | Vulnerability *detection* on 250 hand-written C programs, 25 CWEs, 6 vulnerable + 4 clean per CWE; model returns JSON (present? CWE); points +5 TP, +2 TN, −1 per FP; TPR/FPR reported | deterministic (rule scoring) | 1 (pushed 2026-08-04, 0 stars) | 2 (MIT) | 1 (defensive detection with negative controls and FPR — our metric shape — but C, synthetic, single-file) | 2 (data) | 1 (paper; tiny tooling) | 0 (not repo tasks) | 7 | **reference** | Its 6:4 vulnerable:clean ratio and penalised-FP scoring are a precedent for our FPR metric; wrong language. |
| Inspect Evals — Cybench | `inspect_evals/cybench` | 39 professional CTF challenges in a Kali sandbox with network; proportion solved | deterministic (flag) | 2 | 2 (MIT) | 0 | 2 | 2 | 0 | 8 | **reject** | Offensive capability, not our target. |
| Inspect Evals — CVE-Bench, 3CB, GDM CTFs, InterCode-CTF, ExploitBench, TarantuBench, b3, MCPTox | https://ukgovernmentbeis.github.io/inspect_evals/ | Exploitation / CTF / attack-success evals (MCPTox is model-judged ASR; ExploitBench explicitly deterministic) | mostly deterministic; MCPTox LLM judge | 2 | 2 (MIT) | 0 | 2 | 2 | 0 | 8 | **reject** | Offensive capability, not our target. Listed so the catalogue is complete. |
| Inspect Evals — CyberSecEval 2/3/4 ports, CyberMetric, SecQA, CTI-MCQ, SEvenLLM, CTI-REALM | `inspect_evals/cyberseceval_4` etc. | Inspect ports of CyberSecEval (ICD via bundled semgrep; MITRE/prompt-injection/phishing model-graded; `cyse4_autopatching` prototype excluded for lacking a build/test loop) and knowledge MCQs | mixed (see CyberSecEval row) | 2 | 2 (MIT) | 0–1 | 2 | 2 | 0 | 8 | **reference** | Knowledge MCQs are irrelevant; the Inspect note that AutoPatch was dropped "without source + build/test/validation loop" is a reviewer's statement of exactly the bar our fix grader meets. |
| SeCodePLT (UCSB; HF `UCSB-SURFI/SeCodePLT`) | https://github.com/ucsb-mlsec/SeCodePLT · https://arxiv.org/abs/2410.11096 | 5.9k+ samples, 44 CWE categories, Python/C/Java; splits for secure coding, vulnerability detection and patch generation (~1.24k each per language); seeds human-validated then expanded by mutation; graded by executing code in Docker (`executor_docker`), explicitly contrasting with LLM-judge and rule-based grading | deterministic (dynamic tests) | 0 (repo last push 2025-09-24, 28 commits, 18 stars) | 0 (no LICENSE in repo or on the dataset card; only a vendored RedCode LICENSE.md) | 1 (Python vulnerability-detection split is adjacent — function-level, synthetic from seeds, not repo tasks; "cyberattack helpfulness" part is out of scope) | 1 (data; also a competing detection grader) | 1 (paper; no tests visible) | 0 | 3 | **reject** | No license and no maintenance; cannot be adopted. Watch the HF card; if a license appears, the `python_vulnerability_detection` split could seed per-CWE negative controls. |
| garak (NVIDIA) 0.17.1 | https://github.com/NVIDIA/garak | LLM vulnerability scanner: probe families (promptinject, dan, encoding, gcg, leakreplay, xss, packagehallucination, sysprompt_extraction …) against generators (HF, OpenAI, REST YAML, llama.cpp); detectors score outputs | mixed: `StringDetector`/`TriggerListDetector` (e.g. `promptinject.AttackRogueString` checks for the injected trigger string) are deterministic; `HFDetector` classifiers and `judge` detectors are model-based | 2 (pushed 2026-11-25, release 2026-10-16) | 2 (Apache-2.0) | 1 (probes a *model or REST endpoint*; our P8 target is an app's input path, i.e. a Python callable, which garak does not take natively; much of the corpus is jailbreak-oriented) | 1 (infra + corpus; the promptinject probe/detector pair competes with our harness) | 2 (tests, docs, 10k stars, NVIDIA) | 1 (REST adapter around the app) | 9 | **reference** | Borrow the trigger-string detector pattern (it is our canary design) and the encoding probe family for corpus ideas; do not depend — our harness must stay deterministic and callable-targeted. |
| PyRIT (Microsoft) 1.2.1 | https://github.com/microsoft/PyRIT | AI red-teaming framework: targets (OpenAI, Anthropic, HTTP, WebSocket, Playwright, custom), attack orchestration, converters, scorers | mixed: `SubStringScorer`, regex, `program_execution_scorer`, `cyberseceval_prompt_injection_scorer`, `garak_exploitation_scorer` deterministic; `SelfAsk*` scorers, LlamaGuard/ShieldGemma/WildGuard model-based | 2 (pushed 2026-11-27, v1.2.1 2026-11-18; old Azure/PyRIT archived 2026-03-27 — use microsoft/PyRIT) | 2 (MIT) | 1 (adjacent: own-app red teaming with HTTP targets; heavier than needed; multi-turn adaptive attacks are beyond P8's fixed-corpus design) | 1 (infra; scorers compete) | 2 (tests, docs, whitepaper 2026, 5k stars) | 1 (HTTP target adapter) | 9 | **reference** | Note it ships a CyberSecEval prompt-injection scorer and a garak scorer — the field is converging on reusing those corpora; confirms our corpus-replay design, not a dependency. |
| promptfoo | https://github.com/promptfoo/promptfoo · https://www.promptfoo.dev/docs/red-team/plugins/ | Node/TS eval + red-team CLI: red-team plugins `indirect-prompt-injection`, `system-prompt-override`, `prompt-extraction`, `special-token-injection`, `ascii-smuggling`, `cca`, `hijacking`; assertions | mixed: deterministic assertions (contains/regex/javascript/python/is-json/trajectory:*) vs model-graded (`llm-rubric`, `g-eval`, `classifier`, …); red-team graders are model-based and many plugins use promptfoo's *remote* generation endpoint in the community edition | 2 (pushed 2026-11-27, releases weekly) | 2 (MIT, confirmed after the move under OpenAI) | 1 (own-app eval with a Python provider; red-team graders model-judged and partly remote — conflicts with "no model calls" in the verifier and with offline sandboxes) | 1 (infra; competes) | 2 (27k stars, docs, tests) | 1 (Python provider adapter; Node toolchain) | 9 | **reference** | Useful as a CI harness for our *apps*' regression evals later; not for the lab verifier (remote inference, model-judged red-team results). |
| NeMo Guardrails 0.25.0 | https://github.com/NVIDIA/NeMo-Guardrails | Runtime guardrail library (Colang rails: jailbreak heuristics/classifiers, "injection detection" of code/SQL/template/XSS patterns in output, tool-call validation, PII) — a *defence*, not an evaluator; docs point to garak for scanning | n/a (runtime filter; checks are regex/heuristic or model self-check) | 2 (pushed 2026-11-27, v0.25.0 2026-11-19; `LLMRails` deprecated) | 2 (Apache-2.0 in LICENSE.md; GitHub shows NOASSERTION) | 0 (not a grader; a mitigation. Could be one *subject* a P8 agent recognises as a hardened sink) | 1 | 2 | 0 | 7 | **reject** | Not an eval tool; relevant only as a recognisable mitigation shape in P8 detection rules. |
| Rebuff (Protect AI) | https://github.com/protectai/rebuff | Prompt-injection detector prototype (heuristics, LLM check, vector DB of past attacks, canary tokens) | mixed | 0 (archived 2025-05-16; last push 2024-08) | 2 (Apache-2.0) | 0 | 1 | 1 | 0 | 4 | **reject** | Archived. Its canary-token leak check is the same idea our harness already implements. |
| LLM Guard (Protect AI) | https://github.com/protectai/llm-guard | Runtime input/output scanners incl. `PromptInjection` classifier, Secrets, BanSubstrings | classifier / regex | 0 (archived; models unmaintained) | 2 (MIT) | 0 | 1 | 1 | 0 | 4 | **reject** | Archived runtime filter. |
| mutmut 3.8.1 | https://github.com/boxed/mutmut | Generic mutation testing for Python: operators (int ± 1, `<`→`<=`, break↔continue, …, full list in `node_mutation.py`), pytest only, fork-based isolation, timeout = (baseline + c) × m, optional mypy/pyrefly filtering of type-visible mutants; mutmut 3 mutates only code inside functions | deterministic (test exit status) | 2 (pushed 2026-11-26, 3.8.0 2026-09-12) | 2 (BSD-3-Clause) | 1 (adjacent: measures general test-suite strength; our `mutate.py` answers a different question — *does the regression net catch a reintroduced security fix* — with hand-written fix reversions and per-property kill rate) | 2 (infra) | 2 (docs, CI, 1.6k stars) | 0 (pytest-only, requires fork, Linux/WSL; no notion of a curated fix-reversion list) | 9 | **reference** | Do not replace `mutate.py`: generic operators would flood us with irrelevant mutants and cannot express "revert this fix". Steal two mechanics: the baseline-derived timeout formula and type-checker filtering of trivially-detectable mutants. Could be run once per target repo as a *test-suite strength* covariate. |
| cosmic-ray 8.9.0 | https://github.com/sixty-north/cosmic-ray | Mutation testing for Python 3.9+: AST operators (binary/comparison/unary operator replacement, boolean/number/keyword/variable replacement, exception replacer, remove decorator, zero-iteration loop, break/continue), any test command, distributed execution via Celery | deterministic (test exit status) | 2 (pushed 2026-11-26, v8.9.0 2026-11-10) | 2 (MIT) | 1 (same as mutmut; plus arbitrary test command and `remove_decorator`/`exception_replacer`, which *are* security-relevant operators: removing an auth decorator or swallowing an exception) | 2 (infra) | 1 (docs, CI, 667 stars, fewer users) | 0 (same reasons; config-heavy, Celery) | 8 | **reference** | Its operator list is a better *seed catalogue* for security-flavoured generic mutants than mutmut's (decorator removal, exception replacement). Still not a replacement for curated fix reversions. |
| Harbor registry: `binary-audit` (46), `swtbench-verified` (433), `vmax-tasks` (1,043 JS) | harbor-framework/harbor `registry.json` | Only security-adjacent dataset in Harbor's 80-entry registry is `binary-audit` (backdoors hidden in compiled binaries); no SAST / vulnerability-detection / secure-code / prompt-injection dataset exists there yet | deterministic | 2 | 2 | 0 (binaries) | 2 | 1 | 2 | 9 | **reject** | Wrong artefact type (compiled binaries). The gap confirms our dataset is a genuine contribution to the registry. |

#### Recommended for Phase 1

Adopt **RewardKit** as the reward layer: our five graders become `@criterion` functions in a
multi-reward `tests/` tree (one subdirectory per dimension → `reward.json`), `command_succeeds`
runs the hidden fix test, judge criteria stay off (deterministic verifier, no model calls).
Adopt the **SWE-bench Verified rubric** for the validity gate (two 0–3 axes, two raters, keep
<= 1). Everything else is reference: CodeIPI, AgentDojo and CASTLE for *measurement shape*
(canary checks, clean-control ratio, penalised FP), ICD rules as a fix sanity oracle, cosmic-ray
operators as a catalogue when we grow `mutate.py`. PatchEval's Python CVEs are the first
external task source to mine once a class beyond P4 needs data (check its CWE-918 count first).

#### Gaps: nothing found for …

- A **Python-repository vulnerability-detection task set with negative controls** graded by
  deterministic location-aware recall and FPR (the Phase 1 dataset). CASTLE has the metric
  shape but is C and single-file; SeCodePLT is function-level, unlicensed and dormant;
  Harbor's registry has none.
- A **prompt-injection eval whose target is a Python callable** (an app's own input path) with
  deterministic canary grading. garak/PyRIT/promptfoo target models or HTTP; CodeIPI is the
  nearest, and it targets the coding agent rather than the application under test.
- A **fix-reversion mutation tool** (curated "revert this security fix" mutants, per-property
  kill rate). mutmut and cosmic-ray are generic-operator tools; `evals/mutate.py` stays.
- A **human-validated security task set** in the SWE-bench Verified sense. PatchEval's
  "verified dockerized subset" is verified for *reproducibility* (builds and tests run), not
  annotated for specification clarity or test fairness; CyberGym is unannotated fuzz data.
- **Licenses not stated** where they matter: SWE-bench Verified dataset card, CodeIPI samples,
  SeCodePLT. Confirm before copying any sample.

### A.5 Reproducible environments and sandboxing (`survey-envs.md`)

### Survey — reproducible environments for old commits, and sandboxing

Component: building a Python project at a years-old commit; per-task interpreter selection; sandbox
runtimes Harbor supports (local and hosted, with costs against a $200/month total budget); hardening
references; macOS runtimes; OSS-Fuzz / ARVO as a reproduction pattern.
Surveyed 2026-11-27 against each project's own repo/docs (GitHub API for push dates and licenses;
Harbor `src/harbor/environments/` and `docs.harborframework.com/sandboxes/pre-integrated-sandboxes`;
provider pricing pages). Read-only; nothing installed.

Scores: maintained | license | fit | kind | quality | switching, each 0–2.

| name | link | what it does (categorical) | maint. | lic. | fit | kind | qual. | switch | total | decision | reason |
|---|---|---|---|---|---|---|---|---|---|---|---|
| uv `--exclude-newer` | https://docs.astral.sh/uv/concepts/resolution/ · github.com/astral-sh/uv | Resolver cutoff: only distributions uploaded to the index before an RFC 3339 date/time (or plain date) are considered; per-package exemptions (`exclude-newer-package`); works for `uv pip install/compile` and project `uv lock`. Needs PEP 700 `upload-time` (PyPI has it for all packages); git deps unaffected. Python. | 2 (push 2026-11-26, 92.7k★) | 2 (Apache-2.0/MIT) | 2 | 2 | 2 | 2 | 12 | adopt | The date-pinned resolution we need, one flag in the task Dockerfile: `--exclude-newer=<fix-commit date>` |
| Official `python:<ver>-slim` images | github.com/docker-library/python · hub.docker.com/_/python | Per-minor-version Debian/Alpine images for `FROM`; currently built for 3.11–3.16; EOL tags stay pullable but frozen (3.6-slim last updated 2021-12-22, 3.8-slim 2024-09-28; apt mirrors of that era may be archived). Python. | 2 (push 2026-11-10) | 2 (MIT) | 2 | 2 | 2 | 2 | 12 | adopt | Interpreter of the commit's era as the task base image; Harbor tasks are Dockerfiles already |
| Docker (local, Harbor `--env docker`) | docs.harborframework.com/sandboxes/pre-integrated-sandboxes | Harbor's default local runtime: Compose, egress-control sidecar giving every network policy mode (disable internet / hostname / wildcard / IP / runtime changes), host-mounted logs. Needs docker CLI + compose v2 plugin. | 2 | 2 (Apache-2.0 engine) | 2 | 2 | 2 | 2 | 12 | adopt | The plan's containment + network phases work only here and on a subset of hosted providers |
| colima | github.com/abiosoft/colima | Docker daemon (or containerd/incus) in a Lima VM on macOS; `vz` backend, Rosetta for x86_64 images on Apple silicon; socket at `~/.colima/default/docker.sock`, sets itself as docker context. docker/compose CLIs installed separately. | 2 (push 2026-10-13, 31.9k★) | 2 (MIT) | 2 | 2 | 2 | 2 | 12 | adopt | Already named in the plan; gives Harbor's default `docker` env on this Mac at $0; local results stay labelled local |
| Modal (Harbor `--env modal`) | modal.com/pricing · github.com/modal-labs/modal-client | Hosted sandboxes; Harbor: Compose + all network policy modes, CPU-only Compose tasks default to a VM. Starter plan $0 + **$30/month free credits (recurring)**; Sandbox CPU $0.00003942/core-s (≈$0.142/core-h), RAM $0.00000667/GiB-s (≈$0.024/GiB-h) → 2 core + 4 GiB ≈ $0.38/h ≈ 79 sandbox-hours/month inside the free credit. | 2 (push 2026-11-27) | 2 (client Apache-2.0) | 2 | 2 | 2 | 2 | 12 | adopt | Only provider with a *recurring* free tier that fits a $200/month total; full Harbor network-policy parity |
| uv-managed Python (`uv python install`, python-build-standalone) | docs.astral.sh/uv/concepts/python-versions/ · github.com/astral-sh/python-build-standalone | Downloads prebuilt CPython on demand from `.python-version` / `requires-python` / `--python`; catalogue frozen per uv release. PBS README now lists builds for **3.11–3.16**; older interpreters exist only in past PBS releases — verify `uv python list` before relying on 3.8–3.10. | 2 | 2 (uv Apache/MIT; PBS MPL-2.0) | 1 | 2 | 2 | 2 | 11 | adopt | Second interpreter source when the `python:` tag is wrong or a patch version matters; not for <3.11 without checking |
| Daytona (Harbor `--env daytona`) | daytona.io/pricing · github.com/daytonaio/daytona (archived) | Hosted sandboxes; Harbor's reference remote provider (Compose, GPUs, SSH streaming, all network policy modes; `DAYTONA_API_KEY`). **$200 free compute on signup (one-time)**; vCPU $0.0504/h, RAM $0.0162/GiB/h, per-second billing → 2 vCPU + 4 GiB ≈ $0.166/h ≈ 1,200 sandbox-hours of credit. OSS repo archived 2026-06 ("core development moved to a private codebase"). | 1 (service active; OSS dead) | 0 (service; OSS license pulled) | 2 | 2 | 2 | 2 | 9 | adopt (burst only) | Cheapest hosted hours and the best-supported Harbor remote; spend the one-time credit on sealed-split / parallel runs, nothing recurring |
| Podman (Harbor `--env podman`) | github.com/containers/podman · harbor `environments/podman.py` | Daemonless OCI runtime; Harbor reuses the Docker orchestrator with a Podman compose dialect (`podman compose` / `podman-compose --in-pod=false`); full network policies. Open Harbor issues on compose-provider banner breaking agent install (#3035, #3128, #3480). On macOS runs in `podman machine` (libkrun/Apple HV). | 2 (push 2026-11-27, 33k★) | 2 (Apache-2.0) | 2 | 2 | 2 | 1 | 11 | reference | Fallback local runtime if colima/Docker is unwanted; the open compose issues are the switching cost |
| gVisor (`runsc`) | gvisor.dev · github.com/google/gvisor | User-space kernel as a Docker runtime (`--runtime=runsc`) for syscall-level isolation; Linux only. Harbor's Docker env does not set a `runtime:`; its Kata env shows the compose-overlay pattern that would. | 2 (push 2026-11-26, 20k★) | 2 (Apache-2.0) | 1 | 2 | 2 | 1 | 10 | reference | Hardening reference for a Linux CI host; not runnable on macOS directly |
| Kata Containers (Harbor `--env kata`) | katacontainers.io · harbor `environments/kata.py` | Docker orchestration with each task service in a KVM microVM (Cloud Hypervisor/QEMU). Requires Linux + `/dev/kvm`. Harbor v1 limits: image builds not VM-isolated, **network policies rejected**, no compose DNS discovery. | 2 (push 2026-11-27) | 2 (Apache-2.0) | 1 | 2 | 2 | 1 | 10 | reference | VM boundary for agent/verifier on Linux, but loses our network phases; Linux only |
| E2B (Harbor `--env e2b`) | e2b.dev/pricing · github.com/e2b-dev/E2B | Hosted Firecracker-style sandboxes; Harbor: network policies DI/Host/Wild/IP, no Compose. Hobby: **$100 one-time credit, 10 concurrent, 1 h per session**; Pro $150/month + usage. vCPU $0.000014/s (≈$0.0504/h), RAM $0.0000045/GiB-s (≈$0.0162/GiB-h). Open Harbor issues on Dockerfile builds / readiness (#4005, #4009). | 2 (push 2026-11-27, 15k★) | 2 (SDK Apache-2.0) | 1 | 2 | 2 | 1 | 10 | reference | 1-hour session cap on the free tier is tight for build+agent+verify; Pro would consume 75% of the whole budget |
| SWE-bench harness / image builder | github.com/SWE-bench/SWE-bench (`swebench/image_builder`, `harness/docker_build.py`) | Per-instance Docker images for Python repos at old commits (base → env → instance layering; prebuilt images on Docker Hub); historically a per-repo/version map of python version + install command. Python (plus other languages now). | 1 (push 2026-09-18) | 2 (MIT) | 1 | 2 | 2 | 1 | 9 | reference | Layering pattern and install knowledge for its 12 Python repos; harness itself is replaced by Harbor |
| SWE-smith | github.com/SWE-bench/SWE-smith | Automated environment creation for 250+ Python repos (one image per repo), env-setup guide, task synthesis. NeurIPS 2025 D&B. Linux only. | 2 (838★, active) | 2 (MIT) | 1 | 2 | 2 | 1 | 10 | reference | Its install-recipe discovery is the closest existing answer to our `RepoConfig` auto-detection; read, don't depend |
| ARVO | github.com/n132/ARVO-Meta · arxiv.org/abs/2408.02153 | 6,100+ reproducible OSS-Fuzz vulnerabilities across 311 projects as paired Docker images `n132/arvo:ID-vul` / `ID-fix` with the PoC baked in (`arvo` runs it, `arvo compile` rebuilds); 81% reproduce, 89.4% patch accuracy; EuroS&P 2026; 20M+ pulls. Sanitizer-crash based → overwhelmingly C/C++; not our Python web-class CWEs. | 2 (push 2026-11-21) | 2 (BSD-2) | 1 | 2 | 2 | 1 | 10 | reference | The template for our task layout: vul/fix image pair, PoC as the hidden test, fix verified by rerun; data itself is the wrong language/class |
| OSS-Fuzz infra (`helper.py`, `build_specified_commit.py`, `bisector.py`) | github.com/google/oss-fuzz/tree/master/infra | Per-project Dockerfile + build.sh; `build_image` / `build_fuzzers` / `reproduce <target> <testcase>`; builds at an arbitrary commit, base-builder images selected by timestamp, bisection between commits. Languages: c, c++, go, rust, python (Atheris), jvm, swift, javascript, lua. | 2 (push 2026-11-27) | 2 (Apache-2.0) | 1 | 2 | 2 | 0 | 9 | reference | "Build at commit + reproduce + bisect" and date-indexed base images are the pattern; its image hierarchy is its own |
| pixi `exclude-newer` | pixi.prefix.dev/latest/reference/pixi_manifest/ · github.com/prefix-dev/pixi | Conda + PyPI lockfile manager; `[workspace] exclude-newer` applies to conda and PyPI (uses uv as a library), with `pypi-exclude-newer` and exemptions. | 2 (push 2026-11-26, 8k★) | 2 (BSD-3) | 1 | 2 | 2 | 1 | 10 | reference | Only if a target repo needs conda-native compiled deps; otherwise uv alone |
| PDM `pdm lock --exclude-newer` | pdm-project.org/latest/usage/lockfile/ | Project manager with date cutoff at lock time (since 2.13; relative durations since 2.26.8; `[tool.pdm.resolution]` since 2.26.9). | 2 | 2 (MIT) | 1 | 2 | 2 | 1 | 10 | reference | Same capability as uv but needs a PDM project; redundant |
| pypi-timemachine | github.com/astrofrog/pypi-timemachine | Local PyPI-compatible proxy that hides releases after a cutoff (`pypi-timemachine 2021-02-03`, then `pip install --index-url http://127.0.0.1:5000/`); uses PEP 700 upload-time; "alpha-quality", single maintainer. Python. | 1 (push 2026-11-02, 138★, 50 commits) | 2 (BSD-2) | 2 | 2 | 1 | 1 | 9 | reference | Fallback when a legacy `setup.py` install must run under plain pip rather than uv; extra process in the build |
| anthropics/sandbox-runtime (`srt`) | github.com/anthropics/sandbox-runtime | Process-level sandbox (macOS Seatbelt / Linux bubblewrap) with network deny-by-default through a domain-allowlist proxy and allow-only writes; not a container or VM; Beta research preview. | 2 (push 2026-11-13, 7.3k★) | 2 (Apache-2.0) | 1 | 2 | 1 | 1 | 9 | reference | Could wrap host-side local-mode runs (graders, repo clones) on the Mac; not a Harbor sandbox substitute |
| nixpkgs pinning (+ lazamar nix-versions) | nix.dev/tutorials/first-steps/towards-reproducibility-pinning-nixpkgs · lazamar.co.uk/nix-versions | Pin a whole package set to a nixpkgs commit (`fetchTarball .../archive/<commit>.tar.gz`, npins, flakes); nix-versions finds the commit that carried a given package version. Interpreter and system libs, not PyPI history. | 2 (nixpkgs push 2026-11-27) | 2 (MIT) | 1 | 2 | 2 | 0 | 9 | reference | Solves interpreter/system-lib pinning Nix-style, but means Nix inside every task image; no PyPI date resolution |
| Firecracker | github.com/firecracker-microvm/firecracker | KVM microVM monitor that hosted sandbox providers build on; Linux/KVM only. | 2 (push 2026-11-27, 38k★) | 2 (Apache-2.0) | 0 | 2 | 2 | 0 | 8 | reference | Hardening vocabulary only; we consume it through providers, never run it |
| Apple `container` (Harbor `--env apple-container`) | github.com/apple/container | One lightweight Linux VM per container on Apple silicon, macOS 26+; OCI images. Harbor: CPU/memory limits, **no network policy support**, no Compose; pre-1.0 ("product versions"). | 2 (push 2026-11-13, 52k★) | 2 (Apache-2.0) | 1 | 2 | 1 | 1 | 9 | reject (for now) | VM isolation on this Mac is attractive, but without network policies our no-network/allowlist phases are unenforceable |
| uv2nix / pyproject.nix | github.com/pyproject-nix/uv2nix | Builds Nix derivations from a `uv.lock`. | 2 (push 2026-11-25, 800★) | 2 (MIT) | 1 | 2 | 1 | 0 | 8 | reject | Needs a `uv.lock` in the target; years-old commits have none |
| pip-tools (`pip-compile`) | github.com/pypa/pip-tools | Pins `requirements.in` to exact versions as of *today's* index; no date cutoff. Python. | 2 (push 2026-11-16, 8k★) | 2 (BSD-3) | 0 | 2 | 2 | 1 | 9 | reject | No time-travel; `uv pip compile --exclude-newer` supersedes it |
| Runloop (Harbor `--env runloop`) | runloop.ai/pricing | Hosted devboxes; $50 one-time credit (3 running devboxes on trial); CPU $0.108/CPU-h, RAM $0.0252/GB-h (≈2× Daytona); Harbor: no Compose, DI/Host/Wild policies. | 2 | 0 (service) | 1 | 2 | 1 | 2 | 8 | reject | Smaller credit, double the price, fewer Harbor capabilities than Daytona/Modal |
| pyenv (in Docker) | github.com/pyenv/pyenv | Builds any CPython from source per project (`.python-version`); needs build deps; minutes per image. | 2 (push 2026-11-27, 45k★) | 2 (MIT) | 1 | 2 | 2 | 1 | 10 | reject | Redundant with `python:` tags + uv-managed Python; only worth it for an interpreter neither carries |
| poetry2nix | github.com/nix-community/poetry2nix | Nix derivations from `poetry.lock`. | 2 (push 2026-11-27) | 2 (MIT) | 0 | 2 | 1 | 0 | 7 | reject | Needs a `poetry.lock` at the target commit; Nix overhead |
| conda-lock / mamba | github.com/conda/conda-lock · github.com/mamba-org/mamba | Multi-platform conda lockfiles (pip section via vendored Poetry solver); fast conda solver. No date-based resolution. | 2 (push 2026-11-26) | 1 (conda-lock license not SPDX-detected; mamba BSD-3) | 0 | 2 | 1 | 1 | 7 | reject | Locks today's solve, not the commit's era; our targets are PyPI projects |
| nsjail / bubblewrap | github.com/google/nsjail · github.com/containers/bubblewrap | Linux process sandboxes (namespaces/seccomp); what `srt` and Flatpak build on. | 2 | 1 (nsjail Apache-2.0; bubblewrap LGPL) | 0 | 2 | 1 | 0 | 6 | reject | Linux-only, below the container layer Harbor already gives us |
| Other Harbor remotes (beam, blaxel, novita, tensorlake, vercel, langsmith, gke, ec2, skypilot, sail, runta, prime, mosaic, smol, hf-sandbox, boxd, superserve, …) | docs.harborframework.com/sandboxes/pre-integrated-sandboxes | 30+ `--env` targets exist in Harbor v0.27.0 with per-provider capability tables. | – | – | – | 2 | – | 2 | – | not surveyed | No free tier verified in this pass; revisit only if Modal + Daytona credits run out |

#### Recommended for Phase 1

Task image = `FROM python:<era>-slim` (or uv-managed Python when the tag is wrong) + `uv pip install --exclude-newer=<fix-commit date>` for every install step, so a 2021 commit resolves against 2021 PyPI with one flag and no proxy. Run Harbor `--env docker` on colima locally (labelled local), `--env modal` for the recurring free $30/month (≈79 sandbox-hours at 2 core/4 GiB, full network-policy parity), and spend Daytona's one-time $200 (≈1,200 sandbox-hours) on the sealed-split and parallel runs. Copy ARVO's shape — paired vul/fix images, the PoC/test as the hidden verifier, fix confirmed by rerun — into our task dirs; Harbor's `[environment].docker_image` can even point at prebuilt pairs. Treat gVisor/Kata/Firecracker as Linux-CI hardening to cite, not to run on the Mac.

#### Gaps: nothing found for …

- Date-pinned resolution under **plain pip** with a legacy `setup.py` that uv refuses — only pypi-timemachine (alpha, single maintainer).
- A **Python-language ARVO**: fuzz-crash datasets are C/C++; no reproducible vul/fix image pairs exist for Python web CWEs — that is our dataset build.
- A macOS runtime giving **both** VM isolation and Harbor network policies (apple-container lacks policies; gVisor/Kata are Linux-only).
- Prebuilt interpreters **< 3.11** from python-build-standalone's current list; EOL `python:` tags carry archived apt mirrors — expect `apt-get` failures in old base images and pin `deb.debian.org` → `archive.debian.org` when needed.
- Automated "install recipe at commit" discovery as a library (SWE-smith has a guide, not an importable tool).
- Verified pricing for ~25 of Harbor's remote providers (not costed here).
- Docker Desktop / OrbStack: proprietary, not surveyed.

### A.6 Statistics, reporting and disclosure (`survey-stats-disclosure.md`)

### Survey — statistics / reporting / disclosure workflow (2026-11-27)

Scope: (a) eval-statistics libraries and reporting conventions, cards/datasheets, contamination
tooling; (b) coordinated-disclosure tooling and formats; (c) results viewers (free only).
All activity dates come from the GitHub API (`pushed_at`) or PyPI on 2026-11-27; licenses from the
repo's declared SPDX id. Scores: maintained | license | fit | kind | quality | switching, 0–2 each.

#### Table (sorted by decision, then total)

| name | link | what it does | maint. | lic. | fit | kind | qual. | switch. | total | decision | reason |
|---|---|---|---|---|---|---|---|---|---|---|---|
| OSV schema 1.9.2 | https://github.com/ossf/osv-schema | JSON vulnerability-record format: `id, affected[].ranges, severity[CVSS_V3/V4], credits[type=FINDER/REPORTER], references, database_specific`; JSON Schema + Python validator | 2 (pushed 2026-11-26) | 2 Apache-2.0 | 2 (ingest input *and* output format for a finding) | 2 data/infra | 2 (spec, schema.json, validator, OpenSSF WG) | 2 (we already ingest it) | 12 | adopt | one record type for advisory ingest and for discovery-mode reports; `credits` carries attribution |
| GitHub Advisory Database | https://github.com/github/advisory-database | Reviewed advisories as OSV JSON, per ecosystem (PyPI), git-cloneable | 2 (pushed 2026-11-27) | 2 CC-BY-4.0 (data) | 2 | 2 data | 2 | 2 | 12 | adopt | the CWE-918/PyPI ingest source the plan already names; no API key needed via git |
| GitHub private vulnerability reporting (PVR) | https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability | Private report → maintainers; REST `POST /repos/{o}/{r}/security-advisories/reports` with `summary, description, vulnerabilities[], cwe_ids, severity|cvss_vector_string, start_private_fork`; rate-limited 5/repo/day, 25/day total | 2 (GitHub product, documented) | 2 (free on public repos; part of GitHub) | 2 | 2 infra | 2 | 1 (adapter: OSV record → PVR body; only when the target has PVR enabled) | 11 | adopt | the disclosure channel for Phase 6 discovery mode; fall back to SECURITY.md contact when not enabled |
| OpenSSF OSS Vulnerability Guide | https://github.com/ossf/oss-vulnerability-guide | Maintainer guide, finder guide, runbook, SECURITY.md / embargo / disclosure-notification templates | 1 (pushed 2026-08-19) | 2 CC-BY-4.0 | 2 (finder-guide + templates) | 2 data (text) | 1 (no tests; OpenSSF-maintained) | 2 (copy the templates) | 10 | adopt | our disclosure runbook and report template come from here, not written fresh |
| `statistics`/`math` stdlib (current choice: `evals/metrics.py` has `wilson_ci`, `pass_at_k`, `pass_pow_k`) | — | Wilson, exact McNemar (`math.comb`), paired percentile bootstrap (`random`) | 2 | 2 PSF | 2 | 2 infra | 1 (needs our own oracle tests) | 2 (in place) | 11 | adopt (keep) | see "Is stdlib wise?" — yes, with scipy/statsmodels as *test-time oracles* only |
| scipy.stats (`bootstrap(paired=True, method='BCa')`, `binomtest`) | https://docs.scipy.org/doc/scipy/reference/generated/scipy.stats.bootstrap.html | BCa/percentile/basic bootstrap CIs, paired resampling, exact binomial | 2 (pushed 2026-11-27; v1.18) | 2 BSD-3 | 2 | 2 infra | 2 | 1 (new runtime dep; pulls numpy) | 11 | adopt as dev/test oracle only | validates our stdlib numbers in `tests/`; not a runtime dependency (keeps the `calib` extra small) |
| statsmodels (`proportion_confint(method="wilson")`, `contingency_tables.mcnemar(exact=True)`) | https://www.statsmodels.org/stable/generated/statsmodels.stats.contingency_tables.mcnemar.html | Wilson/Jeffreys/Agresti-Coull CIs, exact/chi2 McNemar | 2 (pushed 2026-11-27) | 2 BSD-3 | 2 | 2 infra | 2 | 1 (heavy dep: pandas, patsy) | 11 | adopt as dev/test oracle only | same role as scipy; the two together cover every function we hand-roll |
| Inspect AI metrics conventions | https://inspect.aisi.org.uk/metrics.html | `accuracy, mean, stderr(cluster=key), bootstrap_stderr(num_samples=1000), ci_wilson, grouped(metric, key)`; recommends `ci_wilson` for binary scores | 2 (pushed 2026-11-27) | 2 MIT | 1 (conventions; we run on Harbor, not Inspect) | 2 infra | 2 | 1 | 10 | adopt the conventions (clustered SE by task, `grouped` by stratum, Wilson for binaries), not the package | mirrors the plan's "task is the unit" rule; name our fields the same way |
| Miller 2024, "Adding Error Bars to Evals" (arXiv 2411.00640) | https://arxiv.org/abs/2411.00640 | CLT SE, clustered SE (up to 3x naive), paired differences, K-resample variance rule, power formula; "bootstrap unnecessary unless complicated estimator" | n/a paper | n/a | 2 | 2 baseline (method) | 2 (widely cited; implemented by Inspect, errorbars) | 2 | 10 | adopt (method) | gives the power note and the K-per-task rule the card needs; cite it in the card's Power section |
| Hugging Face dataset-card template | https://github.com/huggingface/huggingface_hub/blob/main/src/huggingface_hub/templates/datasetcard_template.md | Markdown + YAML front matter: Dataset Details, Uses/Out-of-Scope, Structure, Creation (curation, source, annotation, PII), Bias/Risks/Limitations, Citation | 2 (pushed 2026-11-27) | 2 Apache-2.0 | 1 (dataset card, not eval card) | 2 infra | 2 | 2 (copy headings) | 11 | adopt (skeleton) | our `evals/cards/calib-egress.md` keeps HF's headings and adds Splits, Contamination, Power, Exclusions, Not measured |
| Datasheets for Datasets (Gebru et al., arXiv 1803.09010) / Model Cards (Mitchell et al., 1810.03993) | https://arxiv.org/abs/1803.09010 | Question lists: motivation, composition, collection, preprocessing, uses, distribution, maintenance | n/a papers | n/a | 1 | 2 baseline | 2 | 2 | 9 | adopt (checklist) | the HF template is the operationalised form; use the papers' question lists to audit the card, nothing to install |
| Every Eval Ever (EEE) schema 0.2.0 | https://github.com/evaleval/every_eval_ever | JSON schema for eval runs: `schema_version, evaluation_id, source_data, model_info, evaluation_results`; instance-level schema; converters from HELM / lm-eval / Inspect | 2 (pushed 2026-11-26) | 2 MIT | 1 (generic results schema; no security fields) | 2 infra | 1 (new: June 2026 paper, 142 stars) | 1 (adapter from our `summary.json`) | 9 | reference | emit an EEE record later if we publish; do not shape `summary.json` around it yet |
| Harbor `harbor view` (local viewer) | https://docs.harborframework.com/core-concepts/results/view-job-results.md | Local web viewer: job list, per-trial reward/cost/tokens/trajectory, verifier output, files | 2 (pushed 2026-11-25) | 2 Apache-2.0 | 2 | 2 infra | 2 | 2 (comes with Harbor) | 12 | adopt | free, local, zero extra work — the only viewer Phase 1 needs |
| Harbor Hub (hosted) | https://hub.harborframework.com | Upload/share jobs, cost/token overview, `harbor hub job list/show/compare`, hosted rollouts, leaderboards; needs account + API key | 2 | 1 (service; pricing/free tier not stated anywhere I could find) | 1 | 2 infra | 1 | 1 | 8 | reference (revisit at Phase 6) | not confirmed free; nothing in Phase 1 needs sharing; local viewer suffices |
| MLflow (local tracking server + UI) | https://github.com/mlflow/mlflow | Experiment tracking, GenAI tracing, LLM-judge scorers, local UI on :5000 | 2 (pushed 2026-11-27; 29k stars) | 2 Apache-2.0 | 1 (generic tracker; duplicates Harbor's job results) | 2 infra | 2 | 0 (second results store beside Harbor) | 9 | reject | free and good, but a second system of record for results we already get from Harbor + `summary.json` |
| Weights & Biases Weave | https://github.com/wandb/weave | Hosted LLM tracing/evals; free tier 5 seats, 5 GB storage, 1 GB/mo Weave ingestion (CoreWeave pricing page) | 2 (pushed 2026-11-23) | 1 (client Apache-2.0; server hosted/paid) | 1 | 1 mixed | 2 | 0 | 7 | reject | hosted, 1 GB/mo ingestion cap, sends trajectories off-box; nothing it adds over `harbor view` |
| errorbars 0.3.0 (PyPI) | https://github.com/antonsoo/errorbars | CLI/library: CLT & Wilson & bootstrap CIs, CR2 clustered SE, paired t / McNemar, Holm-corrected leaderboards, power; imports lm-eval and Inspect logs; numpy only | 2 (pushed 2026-11-26; created 2026-09-24) | 2 MIT | 2 | 1 mixed (competes with our `stats.py`) | 1 (oracle tests vs scipy/statsmodels, Monte Carlo coverage; 0 stars, single author, no releases) | 1 | 9 | reference | read its `tests/oracles.py` and coverage tests as a model for ours; too new and unreviewed to depend on |
| lm-evaluation-harness reporting | https://github.com/EleutherAI/lm-evaluation-harness | `mean_stderr`, `bootstrap_stderr(metric, iters=bootstrap_iters)`, `stderr_for_metric`; results keyed `"<metric>,<filter>"` with `<metric>_stderr` sibling | 2 (pushed 2026-11-04) | 2 MIT | 1 | 2 infra | 2 | 1 | 10 | reference | copy one convention: every point estimate ships with a `_stderr`/`_ci95` sibling field |
| HELM `Stat` / summarize outputs | https://github.com/stanford-crfm/helm | `Stat{name,count,sum,mean,variance,stddev,min,max}` with `merge`; `run_spec.json`, `stats.json`, `per_instance_stats.json`, `groups/json/<group>_<metric>.json` | 1 (pushed 2026-09-01) | 2 Apache-2.0 | 1 | 2 infra | 2 | 1 | 9 | reference | per-instance stats file beside the aggregate is the pattern to keep (we need per-task rows for paired tests) |
| CERT Guide to CVD | https://github.com/CERTCC/CERT-Guide-to-CVD | Full CVD guide (roles, phases, timelines, troubleshooting) as MkDocs | 2 (pushed 2026-11-01) | 1 (CMU copyright: redistribute unchanged, no derivative outside internal use) | 1 (policy background, no templates) | 2 data (text) | 2 (SEI, authoritative) | 2 (read) | 10 | reference | read for timelines and multi-party cases; license forbids remixing into our docs, so cite it |
| disclose.io `dioterms` | https://github.com/disclose/dioterms | VDP / VDP+CVD window / Safe Harbor / Simple Safe Harbor templates, regional variants, maturity model | 1 (pushed 2026-07-30) | 2 CC0-1.0 | 1 (recipient-side policy text; we are the finder) | 2 data (text) | 1 | 2 | 9 | reference | useful for our own repo's SECURITY.md safe-harbor clause; irrelevant to reporting into other projects |
| GitHub SECURITY.md convention | https://docs.github.com/en/code-security/getting-started/adding-a-security-policy-to-your-repository | `SECURITY.md` (root, `docs/`, or `.github/`): supported versions + how to report; surfaces in the Security tab and above the PVR form | 2 | 2 | 1 | 2 infra | 1 | 2 | 10 | reference (already in `secure-project`) | discovery mode reads the *target's* SECURITY.md first to pick the channel; nothing to build |
| RFC 9116 `security.txt` + `sectxt` validator | https://github.com/DigitalTrustCenter/sectxt | `/.well-known/security.txt` contact file; Python parser/validator | 1 (pushed 2025-12-11) | 1 EUPL-1.2 (copyleft, tool use OK) | 0 (web-site contact discovery; our targets are repos) | 2 | 1 | 1 | 6 | reject | tangential: repos carry SECURITY.md, not security.txt |
| SARIF 2.1.0 (OASIS) + `sarif-tools` | https://github.com/microsoft/sarif-tools | Static-analysis result interchange: `result{ruleId, level, message, locations, partialFingerprints, baselineState}`; GitHub code scanning ingests it | 2 (spec errata 2023; sarif-tools pushed 2026-10-27) | 2 (MIT tools; OASIS spec) | 1 (per-finding format; ours needs oracle/claim fields) | 2 infra | 2 | 1 | 10 | reference | a `findings → SARIF` exporter is a cheap later add-on for maintainers; not a Phase 1 report format |
| Croissant 1.1 / `mlcroissant` 1.1.1 | https://github.com/mlcommons/croissant | schema.org-based dataset metadata (JSON-LD) with RAI extension; validate/load; deps: pandas, rdflib, scipy, absl, etils | 2 (pushed 2026-11-16; PyPI 2026-10-05) | 2 Apache-2.0 (spec CC-BY-ND) | 0 (describes tabular/file datasets for loaders; our tasks are Docker task dirs with a `dataset.toml`) | 2 | 2 | 0 (heavy deps, no fit to Harbor `dataset.toml`) | 8 | reject | metadata for ML loaders, not for a task suite; a hand-written JSON-LD stub would be decoration |
| BenchmarkCards (IBM/Notre Dame, NeurIPS 2025 D&B) | https://github.com/SokolAnn/BenchmarkCards | Benchmark documentation template (Markdown + JSON), 4k auto-generated cards, risk-atlas mapping | 1 (pushed 2025-11-25; 1 commit on main) | 2 MIT code / CC-BY-4.0 cards | 1 | 2 | 1 | 1 | 8 | reference | compare its section list against our card once; the LLM auto-fill tool is not something we want |
| Evaluation Cards (arXiv 2606.09809, 48 authors) | https://arxiv.org/abs/2606.09809 | Reporting layer composing benchmark + run + model metadata; signals: reproducibility, documentation completeness, provenance/risk, comparability | n/a (June 2026 paper; no code URL on the abstract page) | n/a | 1 | 2 | 1 | 1 | 6 | reference | its "minimal reproducibility fields" list is a checklist for `summary.json`; no artifact to adopt |
| Google `model-card-toolkit` | https://github.com/tensorflow/model-card-toolkit | Model-card generation from TFX/ML Metadata | 0 (archived 2023) | 2 Apache-2.0 | 0 | 2 | 1 | 0 | 5 | reject | archived; TensorFlow-centric |
| LLMSanitize | https://github.com/ntunlp/LLMSanitize | Contamination detection: string-match / embedding (open-data) and guided-prompting, CDD, ts-guessing, sharded-likelihood, min-prob (model-side; vLLM, CUDA 11.8, Python 3.9) | 0 (pushed 2024-08-13) | 2 Apache-2.0 | 1 | 1 mixed | 1 | 0 (needs local GPU models) | 5 | reject | dead; model-side methods need open weights or vLLM; our models are API-only |
| llm-decontaminator (LMSYS) | https://github.com/lm-sys/llm-decontaminator | Rephrased-sample detection: embedding retrieval + LLM judge between a *training set* and a benchmark | 0 (pushed 2023-12-20) | 2 Apache-2.0 | 0 (needs the training corpus, which we never have for API models) | 1 | 1 | 0 | 4 | reject | dead; requires training data access |
| BenchChecker (USENIX Security 2026, arXiv 2610.19447) | https://arxiv.org/abs/2610.19447 | Forensic contamination test for bug-fixing benchmarks: repository-presence probe (prefix completion) + patch-presence test via repo history + tests; works on closed models by text only | n/a (paper; no code link on abstract) | n/a | 2 (exactly our setting: fixed Python bugs, API models) | 1 mixed (would be part of our contamination layer) | 1 (paper; results on open models only) | 0 | 4 | reference | the *method* is right; no released code to adopt; our date-based `cutoffs.yaml` bin remains the primary control, and a repository-presence probe is a cheap Phase 2 addition |

#### Is stdlib-only statistics wise?

Yes, with one condition. Every function the plan names has a closed form or a trivial resampling
loop: Wilson (`math.sqrt`), exact McNemar (`math.comb` binomial tail), paired percentile bootstrap
(`random.Random(seed).choices` over per-task differences, 10 000 draws over ≤ 100 tasks is
milliseconds), pass^k, and Miller's CLT/clustered SE (sums and squares). scipy's `bootstrap`
default is BCa, which returns NaN on degenerate data (all tasks tied) and is overkill for a
difference of binary means; the percentile interval with task-level resampling is what the
plan describes and what Miller's paper says is sufficient. The condition: `tests/test_stats.py`
must check our numbers against scipy/statsmodels (`proportion_confint(method="wilson")`,
`mcnemar(exact=True)`, `binomtest`) as **dev-only** oracles on fixed tables, the way
`errorbars/tests/oracles.py` does — otherwise "stdlib" means "unverified". Runtime stays
`hypothesis + pyyaml`; add `scipy`, `statsmodels` under a `dev` extra only.

#### Recommended for Phase 1

Keep stdlib stats; add scipy/statsmodels as test oracles. Adopt Inspect's naming (`stderr`
clustered by task, `grouped` by split/condition/contamination bin, Wilson for binary rates) and
lm-eval's rule that every estimate ships with a `_ci95` sibling; keep HELM's per-instance file
beside the aggregate so paired tests are recomputable. Card = HF dataset-card headings + Splits,
Contamination, Power (Miller formula), Exclusions, Not measured. Disclosure: OSV record as the
internal finding format, OpenSSF finder-guide + templates as the runbook, GitHub PVR REST as the
channel (target's SECURITY.md decides), `harbor view` as the only viewer.

#### Gaps: nothing found for …

- A maintained, API-model-compatible contamination checker for code benchmarks: BenchChecker is
  the right method but has no code; LLMSanitize and llm-decontaminator are dead or need training
  data. Our date-based bin stays the primary control.
- A security-specific eval card / finding schema that carries oracles, claim fidelity, scope and
  FPR: OSV covers the advisory side and SARIF the static-finding side; the eval-result side
  (EEE, Evaluation Cards) has no security fields. This is contribution territory, not a gap to fill
  by adoption.
- A confirmed free tier for Harbor Hub: no pricing page exists; revisit when sharing is needed.
