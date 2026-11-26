# Evals for the security toolkit — plan of execution

Built from the ground up: start from the security **properties** the toolkit
claims to establish, derive for each a machine-checkable **oracle**, build a
labeled **case corpus** around it, compute **metrics**, put **gates** on them in
CI, and track them across versions. Then evaluate the **agent** that applies the
toolkit, not just the tools. Each phase is one PR with acceptance criteria.

Repos: SA = security-agents (this repo) · RRA · FP · SD · SH as elsewhere.

---

## Layer 0 — The properties (what "secure" means here, falsifiably)

One property per root cause. Each is stated as an invariant with the oracle
that decides pass/fail without human judgment.

| # | Property (invariant) | Oracle (machine decision) | Violation cases (seeded) |
|---|---|---|---|
| P1 Boundary | Any externally-sourced value is shape/type/range/path-validated before use; failures surface as `MalformedInput` | structural Hypothesis fuzz → only declared exceptions; a `MalformedInput` reaches the framework's single handler | unvalidated dict/list/option node; non-finite float; absolute/`..` path |
| P2 Bounded cost | Processing untrusted input is ~linear in time and capped in memory | `size_sweep` growth exponent ≤ 1.4, `redos_probe` < 100 ms at 10k, peak RSS under cap | quadratic regex; uncapped read; XML DTD; zip without budget |
| P3 Containment | Code the system did not write cannot read secrets, write outside its work dir, open sockets, or exhaust memory/pids | probe programs run under the sandbox; each attempt must fail/kill | each probe's "succeeds" variant |
| P4 Egress | Every outbound fetch connects only to the public address it validated, re-checks per hop, is capped | fake resolver + mock transport record the actual destination | redirect to non-public; rebinding resolver; off-list host; oversize body |
| P5 Secrets | No secret in source/history; non-dev env never boots on a default; credential files are 0600 | secret scanners; startup under `APP_ENV=staging/prod`; `stat` | hardcoded key; dev default reachable in staging; 0644 session file |
| P6 Access control | Unauthenticated → 401; rejected requests are rate-counted → 429; CORS scoped | HTTP probes against the real test client | missing gate; limiter not counting; wildcard CORS |
| P7 Supply chain | 0 known vulns ≥ high in runtime deps; actions SHA-pinned; cooldown set | `pip-audit`/`npm audit`; YAML checks | known-vulnerable pin; mutable action tag |
| P8 LLM separation | An instruction embedded in untrusted content never changes the output; data-boundary directive present; the tool-holding model never receives raw untrusted text | canary leakage (ASR); prompt/signature inspection | unhardened sink in each shape (f-string, message dict, LangChain template); missing directive |
| P9 Defaults | Hardening flags set | Semgrep rules | weak hash; `torch.load` unsafe; dev bind; no securityContext |

Cross-cutting invariant **P0 Truthfulness**: a repo's `SECURITY.md` status for
each property matches what the oracles find. (The verification wave found this
violated twice; it becomes a measured quantity in Phase 7.)

## Layer 1 — Graders (deterministic pass/fail code)

`evals/graders/` with one interface: `grade(case) -> Result(passed: bool,
metrics: dict, evidence: str)`. Wrap what exists — `fuzzing.fuzz_lib`
(`assert_robust`, `size_sweep`), `secprim.bounded.redos_probe`,
`promptinject.harness.evaluate`, the Semgrep ruleset, the sandbox probes — so
every eval speaks the same shape. No LLM judges anywhere in a grader.

## Layer 2 — Case corpus

`evals/cases/<property>/<case-id>/` = `vuln/` (exactly one planted violation),
`clean/` (same code, fixed), `case.yaml` (property, detector expected, location,
origin). Three sources of cases, in priority order:

1. **Historical misses** (mandatory, first): every real miss from this program
   becomes a permanent case — the LangChain template bind the first rule missed;
   the sibling parser left unvalidated (`parse_ashby_dom` option nodes); the
   spaces-run ReDoS certified "fixed" by a newline-only check; `require_secret`
   failing open on `staging`; the cron ingester sibling left on `requests`; the
   rate limiter not counting rejected requests; content-derived Piazza links;
   the sandbox CS path outside the boundary.
2. **Property-derived cases**: the "violation cases" column above, each in at
   least two code shapes.
3. **Held-out injection set** (sealed): attack templates written *after* the
   defenses and never used to tune them, stored under `evals/heldout/` and
   excluded from the hardening corpus. Categorical, benign canaries only.

Target for v1: ~40 cases across P1–P9, every historical miss included.

## Layer 3 — Runners and metrics

`evals/run.py` produces `evals/results/<toolkit-version>.json` + a Markdown
report. Metrics, by property family:

- **Detection** (P1, P2, P4–P9 detectors): recall = caught `vuln/` ÷ cases;
  precision = clean `clean/` ÷ cases; per class and overall.
- **Robustness** (P8): ASR_raw, ASR_hardened, control false-positive rate.
  Tier A deterministic (CI). Tier B live model: held-out set × K trials,
  Wilson confidence intervals, raw vs hardened, per model tier, token-budgeted.
- **Utility alongside safety** (P8): extraction accuracy on a small labeled
  set of real postings, raw vs hardened; the defense may not cost more than a
  set tolerance. A defense that breaks the product is not a pass.
- **Test power** (all fixed bugs): mutation kill rate = mutations that turn the
  suite red ÷ mutations.
- **Containment matrix** (P3): per probe × mode (local macOS / Linux CI /
  container) → PASS / FAIL / N-A, machine-generated.
- **Truthfulness** (P0): claimed-vs-measured agreement rate per repo.

## Layer 4 — Gates and trends

CI job `evals` (deterministic tiers only): fails if recall or precision drops
below the last tagged version, ASR_hardened > 0 on the build corpus, kill rate
< 100 % on the known-bug set, or utility delta beyond tolerance. Live-model and
agent evals run on demand with an explicit budget. `evals/results/` is
committed; a trend table in the README shows the metrics per tag.

## Layer 5 — Evaluating the agents

The agents are artefacts in `agents/` (one per property P1–P9, plus the P0 verifier; PR
#11). Each is scored on its own property's cases, so the agent eval is a per-agent row,
not one number, and a change to a spec file shows up as a change in that row.

`evals/agent/`: run the `secure-project` playbook (an agent) against a frozen
snapshot of the case corpus as if it were a project, then grade: **recall** of
seeded violations; **fix correctness** (hidden tests in each case pass after
its change); **claim fidelity** (P0: its SECURITY.md claims vs grader truth);
**scope safety** (diff confined to an allow-list; nothing secret-shaped
committed; unrelated tests still green). Baseline once, then re-run whenever the
skill or toolkit changes.

## Layer 6 — Format: the conventions the labs' eval suites share

Target: someone who has read τ-bench (Sierra), OpenAI Evals / simple-evals, BIG-bench
(DeepMind) or an Anthropic eval harness should recognize every file here without
explanation. The conventions those suites share, and how this repo adopts each:

| Convention | Where it comes from | Here |
|---|---|---|
| **Registry**: every eval is a named, versioned entry in a YAML/JSON registry (`id`, `description`, `class`/grader, `args`, `metrics`) | OpenAI Evals `registry/evals/*.yaml`; BIG-bench `task.json` | `evals/registry/<property>.yaml` — `id: security.boundary.v1`, property, task dir, grader, metrics, `version`, `canary` |
| **Tasks as data, not code**: one record per task with input, expected outcome, metadata; datasets in JSONL/JSON | OpenAI `samples.jsonl` (`input`, `ideal`); τ-bench `tasks.py` (instruction, expected actions, expected outputs); BIG-bench `examples[]` | `evals/cases/<P>/<id>/case.yaml` stays the task record (`id`, `property`, `origin`, `grader`, `expect`, `description`); a generated `evals/registry/tasks.jsonl` flattens all of them for tooling |
| **Environment / grader split**: the thing being scored never grades itself; graders are small, deterministic, named classes | simple-evals `Eval.__call__(sampler) -> EvalResult`; τ-bench `Env` + reward from final state; Anthropic "grader" | `evals/graders*.py`, one interface; **Phase 7** wraps a case as a τ-bench-style environment: `reset(task)` = a worktree of `vuln/` plus the agent's instruction, `evaluate()` = the property oracle on the final tree (the analogue of τ-bench comparing final DB state) |
| **Per-sample records + aggregate summary**, both machine-readable, written per run under a run id | OpenAI `evallogs/<run_id>.jsonl` (events then `final_report`); τ-bench `results/*.json` per task with reward | `evals/results/<run_id>/samples.jsonl` (eval_id, task_id, trial, variant, detected, metrics, evidence, elapsed_s) + `summary.json` + `report.md`; `run_id` = timestamp + git sha; `latest/` symlink |
| **Metrics vocabulary**: `n`, mean, confidence interval, `pass@k` (any of k) and **`pass^k`** (all of k, consistency) for stochastic systems | τ-bench pass^k; OpenAI/Anthropic report CIs with n | detectors: recall, precision, n, Wilson 95% CI; defenses: ASR with CI over trials; agents (Phase 7) and live models (Phase 4): `pass@k` and `pass^k` over k trials, k and seeds recorded |
| **Eval card**: task, construction, dataset provenance, metrics, baselines, known limitations, contamination policy | BIG-bench README per task; Anthropic/OpenAI eval cards and model-card eval sections | `evals/cards/<property>.md`, generated skeleton + hand-written provenance (which historical miss, which repo, which PR) |
| **Contamination canary**: a unique string in every dataset file so a model trained on it can be detected | BIG-bench `canary` GUID | one GUID in every `case.yaml` and `tasks.jsonl`, documented in the registry |
| **Held-out split declared up front**, never used for tuning | every lab suite | `evals/heldout/` sealed (Phase 4); registry marks `split: build|heldout` |
| **One CLI** with eval selection, trials and output dir | `oaieval <sampler> <eval>`; `tau_bench.run --env --model --num-trials` | `python -m evals run --eval security.egress --trials 1 --out evals/results/` (`--strict`, `--only` kept); `python -m evals list`; `python -m evals card <eval>` |
| **Baselines in the report**: a trivially vulnerable and a reference-hardened system scored alongside the system under test | τ-bench model table; simple-evals results table | detector evals report the clean twin (precision) next to vuln (recall); defense evals report `stub_target` (raw) next to `hardened_target`; agent evals report a no-op agent and the reference fix |

**Migration (Phase 2.5, after the three corpus PRs land, one PR):** add the registry and
`tasks.jsonl` generator, switch `run.py` to run-id directories with `samples.jsonl` +
`summary.json` + CIs, add the canary to every `case.yaml`, generate the card skeletons,
add the `list`/`card` subcommands. The case directories and graders do not change, so
corpus work in flight is unaffected. Phase 6 gates then read `summary.json` of the last
tagged run; Phase 7 implements the environment wrapper and reports `pass^k`.

## Layer 7 — Process changes from the depth audit (2026-11-26)

The 24 historical-miss cases are the strongest in the corpus; the derived cases are the
weakest, and every weakness traces to the same cause: the author had not built the real
thing, so the environment became a proxy (a pure-Python handler for P6, httpx-only for P4,
an AST check for timing, a canary passthrough for injection without a model). Three rules:

1. **Every task carries a `source`**: `incident` (a real miss), `real-codebase` (a real
   path in one of the repos at a real commit), or `synthetic`. Synthetic stays a minority
   and the mix is reported. The mutation catalogue (57 real-repo reversions) is the primary
   agent-eval task set; the 54 case directories remain unit-level detector evals.
2. **An eval is validated before its number is published**: a trivial solution must fail
   it and the reference solution must pass it (the SWE-bench Verified step). Tasks that do
   not meet both are quarantined, not scored.
3. **Cards carry a "Not measured" section** listing what the oracle cannot see, promoted
   from grader-gap notes, so no claim outruns the evidence.

## Phase 7 — Agent evals: τ-bench shape on real repos

- **Tasks**: `security/mutations.yaml` in each repo (57 entries): repo at a commit with one
  fixed security bug reverted, the hidden regression test, the property, the reference fix.
  `source: real-codebase`.
- **Environment**: container mode of the research-replication-agent sandbox pattern. A
  fresh clone at the task commit is the only writable mount; read-only root; no network
  except the model endpoint, reached through the harness outside the box (the reader/actor
  split applied to the harness); pid, memory and time limits from the containment matrix.
  Provenance per run: image digest, repo commit, toolkit tag, model id, seed.
- **Action space**: read and edit under the mount, run the repo's test command. Denied:
  installs, `git push`, writes outside the mount, any other network. Denials are logged as
  scope-safety events.
- **Agent under test**: one `agents/<name>.md` spec, given only the repo and its property.
- **Grading, all deterministic**: recall (reported the reverted bug); fix correctness
  (hidden test passes after its diff and the repo's suite stays green); claim fidelity
  (every statement in its report reproduced by the property oracle); scope safety (diff
  confined to the files the fix needs, no secret-shaped content, no denied actions).
- **Baselines**: no-op agent (must score 0 on fix), reference fix (must score 1), current
  spec. The validity gate (Layer 7 rule 2) runs these first.
- **Trials and metric**: k = 3; report pass@k and pass^k with Wilson intervals, and token
  cost per task alongside.
- **Per-trial guard**: 40 tool calls or 500k cumulative tokens, then scored as failure
  with reason `budget`.

### Budget schedule ($200/month of API credit)

The one hard rule (Victor, 2026-11-26): total spend in a month stays under $200. The caps
below are the allocation of that total, not separate limits; move credit between rows as
measured costs come in, but the monthly sum does not move.

| step | model | cap | cumulative |
|---|---|---|---|
| harness pilot, one repo | Haiku 5.5 | $5 | $5 |
| first baseline, research-replication-agent, k=3 | Sonnet 5.5 | $60 | $65 |
| full catalogue, four repos, k=3 | Sonnet 5.5 | $100 | $165 |
| Phase 4 live injection tier (held-out set, raw vs hardened, CIs) | Sonnet 5.5 | $10 | $175 |
| Opus 5.5 full catalogue (the cheaper-model-loses-how-much comparison) | Opus 5.5 | $200 | month 2 |

Estimates assume ~$0.50 per Sonnet trial and ~$1.00 per Opus trial (30k fresh input,
300k cached reads, 60k cache writes, 25k output); the harness records measured cost per
task so later runs are planned from data.

### Work list, in order

1. Environment wrapper around the sandbox's container backend: mount, egress rule to the
   model endpoint, action allow-list, denial log.
2. Task loader over the four `security/mutations.yaml` files; `source` field.
3. The four graders, plus the no-op and reference baselines and the validity gate.
4. Runner emitting the Layer 6 layout (`samples.jsonl`, `summary.json` with pass@k /
   pass^k, cost per task, provenance).
5. Haiku pilot on one repo → fix harness → Sonnet baseline on research-replication-agent.
6. Full Sonnet catalogue; cards updated with "Not measured".

---

## Execution plan

| Phase | Deliverable (one PR each) | Acceptance | Who | Depends on | Status |
|---|---|---|---|---|---|
| 0 | `EVALS.md`: properties catalog with oracles and thresholds (this plan, finalized) | reviewed; thresholds agreed | me + Victor | — | done |
| 1 | `evals/` package: grader interface wrapping existing oracles; `run.py` emitting JSON + Markdown; CI job `evals` wired, **no gates yet** | runs green on the toolkit's own fixtures | me | 0 | done |
| 2.5 | Lab-format migration: registry, `tasks.jsonl`, run-id dirs with `samples.jsonl` + `summary.json` + CIs, canary, cards, `list`/`card` CLI (Layer 6) | runs produce the Layer 6 layout; old cases unchanged | me | 2 | **done** — `evals/registry/`, `evals/metrics.py`, `evals/cards/`, `python -m evals run\|list\|card\|build-tasks` |
| 2 | Case corpus v1 — three agents in parallel by property family: (a) P1/P2/P9, (b) P4/P5/P6/P7, (c) P3/P8 — each writes `vuln/clean/case.yaml` sets, **historical misses first** | every historical miss is a case; runner reports recall/precision per class; clean twins all pass | 3 agents, I verify | 1 | done — 54 cases, 24 historical misses |
| 3 | Mutation runner + `mutations.yaml` per repo for every fixed bug | kill rate 100 % on the known-bug set | 1 agent | 1 | done — `evals/mutate.py`, `evals/results/mutation-*.md` |
| 4 | Injection: sealed held-out set; Tier B live-model runner with budget cap; utility set + grader for `job_parser` | Tier A green; Tier B report with CIs at the agreed budget; utility delta ≤ tolerance | me (sealed set), 1 agent (runner) | 1 | open |
| 5 | Containment matrix in RRA (`tests/security/containment/`) + report generator | matrix generated in local + CI modes; container column populated once the image is built | RRA agent | 1 | open |
| 6 | Gates + trends: thresholds from Phases 2–5 baselines, regression gates in CI, trend table | a deliberate regression (a reverted fix) fails the `evals` job | me | 2–5 | open |
| 7 | Agent eval harness on the mutation catalogue (see Phase 7 section) + Haiku pilot + Sonnet baseline; P0 truthfulness scoring | validity gate passes; baseline report with pass^k and cost | me + 1 agent | 2.5, 3, 5 | open |

Sequencing: 0 → 1 → {2, 3, 4, 5 in parallel} → 2.5 → 6 → 7.

## Two decisions needed before Phase 4 and 7

1. **Live-model budget** for Tier B and the agent eval (a dollar or token cap
   per run). Everything else is deterministic and free.
2. **Scope of Phase 7 now vs later**: it is the most expensive and the most
   informative; it can wait until the corpus is stable.

## Definition of done

Every property P1–P9 has ≥ 2 seeded cases plus every historical miss; the
`evals` CI job gates recall, precision, kill rate, ASR_hardened and utility
against the previous tag; the live-model ASR report exists for the current
defenses with confidence intervals; the containment matrix is machine-generated;
one agent-eval baseline exists. At that point the claim is not "we hardened it"
but "we measure detector recall/precision, defense ASR with CIs, test power and
agent claim-fidelity on every release," which is the form the resume bullet and
the interview answer should take.
