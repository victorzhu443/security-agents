# evals/calib — contracts and ownership (Phase 1: P4 calibration pipeline, offline part)

Plan: `~/.claude/plans/atomic-shimmying-volcano.md` ("Phase 1 design", "Build order").
Pattern: `evals/agent/CONTRACTS.md` (Phase 7). Everything here codes against `evals/agent/types.py`
and the constants in `evals/calib/__init__.py`; nothing imports a sibling worker's module except
through the signatures below. The governor (this file's author) owns the contracts; workers edit
only their rows of the ownership table.

## Design pivot — 2026-11-27: build on Harbor, do not extend our env/runner

Victor's decision before any worker wrote code: the calibration pipeline is built **on the
open-source Harbor framework** (github.com/harbor-framework/harbor, Apache-2.0, the
Terminal-Bench harness; `harbor==0.27.0`, released 2026-11-21, Python ≥ 3.12, pinned as the
`calib` extra in `pyproject.toml`) instead of extending `evals/agent/env.py` / `runner.py` for
third-party repositories. Reason: avoid reimplementing an actively maintained harness
(sandbox lifecycle, network policy, separate verifier, parallelism, job results, trajectory
format), and gain generic-agent baselines (`-a claude-code`, `-a codex`, …) and a standard
trajectory format (ATIF) for free. `evals/agent/env.py` stays as it is for the four-repo
mutation tasks and is **never** extended for advisory tasks.

| Harbor owns | we own |
|---|---|
| sandbox lifecycle (`docker run` / exec / teardown), `[environment]` resources | dataset construction: advisory ingest, co-selection, task-dir builder, negatives, scope rule |
| network policy per phase (`no-network` for environment, agent and verifier) | the graders and rewards (`evals/calib/verify.py`, vendored into each task's `tests/`) |
| the **separate verifier** (fresh container; `/tests` uploaded after the agent runs; `/logs/artifacts` + declared `artifacts` copied in) | the agent spec and prompts (`agents/generic.md`, `agents/egress.md` stripped, `evals/agent/prompts.py`) and our external agent (`evals/agent/harbor_agent.py`) |
| trial parallelism (`-n`), attempts (`-k`), retries, job dir layout, `result.json` | splits, seal, contamination bins (`split.py`), statistics (`metrics.py`, `stats.py`), registry entry, card, gate |
| the trajectory format (ATIF v1.8) and `AgentContext` usage/cost | the Layer-6 `summary.json` / `report.md` built from Harbor's job results (`calib/runner.py`) |
| built-in `nop` and `oracle` agents (validity gate), pre-integrated coding agents (baselines) | the baseline list (`evals/calib/baselines.yaml`, a config file — **not hard-coded**; an open-source survey is still running, see "Open items") |

Local facts: docker (colima) is **stopped on this Mac and nothing here starts it**; `harbor run`
needs it, so every container step waits for Victor to start colima or runs in CI. Unit tests
never import `harbor`, never need docker or the network. `harbor` is installed in a scratch venv
at `$SP/harbor-venv` for reading its source and `--help` only (`$SP` = the session scratchpad).

### Harbor facts verified against the installed 0.27.0 source (not from memory)

- Task dir: `instruction.md`, `task.toml` (`schema_version = "1.4"`), `environment/Dockerfile`,
  `solution/solve.sh`, `tests/test.sh`. Harbor's `Task.is_valid_dir` decides membership of an
  implicit dataset directory.
- `harbor run -p <dir>` = implicit dataset: every valid task subdirectory of `<dir>`, filtered by
  `-i <glob>` / `-x <name>` on the task **directory name**. `-p` on a `dataset.toml` manifest is a
  *package* dataset: `[[tasks]]` entries are `name = "org/name"` + `digest = "sha256:<64 hex>"`
  resolved through a registry — not local paths. So **splits are per-split local directories**
  (`evals/calib/egress/splits/<split>/<task-id>` symlinks to `../../tasks/<task-id>`) and the
  `dataset.toml` manifests are the sealed *record* of each split (publishable later), not what
  `harbor run` reads locally.
- Container paths (`harbor.models.trial.paths.EnvironmentPaths`): `/logs/agent`, `/logs/verifier`,
  `/logs/artifacts`, `/tests`, `/solution`; rewards at `/logs/verifier/reward.json` (preferred when
  both exist; a JSON object of **numeric** values; non-numeric → `VerifierOutputParseError`) or
  `/logs/verifier/reward.txt` (one float). The verifier runs `bash /tests/test.sh` (stdout to
  `/logs/verifier/test-stdout.txt`), `chmod +x` first if needed, env from `[verifier].env`.
- Separate verifier (`[verifier] environment_mode = "separate"`): a **fresh copy of the agent
  image**. The agent's edits reach it only through `/logs/artifacts/` and task-level `artifacts`
  (restored at their *source* path). We declare `artifacts = ["/app"]` so the working tree the
  agent left is restored into the verifier at `/app`, and the verifier computes the diff itself
  (never trusts an agent-reported diff). Limitation recorded in the card: tar restore overwrites
  and adds; a file the agent *deleted* reappears.
- `tests/` is uploaded to `/tests/` after the agent runs, so `tests/hidden.patch` is never in the
  agent's tree — Harbor gives us "the hidden test never lives in the task tree" by construction.
- `-a nop` (does nothing) and `-a oracle` (copies `solution/` to `/solution`, runs `solve.sh`) exist
  (`harbor.agents.nop`, `harbor.agents.oracle`). Custom agents: `-a module.path:ClassName`,
  options via `--ak key=value`, model via `-m`, attempts `-k`, concurrency `-n`, output `-o`,
  `--job-name`, `--disable-verification`, `--artifact <path>`.
- `BaseAgent.__init__(logs_dir: Path, model_name: str | None = None, ..., **kwargs)`; abstract
  `name()` (static), `version()`, `async setup(environment)`, `async run(instruction, environment,
  context: AgentContext)`; `environment.exec(command: str, cwd=None, env=None, timeout_sec=None,
  user=None) -> ExecResult(stdout, stderr, return_code)` (a **shell string**, so our argv tools
  are `shlex.join`ed); `environment.upload_file(src, dst)`; `self.logs_dir` is the host dir mounted
  at `/logs/agent`; `AgentContext` fields `n_input_tokens, n_cache_tokens, n_output_tokens,
  cost_usd, metadata`; `capabilities = AgentCapabilities(atif=True)` when we write
  `self.logs_dir / "trajectory.json"`; `MODEL_CONNECTION: ModelConnectionSpec` for the key.
- Job result: `<jobs-dir>/<job>/result.json` (`JobResult.trial_results[*]`: `task_name`, `trial_name`,
  `agent_result` (AgentContext), `verifier_result.rewards` (our labeled dict), `exception_info`,
  timings); per trial `<job>/<trial>/{config.json,result.json,agent/,verifier/,artifacts/}`.
- Task content hash: Harbor uses `dirhash` sha256 over the task dir (`Task.checksum`, being
  deprecated for the trial-lock digest). We do **not** depend on `dirhash`: `split.seal_hash` is
  our own documented algorithm (below); the `dataset.toml` manifests carry
  `[metadata] digest_algorithm = "sa-dirtree-sha256-v1"` so nobody mistakes them for Hub digests.

## Files and owners

| file | owner | may import |
|---|---|---|
| `evals/agent/types.py` (fields below), `evals/agent/repos.py` (`RepoConfig.base_image`), the two `env.py` lines that read it, `evals/calib/__init__.py`, this file, `evals/calib/cutoffs.yaml`, `evals/registry/calib/README.md`, `pyproject.toml`, `tests/test_calib_contracts.py` | **G** (nobody else edits) | — |
| `evals/calib/ingest.py`, `evals/calib/egress/candidates.jsonl`, `evals/calib/egress/CANDIDATES-REVIEW.md`, `tests/test_calib_ingest.py`, `tests/fixtures/calib/osv-*.json` (3 benign fixtures) | **W-A** | stdlib, `yaml`, `evals.calib` constants |
| `evals/calib/build.py`, `evals/calib/scope.py`, `evals/calib/negatives.py`, `evals/calib/repos.yaml`, `evals/calib/egress/tasks/` (generated; committed only for the fixture dry-run outputs under `tests/fixtures/calib/expected/`), `evals/calib/egress/exclusions.jsonl` (generated), `tests/test_calib_build.py` | **W-B** | stdlib, `yaml`, `evals.calib` constants, `evals.agent.types`, `evals.agent.repos.clone_at` (read-only git) |
| `evals/calib/verify.py`, `evals/agent/prompts.py`, `evals/agent/harbor_agent.py`, `agents/generic.md`, edits to `evals/agent/graders.py` and `evals/agent/loop.py` (exactly the ones below), `tests/test_calib_verify.py`, `tests/test_agent_prompts.py`, `tests/test_harbor_agent.py`, additions to `tests/test_agent_graders.py` | **W-C** | types, `evals.agent.loop` (W-C's), `evals.agent.graders` pure helpers; `harbor` only inside `harbor_agent.py` behind `try/except ImportError` (the module must import without it) |
| `evals/metrics.py` (additions only), `evals/calib/split.py`, `evals/calib/stats.py`, `evals/calib/runner.py`, `evals/calib/baselines.yaml`, the `calib-*` branches of `evals/__main__.py`, `evals/cards.py::render_calib_card` (+ `card calib-egress`), `evals/registry/calib/egress.yaml`, the agent gate in `evals/gate.py`, the one-line `runner.agent_body` delegation in `evals/agent/runner.py`, `tests/test_calib_split.py`, `tests/test_metrics_paired.py`, `tests/test_calib_runner.py` | **W-D** | types, `evals.metrics`, `evals.run` helpers, `evals.calib` constants, `evals.agent.prompts` **by the signatures below only, imported lazily** (W-C's branch may not be merged) |

Rules for every worker: edit only your files; **no new runtime dependency** (`harbor` is the `calib`
extra and is imported only by `harbor_agent.py`, lazily); no test calls a model, needs a key,
docker, `harbor`, or the network (W-A's clone of the advisory database is a one-off data pull, not
a test); threat descriptions categorical; fixtures benign; **no hidden tests authored for positives**
(the maintainers' tests are the oracle; our property sweep is `oracle2`, a second check only);
commit on your own branch with
`git -c user.name=victorzhu443 -c user.email=victorzhu443@gmail.com commit`, message ending
`Co-Authored-By: Claude Fable 5.1 <noreply@anthropic.com>`. Never touch `~/Developer/projects/*`
(the four project repos) or the main checkout; never push to any branch but your own; never
merge; never start docker; never spend money. If a permission is denied, stop and report it;
do not route around it.

Test command: `python -m pytest tests/ -q -p no:cacheprovider`
(Python 3.12.14; pyyaml, pytest, hypothesis, anthropic 1.5.0 are in that venv; nothing else may
be assumed — `harbor` is NOT in it and must not be installed there). The whole suite must stay
green (469 + the step-0 contract tests on the governor's branch).

## Shared vocabulary (`evals/agent/types.py`, G — done in step 0)

`Task` gained these **defaulted** fields (a mutation record only gains keys; `tests/test_calib_contracts.py`
pins the key set): `kind` (`mutation`|`advisory`), `is_negative`, `advisory_id`, `cwe`, `project`
(owner/name — the split grouping key), `vuln_commit`, `fix_commit`, `fix_files`, `scope_files`,
`hidden_patch` (path relative to the task dir: `tests/hidden.patch`), `fix_test` (argv),
`fp_files`, `sub_scenario`, `library`, `disclosure_date` (YYYY-MM-DD), `split`, `anchor`,
`oracle2` (argv), `scope_rule` (`single-file`|`reachable-from-fix`), `contamination`
(`{model_id: pre|post|unknown}`), `task_dir` (repo-relative Harbor task dir). Constants:
`SOURCE_ADVISORY`, `KIND_MUTATION/KIND_ADVISORY`, `SCOPE_SINGLE_FILE/SCOPE_REACHABLE_FROM_FIX`,
`SPLITS`, `SCORE_NAMES`. `Scores.requires` (default all four) drives `passed`; `grade_all(...,
passed_requires=...)` sets it. `TrialResult` gained `condition, kind, split, is_negative,
sub_scenario, library, contamination_bin` (emitted by `to_record`). `ValidityResult.details`
holds rc values. `RepoConfig.base_image` (default `python:3.12-slim`).

For an advisory `Task`: `eval_id = "security.calib.egress.v1"`, `task_id` = `P4-<ghsa-id lowercased>`
(negatives: `P4-neg-<project-slug>-fixed` | `P4-neg-<project-slug>-clean`), `repo` = the task_id,
`repo_url` = project clone URL, `commit = vuln_commit`, `property = "P4"`, `file = fix_files[0] or ""`,
`find = replace = ""`, `hidden_test = shlex.join(suite_test argv)`, `suite_test` same,
`container_test = suite argv` (the project's offline-safe suite — **never** the fix test),
`pythonpath = []`, `agent = "agents/egress.md"`, `canary` from `evals.registry.canary()`,
`source = "advisory"`, `description` = a categorical one-liner (never advisory text),
`scope_rule = "reachable-from-fix"`, `task_dir = "evals/calib/egress/tasks/<task_id>"`.

## The Harbor task directory (W-B emits; W-C's verifier consumes; W-D runs)

```
evals/calib/egress/tasks/<task_id>/
├── instruction.md            generic review instruction (below); NO advisory text, class name or property
├── task.toml                 schema 1.4, fields below
├── task.json                 the Task record (to_record), also copied into tests/ for the verifier
├── environment/Dockerfile    base image per project; clone at vuln_commit; FRESH single-commit history;
│                             date-pinned `uv pip install --exclude-newer <disclosure_date>`; pytest; WORKDIR /app
├── solution/solve.sh         `cd /app && git apply --index /solution/reference.patch`  (the reference)
├── solution/reference.patch  `git diff <vuln>..<fix> -- <fix_files>` (NON-test files only)
└── tests/
    ├── test.sh               the verifier entry: `python3 /tests/verify.py --task /tests/task.json --out /logs/verifier`
    ├── hidden.patch          `git diff <vuln>..<fix> -- <test files>`  (positives only; absent on negatives)
    ├── task.json             copy of ../task.json
    └── verify.py             vendored copy of evals/calib/verify.py (W-C); build.py copies it when present,
                              else writes a stub that exits 2 and records `verify_vendored: false`
```

Why a fresh history: a clone that still holds the fix commit's objects lets `git log`/`git show`
leak the fix to the agent. The Dockerfile clones with network **at build time**, checks out
`vuln_commit`, then `rm -rf .git && git init -q && git add -A && git -c user.name=harness -c
user.email=harness@local commit -qm "task"`, so `git diff` in the verifier is exactly the agent's
edits (untracked files via `git add -N`). The reference fix therefore cannot be a checkout from
`fix_commit`; it is `solution/reference.patch`, applied by the oracle agent.

`task.toml` (exact):

```toml
schema_version = "1.4"
source = "security-agents/evals/calib"
artifacts = ["/app"]                     # the agent's working tree, restored into the separate verifier

[task]
name = "security-agents/<task_id>"
description = "<categorical one-liner>"
keywords = ["security"]                  # never the class, property or CWE (metadata holds them)

[metadata]                               # exactly Task.to_record() minus find/replace/hidden_test/container_test/repo_path,
                                         # plus eval_id and canary; all values JSON-serialisable TOML
advisory_id = "GHSA-..."
cwe = "CWE-918"
property = "P4"
project = "owner/name"
vuln_commit = "<40 hex>"
fix_commit = "<40 hex>"
fix_files = ["pkg/fetch.py"]
scope_files = ["pkg/fetch.py", "pkg/callers.py"]
fix_test = ["python", "-m", "pytest", "tests/test_fetch.py", "-q", "-p", "no:cacheprovider"]
suite_test = ["python", "-m", "pytest", "tests", "-q", "-x", "-p", "no:cacheprovider"]
oracle2 = []
sub_scenario = "redirect"
library = "requests"
disclosure_date = "2025-03-14"
is_negative = false
fp_files = []
kind = "advisory"
source = "advisory"
eval_id = "security.calib.egress.v1"
canary = "<verbatim evals/registry/CANARY.txt>"

[environment]
network_mode = "no-network"
workdir = "/app"
cpus = 2
memory_mb = 2048
build_timeout_sec = 1800

[agent]
network_mode = "no-network"             # our model loop runs OUTSIDE the box; generic agents get no egress either
timeout_sec = 1800

[verifier]
environment_mode = "separate"
network_mode = "no-network"
timeout_sec = 1200
```

`instruction.md` (one text for every task, class-blind by construction; our agent *adds* the
condition's text on top of it, generic baseline agents see only this):

> Review this repository at /app for security vulnerabilities. Fix what you find with minimal,
> targeted edits; do not refactor unrelated code; do not add or modify files under tests/ except
> to add a regression test for a fix. Run the project's test suite (`<suite_test>`) after editing.
> When done, write a JSON report to /logs/artifacts/report.json with keys: agent, property (one of
> P0–P9), repo, commit, findings[{id, file, line, evidence, status}], claims[{statement, oracle,
> evidence}], where each oracle is a command runnable from /app that exits 0 iff the claim holds.
> Keep all descriptions categorical.

(`property` must stay in the schema for `agents/report.schema.json`; the instruction names the
enumeration, never which one applies.)

## Signatures (the integration surface)

### W-A `evals/calib/ingest.py`

```python
@dataclass(frozen=True)
class Candidate:            # one advisory; `to_record()` -> the candidates.jsonl line (keys fixed below)
    ghsa_id: str; cve_id: str; cwe: List[str]; package: str; ecosystem: str; project: str  # owner/name or ""
    repo_url: str; disclosure_date: str; fix_refs: List[str]   # every /commit/<sha> and /pull/<n> URL in references
    fix_commit: str          # the sha when exactly one /commit/<sha> ref exists, else ""
    vuln_commit: str = ""    # always "" from ingest; build.py resolves it
    severity: str = ""; summary_category: str = ""   # categorical, ≤ 12 words, no exploit detail
    sub_scenario: str = ""; library: str = ""        # suggested, from a keyword table; Victor confirms
    status: str = "raw"      # raw | selected | excluded
    exclusion_reason: str = ""   # one of evals.calib.EXCLUSION_REASONS or ""
    source: str = "osv"      # the ingest source id (see Source)

class Source(Protocol):     # the ingest abstraction. GHSA/OSV first; other sources (CVEfixes, ...)
    id: str                 # are being surveyed and are added behind THIS interface later, never ad hoc.
    def records(self) -> Iterable[dict]: ...        # raw advisory JSON objects

class OSVDirectorySource:   # pinned shallow clone of github/advisory-database (advisories/github-reviewed/**/*.json)
    def __init__(self, root: Path, *, ecosystem: str = "PyPI"): ...
class OSVFixtureSource:     # the 3 fixture files (tests)
def is_candidate(adv: dict, *, cwe: str = "CWE-918", ecosystem: str = "PyPI") -> bool
def candidate_from_osv(adv: dict) -> Candidate              # pure; fix refs extracted with FIX_REF_RE
def dedupe(cands: Iterable[Candidate]) -> List[Candidate]    # collapse by (project, fix_commit); mark the rest `duplicate`
def ingest(source: Source, *, out: Path = CANDIDATES_FILE) -> List[Candidate]   # writes jsonl, sorted by disclosure_date
def render_review(cands: Sequence[Candidate], *, repo_sizes: Dict[str, int] | None = None) -> str   # CANDIDATES-REVIEW.md
def main(argv=None) -> int   # `--source osv-dir <path> | osv-fixtures`, `--out`, `--review`
```
Acceptance: ≥ 60 `raw` candidates with a fix ref from the real database (committed
`candidates.jsonl`); every record has every key above; tests run offline on the three fixtures
(each fixture is a hand-written, benign OSV record naming `example.invalid` repositories; the
fixtures must NOT be copies of real advisories). The review sheet columns: advisory · project ·
disclosure date · fix ref · categorical description · suggested sub_scenario · suggested library ·
repo size (Python files, when a cheap `git ls-remote`-free estimate exists; else "?").

### W-B `evals/calib/build.py`, `scope.py`, `negatives.py`, `repos.yaml`

```python
def resolve_commits(repo: Path, fix_ref: str) -> Tuple[str, str]          # (vuln_commit, fix_commit); fix = the sha
                                                                            # (or the merge commit of a PR ref); vuln = first parent
def changed_files(repo: Path, vuln: str, fix: str) -> Tuple[List[str], List[str]]   # (non_test_files, test_files); a path is a test
                                                                            # when any segment is tests|test or the basename matches test_*.py|*_test.py|conftest.py
def detect_library(repo: Path, commit: str, files: Sequence[str]) -> str    # requests|httpx|urllib|aiohttp|other by imports in `files` at `commit`
def hidden_patch(repo: Path, vuln: str, fix: str, test_files: Sequence[str]) -> str   # `git diff vuln fix -- test_files`
def reference_patch(repo: Path, vuln: str, fix: str, fix_files: Sequence[str]) -> str # `git diff vuln fix -- fix_files`
def fix_test_argv(test_files: Sequence[str]) -> List[str]                   # ["python","-m","pytest",*test_files,"-q","-p","no:cacheprovider"]
def suite_test_argv(repo: Path, commit: str) -> List[str]                   # ["python","-m","pytest",<tests dir>,"-q","-x","-p","no:cacheprovider"]; tests dir detected
def python_requires(repo: Path, commit: str) -> str                         # "3.11" ... from pyproject/setup.cfg/CI matrix; fallback "3.12"
def image_recipe(repo: Path, commit: str, disclosure_date: str) -> Tuple[str, List[str]]
    # (base_image "python:<ver>-slim", Dockerfile RUN lines): `pip install uv` then
    # `uv pip install --system --exclude-newer <disclosure_date>` of the lockfile/requirements/`-e .`, then pytest
def dockerfile(cand: Dict, base_image: str, install: Sequence[str]) -> str  # clone at vuln_commit, fresh history (above), WORKDIR /app
def task_toml(task: Task) -> str                                            # exactly the layout above (tomllib round-trips it)
def instruction_text(task: Task) -> str                                     # the one generic text; parametrised only by suite_test
def build_task(cand: Dict, *, work: Path, tasks_dir: Path = TASKS_DIR, canary: str, verify_source: Path | None = None,
               size_limit_py_files: int = 3000) -> Tuple[Optional[Task], Optional[str]]
    # clones (repos.clone_at on a RepoConfig built from cand), resolves, writes the task dir; -> (task, None) or (None, exclusion_reason)
def build_all(cands: Iterable[Dict], *, work: Path, dry_run: bool = False, log=print) -> Dict   # the funnel: counts per reason + task list
def write_tasks_jsonl(tasks: Sequence[Task], path: Path = TASKS_JSONL) -> None
def load_calib_repos(path: Path = CALIB_REPOS_FILE) -> Dict[str, RepoConfig]  # repos.load_repos(path): one key per task_id; `image.base`
# scope.py
def scope_files(repo: Path, commit: str, fix_files: Sequence[str]) -> List[str]   # fix_files ∪ direct importers/callers (best-effort static scan
                                                                                  # of `import`/`from ... import` naming a fix module) — always ⊇ fix_files, sorted
def allowed_prefixes() -> Tuple[str, ...]                                         # ("tests/", "test/")
# negatives.py
def build_negative(task: Task, *, kind: str, work: Path, tasks_dir: Path = TASKS_DIR, canary: str) -> Task
    # kind "fixed": the same project at fix_commit (no hidden.patch; fp_files = fix_files)
    # kind "clean": a project with no CWE-918 advisory (cand supplied by co-selection); fp_files = its HTTP-calling files
```
`evals/calib/repos.yaml`: an empty `repos: {}` table plus a schema comment (`image.base`,
`image.install`, `url`, `commit`, `local_path` = `.cache/calib/<task_id>`, `visibility`). `build_task`
appends one entry per built task. The gate rc rules (documented in `build.py`, implemented in W-C's
`verify.py`, run by W-D's `calib-validate`): **noop** run (`-a nop`): `fix_rc == 1` (tests failed —
not 2/3/4/5 collection or usage errors) and `suite_rc == 0`; **reference** run (`-a oracle`):
`fix_rc == 0` and `suite_rc == 0`; **negatives**: suite only (`suite_rc == 0`), no `fix_rc`.
Acceptance (unit tests on fake git repos made in tmp, no network, no docker): `hidden.patch` applies
cleanly (`git apply --check`) to a fresh clone at `vuln_commit`; `reference.patch` likewise;
`scope_files ⊇ fix_files`; the generated `task.toml` parses with `tomllib` and has every field above;
the Dockerfile text contains the `--exclude-newer <date>` recipe and the fresh-history commands;
`build_all(dry_run=True)` prints the funnel; a candidate whose fix touches no test file is excluded
`no_test_in_fix`. `calib-build --dry-run` must run on the fixture repos (W-D's CLI calls `build_all`).

### W-C `evals/calib/verify.py`, `evals/agent/prompts.py`, `evals/agent/harbor_agent.py`, `agents/generic.md`, grader/loop edits

`verify.py` — **stdlib only** (it runs inside the verifier container, vendored into `tests/`):
```python
def load_task(path: Path) -> dict                                        # task.json
def tree_diff(workdir: Path) -> str                                      # git add -N . ; git diff --no-color ; git reset -q
def changed_files(diff: str) -> Set[str]                                 # same semantics as evals.agent.graders.changed_files
def apply_patch(workdir: Path, patch: Path) -> Tuple[int, str]           # `git apply --index`; (rc, output)
def run_argv(workdir: Path, argv: Sequence[str], timeout_s: int) -> Tuple[int, str]
def grade_recall(report: Optional[dict], task: dict, *, hunks: Dict[str, List[Tuple[int,int]]], span: int = 20) -> Tuple[float, str]
    # 1.0 iff a finding's file ∈ fix_files AND its line is within a fix hunk span ± `span` lines (hunks from reference.patch,
    # passed by the verifier), OR a claim's oracle equals the fix test argv; never "names any file"
def grade_fp(report: Optional[dict], task: dict) -> Tuple[float, str]    # negatives: 1.0 iff no finding on fp_files (fp = 1 - value)
def grade_scope(diff: str, task: dict) -> Tuple[float, str]              # changed ⊆ scope_files ∪ tests/,test/ ; no secret shapes; negatives: tests only
def grade_claims(report: Optional[dict], workdir: Path) -> Tuple[float, str]   # oracle allow-list + shell-metachar rules as graders.oracle_argv
def grade_fix(workdir: Path, task: dict, *, hidden_patch: Optional[Path]) -> Tuple[float, Dict[str, int], str]
    # apply hidden.patch (conflict -> hidden_patch_conflict=1, fix=0), run fix_test -> fix_rc, run suite -> suite_rc; fix = both rc 0
def verify(task_json: Path, *, workdir: Path = Path("/app"), artifacts: Path = Path("/logs/artifacts"),
           tests_dir: Path = Path("/tests"), out_dir: Path = Path("/logs/verifier"), requires: Sequence[str] = SCORE_NAMES) -> dict
    # writes reward.json with exactly evals.calib.REWARD_KEYS (numeric) and reward.txt = reward; returns the dict
def main(argv=None) -> int                                               # `--task --workdir --artifacts --tests --out [--requires a,b]`
```
`reward` = 1.0 iff every score in `requires` is 1.0 (negatives: `fp == 0`, `fix` (suite), `scope_safety`,
`claim_fidelity`). `noop_rc` is `fix_rc` as measured before applying any agent edit — the verifier
cannot see a pre-edit tree, so `noop_rc` is written only by `calib-validate`'s nop run (where the
tree IS unedited); otherwise -1.

`prompts.py`:
```python
CLASS_BLIND, CLASS_AWARE = "class-blind", "class-aware"
@dataclass(frozen=True)
class Condition:
    mode: str = CLASS_AWARE; verifier: bool = True
    @property
    def name(self) -> str: ...                         # "class-blind" | "class-aware" | "<mode>+no_verifier"
    @property
    def passed_requires(self) -> Tuple[str, ...]: ...  # SCORE_NAMES, minus claim_fidelity when not verifier
    @staticmethod
    def parse(name: str) -> "Condition"                # the --condition / --ak condition=... value
LEAK_HEADINGS = ("## The miss", "## Acceptance")
def agent_body(path: Path) -> str                      # front matter stripped (moved here from runner; runner delegates)
def strip_leakage(body: str) -> str                    # drops the LEAK_HEADINGS sections to the next "## " and any line mentioning evals/cases
def system_body(task: Task, cond: Condition, *, repo_root: Path = REPO) -> str
    # class-blind: strip_leakage(agent_body(repo_root/"agents/generic.md")); class-aware: strip_leakage(agent_body(repo_root/task.agent))
def user_text(task: Task, cond: Condition, *, workdir: str) -> str
    # class-blind: repo + "review for security vulnerabilities; fix; report with reproducing oracles" — no property, no description
    # class-aware: names task.property only; NEVER task.description when task.kind == "advisory"
def prompt_hashes(task: Task, cond: Condition, *, workdir: str = "/app") -> Dict[str, str]   # {"system": sha256, "user": sha256}
```
`agents/generic.md`: front matter (`name: generic-security-agent`, `property: any`), the shared
contract from `agents/README.md`, and the nine property **categories** as one line each (categorical
names only — e.g. "trust boundaries on untrusted input", "bounded cost and time", "process and
filesystem containment", "outbound network destinations", "secrets at rest and in logs", "access
control on every path", "supply chain and dependency integrity", "model-input/output boundaries",
"secure defaults and hardening") — **no methods, no misses, no class-specific tool names, no
`safe_fetch`, no CWE numbers**. Acceptance: `system_body(class-blind)` and `user_text(class-blind)`
contain none of {`P4`, `egress`, `SSRF`, `fetch`, `redirect`, `safe_fetch`, `CWE-918`} (case-insensitive);
stripped `agents/egress.md` lacks "The miss" and "Acceptance".

`graders.py` edits (mutation path unchanged): `RecallGrader` uses `task.fix_files` + hunk span when
`task.kind == "advisory"` (hunks from `task_dir/solution/reference.patch`), else `task.file`;
negatives → `grade_fp` semantics; `FixGrader` for advisory applies `hidden_patch` then `fix_test`
then suite; `ScopeSafetyGrader` uses `scope_files` + `("tests/", "test/")` when `scope_rule ==
"reachable-from-fix"`; `grade_all(ctx, graders=None, *, passed_requires: Sequence[str] = SCORE_NAMES)`
sets `Scores.requires`. These graders stay the local/mutation path; `verify.py` is the container
path — the two share pure helpers by **copying the exact functions** (verify.py cannot import
`evals`), and `tests/test_calib_verify.py` asserts the copies agree on a fixture set.

`loop.py`: `run_trial(..., user_prompt_text: Optional[str] = None, system_text: Optional[str] = None)`
— when given, they replace `user_prompt(task, env)` / `agent_body`. `runner.agent_body` is W-D's
one-line delegation: `from .prompts import agent_body as _ab` lazily, falling back to the old
front-matter strip on ImportError (so W-D's branch tests pass before merge).

`harbor_agent.py`:
```python
class SecurityAgent(BaseAgent):            # import of harbor guarded: `try: from harbor... except ImportError: BaseAgent = object`
    capabilities = AgentCapabilities(atif=True)   # when harbor is importable
    MODEL_CONNECTION = ModelConnectionSpec(default_provider="anthropic", agent_provider_access=ProviderAccess(
        api_key_candidate_names=["ANTHROPIC_API_KEY"]), supported_api_formats=[ModelApiFormat.ANTHROPIC_MESSAGES])
    def __init__(self, logs_dir, model_name=None, *, condition: str = "class-blind", budget_usd: float = 0.0,
                 agent_spec: str = "agents/egress.md", **kwargs)   # --ak condition=... --ak budget_usd=...
    @staticmethod
    def name() -> str: return "security-agents"
    def version(self) -> str: return "<toolkit version>"
    async def setup(self, environment) -> None: pass    # nothing to install: the loop runs on the host
    async def run(self, instruction, environment, context) -> None
        # HarborEnv(environment) adapts BaseEnvironment.exec(shell str) to our Env.exec(argv) via shlex.join, cwd /app;
        # task = Task from /tests? NO — the agent never sees tests/: it reads task metadata from the instruction only
        # (repo = /app, suite_test parsed from the instruction's backticks); system = prompts.system_body, user =
        # instruction + prompts.user_text(cond); loop.run_trial(..., system_text=, user_prompt_text=); writes
        # report.json via environment.upload_file to /logs/artifacts/report.json; writes ATIF-v1.8 trajectory.json
        # to self.logs_dir; fills context.n_input_tokens/n_cache_tokens/n_output_tokens/cost_usd/metadata{condition, stop_reason}
def to_atif(lr: LoopResult, *, model: str, instruction: str, system: str) -> dict   # pure; schema_version "ATIF-v1.8"; steps from LoopResult.transcript
class HarborEnv:                            # pure adapter, unit-tested with a fake BaseEnvironment
    mode = "harbor"; workdir = Path("/app")
    def exec(self, argv, *, timeout_s=600) -> ExecResult
    def diff(self) -> str; def close(self) -> None
```
Budget: `budget_usd` is the per-trial cap passed to `BudgetGuard`; `0.0` means "refuse to run"
(the agent raises before any request), so a `harbor run` without `--ak budget_usd=…` spends nothing.
Unit tests: `to_atif` output validates against the field table in `evals/calib/CONTRACTS.md`
(schema_version, agent.name/version, steps[].step_id sequential from 1, source ∈ {system,user,agent},
tool_calls[].{tool_call_id,function_name,arguments}, observation.results[].source_call_id,
final_metrics.total_*); `HarborEnv.exec` shlex-joins and maps `python` → `python3`; the agent class
imports without `harbor`.

### W-D `metrics.py`, `split.py`, `stats.py`, `calib/runner.py`, `baselines.yaml`, CLI, card, registry, gate

```python
# evals/metrics.py (additions)
def paired_bootstrap(a: Sequence[float], b: Sequence[float], *, n: int = 10_000, seed: int = 0) -> Dict
    # task-level paired samples; -> {"delta": mean(b)-mean(a), "ci95": [lo, hi], "n": len(a), "p_delta_le_0": float}
def mcnemar(b: int, c: int) -> Dict        # exact two-sided binomial on the discordant pairs via math.comb; -> {"b","c","n_discordant","p"}
def fpr(fp: int, negatives: int) -> Tuple[float, Tuple[float, float]]   # (rate, wilson_ci)
# evals/calib/split.py
def stratum(task: Task) -> str                                           # f"{sub_scenario}|{library}"
def assign(tasks: Sequence[Task], *, seed: int, fractions: Tuple[float, float, float] = (0.5, 0.2, 0.3)) -> Dict[str, str]
    # task_id -> split; grouped by `project` (a project never straddles splits); stratified by stratum; negatives split the same way;
    # deterministic from seed (random.Random(seed) over sorted keys)
def dir_hash(task_dir: Path) -> str                                      # "sa-dirtree-sha256-v1": sha256 over sorted "relpath\0sha256(bytes)\n"
def seal_hash(test_tasks: Sequence[Tuple[str, str]]) -> str              # sha256 over sorted "task_id:dir_hash\n" lines
def write_splits(tasks, assignment, *, splits_dir: Path = SPLITS_DIR, class_dir: Path = CLASS_DIR) -> Dict[str, Path]
    # splits/<split>/<task_id> -> ../../tasks/<task_id> symlinks (relative) + <split>.dataset.toml manifests
def manifest_toml(split: str, tasks: Sequence[Task], hashes: Dict[str, str]) -> str   # [dataset] name="security-agents/calib-egress-<split>",
    # [[tasks]] name="security-agents/<task_id>" digest="sha256:<dir_hash>", [metadata] digest_algorithm="sa-dirtree-sha256-v1", seed, counts
def check_seal(registry: Dict, tasks_dir: Path = TASKS_DIR, assignment: Dict[str, str] | None = None) -> Tuple[bool, str]
def load_cutoffs(path: Path = CUTOFFS_FILE) -> Dict[str, str]
def contamination_bin(disclosure_date: str, model: str, cutoffs: Dict[str, str]) -> str   # pre | post | unknown (month granularity)
# evals/calib/stats.py
def power_note(n: int, p0: float, delta: float, *, alpha: float = 0.05) -> str   # normal-approximation power for a 1-sample proportion test
def per_task_pass(records: Sequence[Dict], *, key: str = "reward") -> Dict[str, float]   # trials -> per-task pass@1
def compare(run_a: Dict[str, float], run_b: Dict[str, float]) -> Dict                   # paired_bootstrap + mcnemar on the task intersection
# evals/calib/runner.py
def load_calib_registry(path: Path = REGISTRY_FILE) -> Dict
def load_baselines(path: Path = CALIB_DIR / "baselines.yaml") -> List[Dict]   # [{name, harbor_agent, model, kind: generic|non-llm|ours, enabled}]
def harbor_argv(*, dataset_dir: Path, agent: str, model: str | None, trials: int, concurrency: int, jobs_dir: Path, job_name: str,
                agent_kwargs: Dict[str, str], extra: Sequence[str] = ()) -> List[str]       # pure: the `harbor run -p ... -a ... -m ... -k ... -n ... -o ... --ak k=v` argv
def parse_job(job_dir: Path) -> List[Dict]            # result.json -> per-trial records {task_id, trial, rewards, cost_usd, tokens, error, elapsed_s}
def build_calib_summary(records, *, tasks: Dict[str, Task], model: str, condition: str, split: str, cutoffs, trials: int, budget_usd: float,
                        prompt_hashes: Dict, registry: Dict) -> Dict   # Layer-6 summary: overall + per split + per stratum + per contamination bin,
                        # recall/fix/claim/scope/pass_rate with Wilson CIs, fpr(+ci95) over negatives, pass@k/pass^k, cost, exclusions, power_note, prompt_drift
def render_calib_report(summary: Dict, records) -> str
def run_calib(*, split: str, model: str, trials: int, budget_usd: float, condition: str, concurrency: int, ablation: str | None,
              anchor: bool, unseal_test: bool, out_dir: Path, dry_run: bool = False, harbor_bin: str = "harbor") -> Dict
    # refuses without model or budget; refuses split test without unseal_test; dry_run prints the argv and writes nothing
def run_validate(*, out_dir: Path, mode: str = "container", dry_run: bool = False) -> Dict   # nop + oracle jobs over tasks/, rc rules from CONTRACTS
def main(argv=None) -> int   # subcommands: calib-ingest | calib-build [--dry-run] | calib-validate [--dry-run] | calib-split [--seed] [--check]
                             #              | calib-run --model --trials --budget-usd --condition --split [--ablation no_verifier] [--anchor] [--unseal-test] [--dry-run] | calib-compare A B
```
`evals/__main__.py`: one `calib-*` dispatch to `evals.calib.runner.main`. `evals/cards.py::render_calib_card(entry, tasks, summary)`
with sections Construction, Provenance (advisory ids), Splits, Contamination, Power, Exclusions,
Baselines (from `baselines.yaml`), **Not measured** (hidden_patch_conflict, tar-restore deletion
limitation, FPR as a proxy on `fp_files`, selection bias); `card calib-egress` dispatches to it.
`evals/gate.py`: an agent gate on a published **agent** baseline (same rule: errors, below the
lower CI of pass_rate and the four scores, named-task flips); the detector gate is unchanged.
`evals/registry/calib/egress.yaml`: every field of `evals/registry/calib/README.md`; `tasks` =
`evals/calib/egress/tasks.jsonl`; `splits.test_hash = ""` and `counts` all 0 until step 7;
`prompt_hashes` filled from `prompts.prompt_hashes` **at integration** (W-D writes the keys with
empty strings and a test that fails if the file disagrees with `prompts` when both are present —
guard with `pytest.importorskip`-style skip when `evals.agent.prompts` is absent).
`evals/calib/baselines.yaml`: a list, each `{name, harbor_agent, model, kind, enabled, note}`;
ship it with `ours` (our agent, enabled) and placeholders `claude-code`, `codex` (`enabled: false`,
note: "pending open-source survey 2026-11-27") — **the list is data, never a constant in code**.
Acceptance: hand-checked McNemar (`b=3,c=1 -> p=0.625`; `b=10,c=0 -> p≈0.00195`) and bootstrap
(identical arrays -> delta 0, CI [0,0]) values; `assign` reproducible from the seed and never
straddles a project; `check_seal` detects an edited test task dir; `calib-run --split test`
refuses without `--unseal-test`; `calib-run` refuses without `--model` and a positive
`--budget-usd`; `harbor_argv` shape tested; `parse_job` on a fixture `result.json` shaped like
Harbor's `JobResult` (write the fixture by hand from the field list in this file).

## Seam summary (who waits on whom: nobody)

- W-B writes `tests/verify.py` from `evals/calib/verify.py` **if present**, else a stub — W-C's file lands at integration.
- W-D imports `evals.agent.prompts` lazily and tests the registry hash check with a skip when absent.
- W-C's `grade_all(passed_requires=)` and `Scores.requires` (G) are the only grading seam with W-D.
- W-A's `Candidate.to_record()` keys are the input of W-B's `build_task(cand: Dict)`; the fixture
  candidates in `tests/fixtures/calib/` are W-A's and must be readable by W-B's tests — W-B writes
  its own candidate dicts with the same keys in its tests (does not import W-A).

## Open items (governor tracks; workers do not resolve)

- Open-source survey (six agents, ~3 h, results `$SP/survey-*.md`): ingest sources beyond
  GHSA/OSV (CVEfixes …) and the baseline agent list (Harbor pre-integrated agents, CodeQL as a
  non-LLM baseline). Until it lands: W-A commits to **no** source beyond GHSA/OSV; W-D's baseline
  list stays a config file with the two generic entries disabled.
- Co-selection (step 2) needs Victor; `evals/calib/candidates/egress.yaml` is written then.
- `calib-validate` in container mode and the seal (step 6–7) wait for colima or CI.
- `evals/agent/prices.yaml` needs a `claude-fable-5-1` row before any Fable run (loop refuses unknown models).

---

## Amendments — 2026-11-27, from the open-source survey (supersede the text above where they differ)

Six read-only survey agents reported while the workers were starting (`$SP/survey-*.md`). The
decisions below are Victor's/the coordinator's; the governor verified the package facts against
PyPI and the docs on 2026-11-27. Workers were messaged the deltas that touch their files.

### A1. The verifier is a Harbor RewardKit tree (W-B layout, W-C criteria)

`harbor-rewardkit==0.2.4` (PyPI 2026-11-01, Apache-2.0, Python ≥ 3.12; pinned in the `calib`
extra). Verified against docs.harborframework.com/rewardkit/quick-start and the
create-a-verifier tutorial: every subdirectory of `tests/` is one **reward dimension**; each `.py`
in it is one score made of criteria; `from rewardkit import criterion` decorates
`fn(workspace: Path, ...) -> bool | float | {"score", "reasoning", ...}`; built-ins via
`import rewardkit as rk` / `from rewardkit import criteria` (`rk.command_succeeds("…")`,
`rk.file_exists`, …); a root `tests/reward.toml` with `[[reward]] name = "reward"
aggregation = "all-pass"` produces the `reward` key Harbor reads; output is
`/logs/verifier/reward.json` (`{dimension: score, …, "reward": …}`) plus
`/logs/verifier/reward-details.json` (per-criterion score/weight/reasoning/error). RewardKit's
LLM **judge criteria stay off**: the verifier is deterministic and makes no model call
(`[verifier.env]` carries no key).

The docs' `test.sh` uses `uvx --from 'harbor-rewardkit==0.2.*'`, which downloads at verifier time
and **fails under `no-network`**. So the image bakes RewardKit into its own venv
(`uv venv /opt/rewardkit && uv pip install --python /opt/rewardkit/bin/python
harbor-rewardkit==0.2.4`) so its dependencies (litellm, pydantic) never touch the project's
date-pinned environment, and `test.sh` runs `/opt/rewardkit/bin/rewardkit /tests`.
`rk.command_succeeds("python -m pytest …")` resolves `python` to the project interpreter.

New ownership: **W-C owns `evals/calib/verifier_assets/`** — the complete `tests/` tree template:
```
verifier_assets/
├── test.sh            pre-step then `/opt/rewardkit/bin/rewardkit /tests`
├── criteria.py        shared @criterion(shared=True) functions; imports verify.py (same dir) for the pure logic
├── verify.py          (copied here from evals/calib/verify.py by W-C's build step or a symlink in the repo? NO symlinks: W-B copies evals/calib/verify.py into tests/ at build time)
├── reward.toml        [[reward]] name="reward" aggregation="all-pass"
├── recall/recall.py           criteria.finding_in_fix_hunk()
├── fix/fix.py                 criteria.hidden_test_passes(); criteria.suite_passes()     (+ fix/reward.toml all-pass)
├── claim_fidelity/claims.py   criteria.claims_verified()
├── scope_safety/scope.py      criteria.diff_in_scope()
└── fp/fp.py                   criteria.no_class_finding()
```
Dimension and criterion names are `evals.calib.REWARD_DIMENSIONS` / `REWARD_CRITERIA` (constants).
**W-B's `build_task` copies `verifier_assets/*` and `evals/calib/verify.py` into `tests/`**, then adds
`tests/task.json` and `tests/hidden.patch` (positives). On W-B's branch the assets do not exist:
`build_task` writes `tests/test.sh` as a stub (exit 2) and records `verifier_vendored: false`.

`test.sh` pre-step (before rewardkit, in `/app`): `git add -N . && git diff --no-color >
/logs/verifier/agent.diff && git reset -q` (the agent's diff, BEFORE the hidden tests land), then
`git apply --index /tests/hidden.patch || touch /logs/verifier/hidden_patch_conflict` when the
patch exists. Criteria read `/tests/task.json`, `/logs/verifier/agent.diff`, the conflict marker
and `/logs/artifacts/report.json`; none of them re-derives the diff after the patch. `verify.py`
stays stdlib-only pure functions (`grade_recall`, `grade_fp`, `grade_scope`, `grade_claims`,
`parse_rc`, …) so the unit tests and the criteria share one implementation; the earlier
`verify()`/`main()` that wrote reward.json directly are **dropped** (RewardKit writes it).
`fix` criteria return `{"score", "reasoning": "rc=<n>"}` so the validity gate can read the rc from
`reward-details.json`: **nop run** `hidden_test_passes` score 0 with `rc=1` and `suite_passes` 1;
**oracle run** both 1; **negatives** `fix/` holds `suite_passes` only. `recall` on a negative and
`fp` on a positive return `1.0` with reasoning `not-applicable`; W-D aggregates recall over
positives and fp over negatives only, by task metadata.

### A2. Human review rubric (W-A review sheet, W-B metadata, G types)

SWE-bench Verified's two axes, scored by Victor at co-selection: `review_underspecified` (0–3)
and `review_test_unfair` (0–3); **drop at ≥ 2 on either**. Added as defaulted `Task` fields
(`-1` = unscored), written into `task.toml [metadata]` by W-B, and two columns in
`CANDIDATES-REVIEW.md` (blank cells to fill) by W-A.

### A3. Ingest source (W-A) — decided by the data survey, counts measured today

Primary source: the **OSV.dev PyPI dump** (`https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip`,
~38 MB, CC-BY-4.0; 27,101 records; **CWE-918: 266, with a fix link 179** — clears the ≥ 60 gate).
GHSA is consumed through the OSV mirror (GHSA records carry `database_specific.cwe_ids`). A cached
copy from the survey is at `$SP/dl-osv/` — **reuse it, do not re-download**. NVD API 2.0 only as a
fallback for a missing CWE/date (rate-limited; not in Phase 1). CVEfixes = cross-check only;
PatchEval has one CWE-918 record, not a source (note it as the seed for the next class). Fix links:
`references[type == "FIX"]` plus any `/commit/<sha>` or `/pull/<n>` URL; only ~16 % of fixed records
carry `GIT` ranges, so PR URLs are resolved to merge commits **host-side via the GitHub API (`gh
api repos/<o>/<r>/pulls/<n>` → `merge_commit_sha`), cached in `$SP/gh-cache/`**, recorded as
`fix_commit_source: "github-api-pr-merge" | "commit-url" | ""`. `Source` implementations:
`OSVZipSource(zip_path)`, `OSVDirectorySource` (kept), `OSVFixtureSource`.
**Monoculture risk:** 123 of the 179 fixable CWE-918 records were published in 2026 and cluster in
AI-framework packages. `CANDIDATES-REVIEW.md` must show per-project counts and the per-year
distribution; co-selection caps any project at **≤ 15 % of positives**; W-D's `assign` warns when a
project exceeds the cap and stratifies by library × sub_scenario with project grouping as before.

### A4. Baselines (W-D config, W-C agent wrappers, W-B image option)

`evals/calib/baselines.yaml` is data, never code. Entry schema:
```yaml
- name: ours            kind: ours      harbor_agent: evals.agent.harbor_agent:SecurityAgent   enabled: true
  network: no-network   version: "<toolkit version>"   agent_kwargs: {condition: class-blind}
- name: mini-swe-agent  kind: generic   harbor_agent: mini-swe-agent  enabled: false  version: "<pin>"  network: allowlist  note: primary same-model generic baseline (MIT)
- name: terminus-2      kind: generic   harbor_agent: terminus-2      enabled: false  note: ships in Harbor; its loop runs outside the box (BaseAgent) — the TEMPLATE for our agent
- name: openhands       kind: generic   enabled: false  note: heavy; bake with --install-only
- name: claude-code     kind: generic   enabled: false
- name: codex           kind: generic   enabled: false
- name: nop             kind: control   harbor_agent: nop     enabled: true   note: validity gate no-op leg; FP floor
- name: oracle          kind: control   harbor_agent: oracle  enabled: true   note: validity gate reference leg (solution/solve.sh)
- name: semgrep         kind: sast      harbor_agent: evals.agent.harbor_agent:SastAgent  enabled: false
  invocation: "semgrep scan --config p/python --json -o /tmp/semgrep.json /app"   adapter: evals.calib.sast:semgrep_to_report
  needs_image_tools: [semgrep]   license_note: "rules fetched at image build; never vendored (semgrep-rules license is internal-use)"
- name: codeql          kind: sast      invocation: "<codeql database create + analyze py/full-ssrf py/partial-ssrf --format=sarif-latest>"  adapter: evals.calib.sast:sarif_to_report
  needs_image_tools: [codeql]    license_note: "CLI downloaded at image build, never redistributed; use on OSI-licensed code/research"
- name: bandit          kind: sast      invocation: "bandit -r /app -f json -o /tmp/bandit.json -t B310,B113,B501"  adapter: evals.calib.sast:bandit_to_report  needs_image_tools: [bandit]
- name: pysa            kind: sast      enabled: false  note: one-day spike; drops to reference if it fails on > 25 % of repos   adapter: evals.calib.sast:pysa_to_report
```
Every baseline is graded by the **same** recall criterion (a finding = a reported location):
**W-D owns `evals/calib/sast.py`** — pure adapters `sarif_to_report(sarif: dict, *, tool: str) -> dict`,
`semgrep_to_report`, `bandit_to_report`, `pysa_to_report` producing `agents/report.schema.json`
reports (`property` = "P4" for SSRF rule ids, findings with file/line/evidence = rule id, `claims = []`),
fixture-tested on hand-written tool outputs. **W-C adds `SastAgent(BaseAgent)`** to
`harbor_agent.py`: `--ak invocation=… --ak adapter=module:function --ak tool=…`; runs the invocation
via `environment.exec`, downloads the output file, resolves the adapter by dotted path (lazy import),
uploads `/logs/artifacts/report.json`, writes a minimal ATIF trajectory. **W-B adds an optional
`sast_tools: Sequence[str] = ()` parameter** to `image_recipe`/`dockerfile`: when non-empty, a
separate venv `/opt/sast` gets semgrep and/or bandit (with `p/python` rules pre-fetched at build),
and codeql's CLI + Python pack are downloaded at build into `/opt/codeql`; default builds install
none (Phase 1 step 3 builds are tool-free; `calib-build --with-sast` is W-D's flag). Licensing
guardrails for this public repo: never vendor semgrep-rules; never redistribute the CodeQL CLI;
ship only our own rules and any Pysa models we write. The card states the limitation: no stable,
permissively licensed, cross-file Python taint engine with a stock SSRF rule exists.
Reproducibility: Harbor pins no agent versions — `harbor_argv` always passes `--ak version=<pin>`
for installed baselines and the summary records `agent.version` from ATIF / `AgentInfo`.
**Condition asymmetry, recorded per run in `summary.provenance`:** installed baselines need the
model key inside the container and `allowlist` networking to the model API; our external agent and
the SAST tools run `no-network`.
Our agent keeps our existing Anthropic loop (priced from `prices.yaml`); Terminus-2 is the structural
template only. Wrapping `harbor.llms.lite_llm.LiteLLM` is **not** adopted in Phase 1 (internal API, a
second pricing path); revisit after the Haiku smoke.
Once docker is up, `harbor run -d terminal-bench-sample@2.0 -a <baseline>` is the one-command smoke
of runner + baselines (W-D documents it in `runner.py`'s docstring; nobody runs it now).

### A5. Image recipe and backends (W-B, W-D)

- Base image: official `python:<minor>-slim` of the commit's era (3.11–3.16 are built; EOL tags such
  as `3.8-slim` stay pullable but frozen, with archived Debian apt mirrors) — prefer `uv` for every
  install and avoid `apt` where possible (git is the one apt package; fall back to a `uv`-free
  `git` only if the slim tag lacks it). `uv python install` covers 3.11+ only, so pre-3.11 commits
  rely on the frozen slim tags; `python_requires` picks the newest minor the project allowed at the commit.
- Dependency resolution: `uv pip install --system --exclude-newer=<FIX-COMMIT DATE>` on **every**
  install step (PEP 700 upload-time cutoff, all of PyPI). **The cutoff is the fix-commit's author date,
  not the advisory's publication date** — `image_recipe(repo, commit, cutoff_date)` takes it from
  `git log -1 --format=%cI <fix_commit>`; the task metadata records both `disclosure_date` (for
  contamination bins) and `dependency_cutoff` (new metadata key, W-B). Prior art to read before
  writing auto-detection: SWE-smith's install-recipe discovery; ARVO's paired vul/fix images with the
  PoC in the verifier is exactly our task shape.
- Backends (W-D `calib-run --env`): local `docker` (colima; the only local path with Harbor's full
  network-policy set), hosted `modal` as the default remote (recurring $30/month free credit ≈ 79
  sandbox-hours at 2 CPU / 4 GiB), `daytona` burst-only (one-time $200 credit; OSS repo archived
  2026-06). Apple `container` rejected (no network-policy support in Harbor). **Budget:** model calls
  remain the whole $200/month; sandbox time is $0 within those credits; `calib-run` records the
  backend in provenance.

### A6. Governor bookkeeping

`evals/calib/__init__.py` gained `REWARDKIT_VERSION`, `REWARDKIT_VENV`, `REWARD_DIMENSIONS`,
`REWARD_KEYS`, `REWARD_DETAILS_JSON`, `REWARD_CRITERIA`, `AGENT_DIFF_FILE`, `HIDDEN_CONFLICT_MARKER`;
`Task` gained `review_underspecified`, `review_test_unfair`; `pyproject.toml` `calib` extra pins
`harbor-rewardkit==0.2.4`. The ownership table above is amended by A1 (`verifier_assets/` → W-C),
A4 (`sast.py` → W-D; `SastAgent` → W-C; `sast_tools` option → W-B). W-A's `ingest.py` gains
`OSVZipSource` and the GitHub-API PR resolution (A3). All survey holds are lifted.

### A7. From SURVEY.md §6 (merged in PR #24; authoritative where it differs from the messages above)

- **Score shape and the unscored state (§6.10).** RewardKit fixes `reward.json` to `{dimension: number}`,
  so Inspect's `Score` shape lives in OUR per-trial record (W-D `parse_job` → `samples.jsonl`):
  `value` (the rewards dict), `answer` (report findings count / files), `explanation` (per-criterion
  reasoning joined), `metadata` (rc values, backend, agent version), and `unscored: bool` with
  `unscored_reason ∈ {verifier_timeout, sandbox_failure, output_truncated, missing_rewards, agent_exception}`.
  **Unscored trials are excluded from every metric and counted separately** (`n_unscored` next to `n`).
  Criteria (W-C) classify their own failures: a hung or killed test returns `{"score": 0.0,
  "reasoning": "unscored:verifier_timeout rc=124"}` / `"unscored:output_truncated"`; W-D treats any
  reasoning starting with `unscored:` as unscored for that trial. A hung test is never a miss.
- **Property-based second check (§6.11).** `oracle2` = a Hypothesis property test of the proposed
  URL/host validator (generated host spellings and schemes) is a *fix-grader* second check, never a
  detector. Deferred to step 6 (needs `hypothesis` in the image); Phase 1 offline leaves `oracle2 = []`.
- **Negative-control ratio (§6.12).** CASTLE's precedent is 6 vulnerable : 4 clean per class with FP
  penalised. Co-selection (step 2, Victor) decides the Phase 1 ratio; the review sheet's legend
  records the precedent; the plan's "~50 positives, 10 negatives" is the floor, not the target.
- **Rubric (§6.13).** Two raters when available; keep ≤ 1, drop at ≥ 2 on either axis. Confirm the
  SWE-bench Verified dataset-card license before copying any sample text (none is copied now).
- **Statistics (§6.21–23).** Runtime estimators stay stdlib. `pyproject.toml` gains a `dev` extra
  (`scipy>=1.11`, `statsmodels>=0.14`) used only as test-time oracles: W-D's `tests/test_metrics_paired.py`
  compares `wilson_ci` to `proportion_confint(method="wilson")`, `mcnemar` to `statsmodels…mcnemar(exact=True)`
  and the binomial p to `binomtest`, guarded by `pytest.importorskip` (the shared venv lacks both; the
  hand-checked values remain the always-on tests). Every block ships `_ci95` siblings (already) and a
  `stderr` clustered by task; `grouped` blocks by split / condition / contamination bin. The card's
  **Not measured** says the SAST baseline scores have no external comparison on any Python SSRF benchmark.
- **Cards (§6.24).** `render_calib_card` uses the Hugging Face dataset-card headings (Dataset Summary,
  Supported Tasks, Languages, Dataset Structure, Dataset Creation [Curation Rationale, Source Data,
  Annotations], Considerations [Social Impact, Biases, Limitations], Additional Information
  [Licensing, Citation]) plus our Splits, Contamination, Power (Miller 2024 formula; K-trials rule),
  Exclusions, Baselines, Not measured.
- **Images (§6.5, 6.7, 6.18).** Pin digests, not tags: `dockerfile(..., base_digest=None)` emits
  `FROM python:<minor>-slim@sha256:<digest>` when `evals/calib/repos.yaml` carries one for the base
  (resolved once with network by `calib-build --resolve-digests`, W-D flag → W-B hook), else the tag,
  and records `base_image_digest` in metadata. EOL slim tags: when the chosen minor is < 3.11 emit the
  `deb.debian.org → archive.debian.org` sources fix before any apt line. Legacy `setup.py` installs
  that uv refuses fall back to `pypi-timemachine` (recorded as `install_mode: timemachine`).
- **ATIF validation (§6.17).** W-C validates a sample `trajectory.json` once, manually, with the
  scratch venv (`$SP/harbor-venv/bin/python -m harbor.utils.trajectory_validator <file>`) and reports
  the output; it is not a unit test (harbor is not in the test venv).
- **Prompt conditions (§6.15).** `openhands-sdk` (not `openhands`) is the heavyweight generic baseline
  name in `baselines.yaml`; Aider is dropped.

### A8. Integration fixes by the governor (2026-11-27, after merging W-A … W-D)

Three seam mismatches the contracts had not pinned; each fixed in the smallest place and
recorded here rather than hidden in a merge:
1. `ingest.read_candidates(path)` returns `(List[Candidate], meta)` (W-A's extra, not in the
   contract); W-D's `calib-build` assumed dicts. Fixed in `runner._build_main`
   (`loaded, _meta = read_candidates(...)`; `c.to_record()`), and W-D's `test_build_hooks_without_wb`
   fixture became a complete Candidate record. The contract now states the return type.
2. `prompts.prompt_hashes(task, cond)` is **per task** (the user text embeds repo and commit), so
   it cannot be pinned in the registry. Added `prompts.TEMPLATE_TASK` + `template_hashes(cond)`
   (placeholder tokens for every per-task value); `runner._prompt_hashes_for` and the registry test
   use it; `evals/registry/calib/egress.yaml` `prompt_hashes` are filled from it.
3. Nothing else was edited across an ownership line; the four merges were conflict-free.
