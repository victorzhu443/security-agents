"""evals.calib — the per-class calibration pipeline (Phase 1: P4 egress / SSRF, CWE-918).

Advisory-derived tasks: a third-party Python project cloned at the commit just before a
public, already-patched CWE-918 fix, built as a **Harbor task directory** and run by
`harbor run` with `evals/agent/harbor_agent.py` as the external agent. Harbor owns the
sandbox lifecycle, network policy, parallelism, the separate verifier and the trajectory
format; this package owns dataset construction, the graders that run inside the verifier,
the splits and seal, the statistics, the registry entry and the card.

    ingest.py      advisories -> egress/candidates.jsonl (+ CANDIDATES-REVIEW.md)     W-A
    build.py       candidate -> Harbor task dir (task.toml, Dockerfile, hidden.patch)  W-B
    scope.py       reachable-from-fix scope rule                                       W-B
    negatives.py   negative controls (fixed twin, clean project)                       W-B
    verify.py      pure graders + the verifier entry point vendored into tests/        W-C
    split.py       stratified, project-grouped, seeded splits; seal + check            W-D
    stats.py       power note, paired summaries                                        W-D
    runner.py      calib-* CLI: wraps `harbor run`, parses job results -> Layer 6      W-D

Read `CONTRACTS.md` in this directory before editing anything. Constants here are the
shared vocabulary; nothing in this file imports a sibling or `harbor`.
"""
from __future__ import annotations

from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
CALIB_DIR = Path(__file__).resolve().parent

#: The class this phase calibrates.
CLASS_NAME = "egress"
PROPERTY = "P4"
CWE = "CWE-918"
EVAL_ID = "security.calib.egress.v1"
EVAL_NAME = "calib.egress"
#: `[task] name` prefix in task.toml (Harbor wants org/name).
TASK_ORG = "security-agents"

#: Layout under evals/calib/egress/.
CLASS_DIR = CALIB_DIR / CLASS_NAME
CANDIDATES_FILE = CLASS_DIR / "candidates.jsonl"            # W-A output, one record per advisory
CANDIDATES_REVIEW = CLASS_DIR / "CANDIDATES-REVIEW.md"      # W-A output, Victor's co-selection sheet
SELECTION_FILE = CALIB_DIR / "candidates" / "egress.yaml"   # step 2 output (co-selection), not code
TASKS_DIR = CLASS_DIR / "tasks"                             # one Harbor task dir per task id
TASKS_JSONL = CLASS_DIR / "tasks.jsonl"                     # one evals.agent.types.Task record per line
SPLITS_DIR = CLASS_DIR / "splits"                           # splits/<split>/<task-id> -> ../../tasks/<task-id>
EXCLUSIONS_FILE = CLASS_DIR / "exclusions.jsonl"            # every excluded candidate with its categorical reason

#: Shared config files.
CUTOFFS_FILE = CALIB_DIR / "cutoffs.yaml"
CALIB_REPOS_FILE = CALIB_DIR / "repos.yaml"
REGISTRY_FILE = REPO / "evals" / "registry" / "calib" / "egress.yaml"
CARD_FILE = REPO / "evals" / "cards" / "calib-egress.md"

#: Harbor facts the pipeline is pinned to (verified against the installed 0.27.0 source,
#: 2026-11-27). Change them only with the `calib` extra in pyproject.toml.
HARBOR_VERSION = "0.27.0"
TASK_TOML_SCHEMA_VERSION = "1.4"
ATIF_SCHEMA_VERSION = "ATIF-v1.8"
#: Paths inside a Harbor container (harbor.models.trial.paths.EnvironmentPaths).
WORKDIR = "/app"                                 # the project clone; `[environment] workdir`
LOGS_AGENT = "/logs/agent"
LOGS_VERIFIER = "/logs/verifier"
LOGS_ARTIFACTS = "/logs/artifacts"               # copied into the separate verifier
TESTS_DIR = "/tests"                             # tests/ is uploaded here before test.sh runs
SOLUTION_DIR = "/solution"                       # the oracle agent copies solution/ here
REWARD_JSON = f"{LOGS_VERIFIER}/reward.json"
REWARD_TXT = f"{LOGS_VERIFIER}/reward.txt"
REPORT_ARTIFACT = f"{LOGS_ARTIFACTS}/report.json"
TRAJECTORY_FILE = "trajectory.json"              # written to the agent's logs_dir

#: Exclusion reasons (categorical; the only values `exclusion_reason` may take).
EXCLUSION_REASONS = (
    "no_fix_ref",             # advisory names no commit/PR
    "fix_ref_unresolvable",   # the ref does not resolve to a commit in the clone
    "no_test_in_fix",         # fix commit changes no test file (we do not author hidden tests)
    "not_python_project",     # repository is not a Python project at the fix
    "build_fails_at_vuln",    # date-pinned install fails at vuln_commit
    "test_needs_network",     # the fix test cannot run under no-network
    "noop_passes",            # fix test passes on the vulnerable tree (gate)
    "reference_fails",        # fix test fails after reference.patch (gate)
    "suite_fails_at_vuln",    # project suite is red before any change (gate)
    "repo_too_large",         # > 3000 Python files
    "duplicate",              # same (project, fix_commit) as a kept candidate
    "not_selected",           # left out at co-selection
    "other",                  # must come with a note
)

#: The verifier is a Harbor RewardKit tree (amendment 2026-11-27): one subdirectory of
#: tests/ per reward dimension, a root reward.toml with `aggregation = "all-pass"` producing
#: `reward`. reward.json therefore has exactly these keys (all numeric; Harbor requires that);
#: per-criterion scores and rc values live in reward-details.json.
REWARDKIT_VERSION = "0.2.4"                      # harbor-rewardkit on PyPI, 2026-11-01, Python >= 3.12
REWARDKIT_VENV = "/opt/rewardkit"                # baked into the image: the verifier runs no-network, uvx cannot fetch
REWARD_DIMENSIONS = ("recall", "fix", "claim_fidelity", "scope_safety", "fp")
REWARD_KEYS = ("reward",) + REWARD_DIMENSIONS
REWARD_DETAILS_JSON = f"{LOGS_VERIFIER}/reward-details.json"
#: Criterion names inside each dimension (the validity gate reads them from reward-details.json).
REWARD_CRITERIA = {
    "recall": ("finding_in_fix_hunk",),          # or oracle == fix test; 1.0 "not-applicable" on negatives
    "fix": ("hidden_test_passes", "suite_passes"),   # reasoning carries "rc=<n>"; nop run: hidden 0 (rc=1), suite 1
    "claim_fidelity": ("claims_verified",),
    "scope_safety": ("diff_in_scope",),          # scope_files ∪ tests/, test/; no secret shapes; negatives: tests only
    "fp": ("no_class_finding",),                 # negatives: 1.0 iff no finding on fp_files; 1.0 "not-applicable" on positives
}
#: Pre-criteria step in tests/test.sh (before rewardkit runs): the agent's diff is captured to
#: /logs/verifier/agent.diff, then tests/hidden.patch is applied; a conflict writes this marker.
AGENT_DIFF_FILE = f"{LOGS_VERIFIER}/agent.diff"
HIDDEN_CONFLICT_MARKER = f"{LOGS_VERIFIER}/hidden_patch_conflict"

__all__ = [n for n in dir() if n.isupper()]
