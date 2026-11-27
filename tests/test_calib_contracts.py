"""Step-0 contracts of the calibration pipeline (evals/calib/CONTRACTS.md): the advisory
fields on Task are defaulted, a mutation record only gains keys, Scores.requires drives
`passed`, and the shared constants exist. No model, no docker, no harbor."""
from __future__ import annotations

import json

import yaml

from evals import calib
from evals.agent import types
from evals.agent.repos import RepoConfig, load_repos
from evals.agent.tasks import tasks_jsonl
from evals.agent.types import Scores, Task

#: The record keys a mutation task had before Phase 1 (the Phase 7 harness). The new keys
#: may only be added to this set, never removed or renamed.
PHASE7_KEYS = {"task_id", "eval_id", "repo", "repo_url", "commit", "property", "description", "file",
               "find", "replace", "hidden_test", "suite_test", "container_test", "pythonpath", "agent",
               "canary", "source", "repo_path"}
ADVISORY_KEYS = {"kind", "is_negative", "advisory_id", "cwe", "project", "vuln_commit", "fix_commit",
                 "fix_files", "scope_files", "hidden_patch", "fix_test", "fp_files", "sub_scenario",
                 "library", "disclosure_date", "split", "anchor", "oracle2", "scope_rule",
                 "contamination", "task_dir"}


def _mutation_task() -> Task:
    return Task(task_id="P4-x", eval_id="security.agent.fixture.v1", repo="fixture",
                repo_url="https://example.invalid/x.git", commit="a" * 40, property="P4",
                description="drop the allow-list", file="pkg/f.py", find="a", replace="b",
                hidden_test="python -m pytest tests/security -q", suite_test="python -m pytest tests/security -q",
                container_test=["python", "-m", "pytest", "tests/security", "-q"], pythonpath=[],
                agent="agents/egress.md", canary="c")


def test_mutation_record_only_gains_default_keys():
    rec = json.loads(tasks_jsonl([_mutation_task()]).splitlines()[0])
    assert set(rec) == PHASE7_KEYS | ADVISORY_KEYS
    assert rec["kind"] == types.KIND_MUTATION and rec["scope_rule"] == types.SCOPE_SINGLE_FILE
    assert rec["is_negative"] is False and rec["split"] == "" and rec["fix_files"] == []
    assert rec["contamination"] == {} and rec["source"] == types.SOURCE_REAL_CODEBASE
    assert Task(**rec) == _mutation_task()          # round-trips with the defaults


def test_advisory_task_round_trips():
    t = Task(**{**_mutation_task().to_record(), "kind": types.KIND_ADVISORY, "source": types.SOURCE_ADVISORY,
                "advisory_id": "GHSA-aaaa-bbbb-cccc", "cwe": "CWE-918", "fix_files": ["pkg/f.py"],
                "scope_rule": types.SCOPE_REACHABLE_FROM_FIX, "split": "train",
                "contamination": {"claude-fable-5-1": "pre"}})
    assert Task(**json.loads(tasks_jsonl([t]))) == t
    assert t.find == "a"            # mutation fields are untouched by the advisory ones


def test_scores_requires_drives_passed():
    full = Scores(recall=1, fix=1, claim_fidelity=0, scope_safety=1)
    assert not full.passed
    ablated = Scores(recall=1, fix=1, claim_fidelity=0, scope_safety=1,
                     requires=["recall", "fix", "scope_safety"])
    assert ablated.passed
    assert ablated.to_dict()["requires"] == ["recall", "fix", "scope_safety"]
    assert Scores().to_dict()["requires"] == list(types.SCORE_NAMES)


def test_trial_result_seam_keys_default():
    tr = types.TrialResult(eval_id="e", task_id="t", trial=1, property="P4", agent="a", source="s",
                           scores=Scores(), stop_reason="done", failure_reason="", cost_usd=0.0,
                           usage=types.Usage(), tool_calls=0, denials=[], elapsed_s=0.0,
                           provenance=types.Provenance(mode="local", repo="r", repo_commit="c",
                                                       toolkit_version="v", toolkit_sha="s", model="m"))
    rec = tr.to_record()
    for k in ("condition", "kind", "split", "is_negative", "sub_scenario", "library", "contamination_bin"):
        assert k in rec
    assert rec["kind"] == types.KIND_MUTATION and rec["condition"] == ""


def test_repo_config_base_image_default_and_yaml():
    assert RepoConfig(name="n", url="u", local_path="p", commit="c").base_image == "python:3.12-slim"
    for cfg in load_repos().values():
        assert cfg.base_image == "python:3.12-slim"     # the four repos.yaml entries declare none


def test_calib_constants_and_cutoffs():
    assert calib.EVAL_ID == "security.calib.egress.v1" and calib.CWE == "CWE-918"
    assert calib.HARBOR_VERSION == "0.27.0" and calib.TASK_TOML_SCHEMA_VERSION == "1.4"
    assert calib.REWARD_JSON == "/logs/verifier/reward.json"
    data = yaml.safe_load(calib.CUTOFFS_FILE.read_text())
    assert data["cutoffs"]["claude-fable-5-1"] == "2026-06"
    assert data["cutoffs"]["claude-sonnet-5-5"] == "unknown"
    assert "duplicate" in calib.EXCLUSION_REASONS and "no_test_in_fix" in calib.EXCLUSION_REASONS


def test_pyproject_lists_calib_package_and_extra():
    text = (calib.REPO / "pyproject.toml").read_text()
    assert '"evals.calib"' in text
    assert f'harbor=={calib.HARBOR_VERSION}' in text
