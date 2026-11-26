"""The Layer 6 format: registry, canary, tasks.jsonl, run-id directories, cards, CLI."""
import json
import re
from pathlib import Path

import pytest
import yaml

from evals import __main__ as cli
from evals.cards import CARDS_DIR, card, layer0_row, repo_of, what_was_missed
from evals.registry import (CANARY_FILE, REGISTRY_DIR, TASKS_FILE, build_tasks, canary,
                            load_registry, select, tasks_are_fresh)
from evals.run import REPO, discover, main as run_main, summarize

CASES = REPO / "evals" / "cases"
NAMES = {"P1": "boundary", "P2": "cost", "P3": "containment", "P4": "egress", "P5": "secrets",
         "P6": "access", "P7": "supply", "P8": "llmsep", "P9": "defaults"}


# ----------------------------------------------------------------- registry

def test_registry_has_one_entry_per_property_with_required_fields():
    reg = load_registry()
    assert {e["property"] for e in reg.values()} == set(NAMES)
    for eid, e in reg.items():
        assert eid == f"security.{NAMES[e['property']]}.v1" == e["id"]
        assert e["version"] == 1 and e["split"] == "build"
        assert e["metrics"] == ["recall", "precision"]
        assert e["task_dir"] == f"cases/{e['property']}"
        assert (REPO / e["owner_agent"]).is_file(), e["owner_agent"]
        assert e["description"].strip()


def test_registry_graders_are_exactly_the_ones_the_cases_use():
    reg = load_registry()
    used = {}
    for c in discover(CASES):
        used.setdefault(c.property, set()).add(c.grader)
    for e in reg.values():
        assert sorted(e["graders"]) == sorted(used[e["property"]]), e["id"]


def test_select_accepts_id_name_and_property_and_rejects_typos():
    reg = load_registry()
    assert select(reg, ["egress"]) == ["security.egress.v1"]
    assert select(reg, ["security.egress"]) == ["security.egress.v1"]
    assert select(reg, ["P4", "security.egress.v1"]) == ["security.egress.v1"]
    assert select(reg, ["P9", "P1"]) == ["security.defaults.v1", "security.boundary.v1"]
    with pytest.raises(ValueError):
        select(reg, ["egres"])


def test_registry_rejects_a_wrong_canary(tmp_path):
    for f in REGISTRY_DIR.glob("*.yaml"):
        (tmp_path / f.name).write_text(f.read_text())
    (tmp_path / "CANARY.txt").write_text("not the canary\n")
    (tmp_path / "cases").mkdir()
    with pytest.raises(ValueError, match="canary"):
        load_registry(tmp_path)


# ----------------------------------------------------------------- canary

def test_canary_is_one_guid_embedded_everywhere():
    want = canary()
    assert want == CANARY_FILE.read_text().strip()
    assert "canary GUID" in want and len(want.rsplit(" ", 1)[1]) == 36
    yamls = sorted(CASES.glob("*/*/case.yaml"))
    assert len(yamls) >= 54
    for y in yamls:
        assert yaml.safe_load(y.read_text()).get("canary") == want, y
    for y in REGISTRY_DIR.glob("*.yaml"):
        assert yaml.safe_load(y.read_text())["canary"] == want, y
    for line in TASKS_FILE.read_text().splitlines():
        assert json.loads(line)["canary"] == want


def test_build_tasks_refuses_a_case_without_the_canary():
    cases = discover(CASES)
    cases[0].canary = ""
    with pytest.raises(ValueError, match="canary"):
        build_tasks(cases)


# ----------------------------------------------------------------- tasks.jsonl

def test_tasks_jsonl_is_fresh_relative_to_the_case_dirs():
    # fails when a case was added or edited without `python -m evals build-tasks`
    records = build_tasks(discover(CASES))
    assert tasks_are_fresh(records), "evals/registry/tasks.jsonl is stale: run `python -m evals build-tasks`"


def test_tasks_jsonl_records_have_the_task_fields():
    lines = [json.loads(l) for l in TASKS_FILE.read_text().splitlines()]
    assert len(lines) == len(list(CASES.glob("*/*/case.yaml")))
    assert [l["task_id"] for l in lines] == sorted(l["task_id"] for l in lines)
    for rec in lines:
        assert set(rec) == {"eval_id", "task_id", "property", "origin", "grader", "expect",
                            "description", "paths", "canary"}
        assert rec["eval_id"] == f"security.{NAMES[rec['property']]}.v1"
        for p in rec["paths"].values():
            assert (REPO / p).exists(), p


def test_build_tasks_check_exits_nonzero_when_stale(tmp_path, monkeypatch, capsys):
    assert cli.main(["build-tasks", "--check"]) == 0
    stale = tmp_path / "tasks.jsonl"
    stale.write_text("{}\n")
    monkeypatch.setattr(cli, "TASKS_FILE", stale)
    assert cli.main(["build-tasks", "--check"]) == 1
    assert cli.main(["build-tasks"]) == 0           # rewrites the (patched) file
    assert tasks_are_fresh(build_tasks(discover(CASES)), stale)


# ----------------------------------------------------------------- runner layout

def _run_dir(out: Path) -> Path:
    latest = json.loads((out / "latest.json").read_text())
    return out / latest["run_id"]


def test_run_writes_run_id_directory_with_samples_summary_report(tmp_path):
    rc = run_main(["--out", str(tmp_path), "--only", "P1-option-node-shape-01,P8-text-sink-01", "--quiet"])
    assert rc == 0
    rd = _run_dir(tmp_path)
    assert re.fullmatch(r"\d{8}T\d{6}Z-([0-9a-f]{7}|nogit)", rd.name), rd.name
    samples = [json.loads(l) for l in (rd / "samples.jsonl").read_text().splitlines()]
    assert len(samples) == 4                                    # 2 tasks x 1 trial x 2 variants
    assert {s["variant"] for s in samples} == {"vuln", "clean"}
    for s in samples:
        assert {"eval_id", "task_id", "trial", "variant", "detected", "metrics", "evidence",
                "error", "elapsed_s"} <= set(s)
    summary = json.loads((rd / "summary.json").read_text())
    for key in ("run_id", "toolkit_version", "git_sha", "generated", "python", "platform"):
        assert summary[key]
    o = summary["overall"]
    assert o["n"] == 2 and o["passed"] == 2 and o["errors"] == 0
    assert o["recall"] == 1.0 and len(o["recall_ci95"]) == 2 and o["recall_ci95"][0] < 1.0
    assert o["precision_ci95"][1] == 1.0
    assert set(summary["evals"]) == {"security.boundary.v1", "security.llmsep.v1"}   # narrowed run
    assert "pass_pow_k" not in o                                 # trials == 1
    report = (rd / "report.md").read_text()
    assert "1.00 [" in report and "security.boundary.v1" in report


def test_run_with_trials_reports_pass_at_k_and_pass_pow_k(tmp_path):
    rc = run_main(["--out", str(tmp_path), "--trials", "2", "--only", "P1-option-node-shape-01", "--quiet"])
    assert rc == 0
    summary = json.loads((_run_dir(tmp_path) / "summary.json").read_text())
    o = summary["overall"]
    assert o["n"] == 2 and o["tasks"] == 1 and o["trials"] == 2
    assert o["pass_at_k"] == {"1": 1.0, "2": 1.0} and o["pass_pow_k"] == {"1": 1.0, "2": 1.0}
    assert len((_run_dir(tmp_path) / "samples.jsonl").read_text().splitlines()) == 4


def test_run_eval_selector_and_strict_on_a_broken_case(tmp_path):
    # a corpus with one case whose grader does not exist: strict must fail it
    cdir = tmp_path / "cases" / "P9" / "bad-01"
    (cdir / "vuln").mkdir(parents=True)
    (cdir / "clean").mkdir()
    (cdir / "case.yaml").write_text(
        f"id: P9-bad-01\ncanary: {canary()}\nproperty: P9\norigin: derived\ngrader: nope\nexpect: {{}}\n")
    out = tmp_path / "out"
    assert run_main(["--cases", str(tmp_path / "cases"), "--out", str(out), "--eval", "P9", "--quiet"]) == 0
    assert run_main(["--cases", str(tmp_path / "cases"), "--out", str(out), "--eval", "defaults",
                     "--strict", "--quiet"]) == 1
    summary = json.loads((_run_dir(out) / "summary.json").read_text())
    assert summary["overall"]["errors"] == 1 and list(summary["evals"]) == ["security.defaults.v1"]
    with pytest.raises(ValueError):
        run_main(["--cases", str(tmp_path / "cases"), "--out", str(out), "--eval", "nonesuch", "--quiet"])


def test_summarize_by_eval_id_carries_wilson_cis():
    rows = [{"eval_id": "security.cost.v1", "property": "P2", "origin": "derived", "id": f"t{i}",
             "recall_hit": i < 3, "precision_hit": True, "passed": i < 3, "error": None} for i in range(4)]
    s = summarize(rows, by="eval_id")
    b = s["security.cost.v1"]
    assert b["n"] == 4 and b["recall"] == 0.75 and b["precision"] == 1.0
    assert b["recall_ci95"] == [0.301, 0.954] and b["precision_ci95"] == [0.51, 1.0]
    assert s["_overall"]["passed"] == 3


# ----------------------------------------------------------------- cards

def test_layer0_rows_parse_for_every_property():
    for p in NAMES:
        row = layer0_row(p)
        assert row["invariant"] and "not found" not in row["invariant"], p
        assert row["oracle"]


def test_card_helpers_pull_repo_and_first_sentence():
    d = "smart-dispatch forecast API: ?marginal_cost= went through float(), which accepts \"nan\". Clean uses x."
    assert repo_of(d) == "smart-dispatch"
    assert what_was_missed(d).endswith('accepts "nan".')
    assert repo_of("Every project's workflow before the pinning round.") == "every project repo"
    assert what_was_missed("Flask 2.3.3 was below 2.3.5. Clean bumps.") == "Flask 2.3.3 was below 2.3.5."


@pytest.mark.parametrize("name", sorted(NAMES.values()))
def test_card_renders_every_section_and_is_committed(name):
    text = card(name)
    for h in ("## Task statement", "## Construction", "## Provenance of the historical misses",
              "## Metrics and current numbers", "## Known limitations", "## Contamination policy"):
        assert h in text, (name, h)
    assert canary() not in text          # the card is prose about the canary, not a dataset file
    assert "CANARY.txt" in text
    assert (CARDS_DIR / f"{name}.md").is_file(), f"run `python -m evals card {name} --write`"


def test_card_lists_every_historical_miss_with_a_repo():
    text = card("egress")
    for c in discover(CASES):
        if c.property == "P4" and c.origin == "historical-miss":
            assert f"`{c.id}`" in text


# ----------------------------------------------------------------- CLI

def test_cli_list_prints_every_eval_with_counts(capsys):
    assert cli.main(["list"]) == 0
    out = capsys.readouterr().out
    for p, n in NAMES.items():
        assert f"security.{n}.v1" in out
    assert "54 tasks" in out and "24 historical misses" in out


def test_cli_card_prints_and_dispatch_rejects_unknown(capsys):
    assert cli.main(["card", "P4"]) == 0
    assert "security.egress.v1" in capsys.readouterr().out
    assert cli.main(["bogus"]) == 2
    assert cli.main([]) == 2
    assert cli.main(["--help"]) == 0
