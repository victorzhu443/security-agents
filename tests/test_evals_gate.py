"""The regression gate (evals/gate.py) on synthetic baselines: the Wilson-bound rule,
the named-regression rule, errors, exit codes; baseline publish/read round trip; the
trend table. Tests OF the gate, not evals."""
import json
from pathlib import Path

import pytest

from evals import gate
from evals.__main__ import main as cli
from evals.metrics import wilson_ci


# ----------------------------------------------------------------- synthetic runs

def _block(prop, rows):
    n = len(rows)
    rh = sum(1 for r in rows if r["recall_hit"] and not r["error"])
    ph = sum(1 for r in rows if r["precision_hit"] and not r["error"])
    return {"property": prop, "name": prop.lower(), "split": "build", "n": n, "tasks": n,
            "recall_hits": rh, "precision_hits": ph,
            "recall": round(rh / n, 3) if n else None,
            "recall_ci95": [round(x, 3) for x in wilson_ci(rh, n)] if n else None,
            "precision": round(ph / n, 3) if n else None,
            "precision_ci95": [round(x, 3) for x in wilson_ci(ph, n)] if n else None,
            "passed": sum(1 for r in rows if r["passed"]),
            "errors": sum(1 for r in rows if r["error"]),
            "historical_misses": sum(1 for r in rows if r["origin"] == "historical-miss")}


def summary(evals, run_id="20260101T000000Z-abc1234", sha="abc1234"):
    """evals: {eval_id: [(task_id, recall_hit, precision_hit, error?), ...]} -> summary.json shape."""
    out_evals, tasks, all_rows = {}, [], []
    for eid, specs in evals.items():
        prop = {"egress": "P4", "secrets": "P5"}.get(eid.split(".")[1], "P?")
        rows = []
        for spec in specs:
            tid, rhit, phit = spec[:3]
            err = spec[3] if len(spec) > 3 else None
            row = {"id": tid, "recall_hit": rhit, "precision_hit": phit, "error": err,
                   "passed": bool(rhit and phit and not err), "origin": "derived"}
            rows.append(row)
            tasks.append({"eval_id": eid, "task_id": tid, "property": prop, "origin": "derived",
                          "grader": "x", "trials": 1, "passes": int(row["passed"]),
                          "passed": row["passed"], "error": err})
        out_evals[eid] = _block(prop, rows)
        all_rows += rows
    return {"run_id": run_id, "git_sha": sha, "toolkit_version": "0.1.1", "trials": 1,
            "generated": "2026-01-01T00:00:00+00:00", "evals_selected": list(evals),
            "overall": _block("all", all_rows), "evals": out_evals, "tasks": tasks}


def passing(prefix, n):
    return [(f"{prefix}-{i:02d}", True, True) for i in range(n)]


E1 = "security.egress.v1"
E2 = "security.secrets.v1"


def test_identical_run_passes():
    s = summary({E1: passing("P4", 5), E2: passing("P5", 5)})
    b = gate.baseline_from_summary(s, "v0", published="2026-01-01")
    d = gate.decide(b, s)
    assert d.exit_code == 0 and d.status == "PASS"
    assert not d.named and not d.problems
    assert all(r.verdict == "pass" for r in d.rows)


def test_drop_within_noise_passes_when_no_baseline_task_flips():
    base = summary({E1: passing("P4", 20)})                       # recall 1.00, bound 0.839
    b = gate.baseline_from_summary(base, "v0", published="2026-01-01")
    new = summary({E1: passing("P4", 20) + [("P4-new", False, True)]})   # 20/21 = 0.952
    d = gate.decide(b, new)
    assert d.exit_code == 0, gate.render_decision(d, b)
    assert any("within noise" in n for n in d.rows[0].notes)


def test_recall_below_lower_bound_fails_without_a_named_regression():
    base = summary({E1: passing("P4", 10)})                       # bound 0.722
    b = gate.baseline_from_summary(base, "v0", published="2026-01-01")
    new = summary({E1: passing("P4", 10) + [(f"P4-new-{i}", False, True) for i in range(10)]})  # 0.5
    d = gate.decide(b, new)
    assert d.exit_code == 1
    assert not d.named                                            # aggregate alone fails it
    assert any(f.startswith("recall") and "lower bound" in f for f in d.rows[0].failures)
    assert "GATE: FAIL" in gate.render_decision(d, b)


def test_precision_below_lower_bound_fails():
    base = summary({E1: passing("P4", 10)})
    b = gate.baseline_from_summary(base, "v0", published="2026-01-01")
    new = summary({E1: passing("P4", 10) + [(f"P4-new-{i}", True, False) for i in range(10)]})
    d = gate.decide(b, new)
    assert d.exit_code == 1
    assert any(f.startswith("precision") for f in d.rows[0].failures)
    assert not any(f.startswith("recall") for f in d.rows[0].failures)


def test_named_flip_fails_even_with_identical_aggregate():
    base = summary({E1: [("P4-a", True, True), ("P4-b", False, True)]})    # recall 0.5
    b = gate.baseline_from_summary(base, "v0", published="2026-01-01")
    new = summary({E1: [("P4-a", False, True), ("P4-b", True, True)]})     # recall 0.5, a flipped
    assert new["evals"][E1]["recall"] == base["evals"][E1]["recall"]
    d = gate.decide(b, new)
    assert d.exit_code == 1
    assert [t for t, _, _ in d.named] == ["P4-a"]
    assert not d.rows[0].failures                                 # aggregate rule did not fire
    text = gate.render_decision(d, b)
    assert "P4-a" in text and "Named regressions (1" in text


def test_task_that_failed_in_the_baseline_and_still_fails_is_not_named():
    base = summary({E1: [("P4-a", True, True), ("P4-b", False, True)]})
    b = gate.baseline_from_summary(base, "v0", published="2026-01-01")
    d = gate.decide(b, base)
    assert d.exit_code == 0 and not d.named


def test_grader_error_fails_even_when_metrics_hold():
    base = summary({E1: passing("P4", 5)})
    b = gate.baseline_from_summary(base, "v0", published="2026-01-01")
    new = summary({E1: passing("P4", 5) + [("P4-new", True, True, "semgrep: not installed")]})
    d = gate.decide(b, new)
    assert d.exit_code == 1
    assert "errors=1" in d.rows[0].failures


def test_eval_missing_from_the_run_cannot_be_evaluated():
    base = summary({E1: passing("P4", 5), E2: passing("P5", 5)})
    b = gate.baseline_from_summary(base, "v0", published="2026-01-01")
    new = summary({E1: passing("P4", 5)})                          # a narrowed run
    d = gate.decide(b, new)
    assert d.exit_code == 2 and d.status == "COULD NOT EVALUATE"
    assert any(E2 in p for p in d.problems)
    assert next(r for r in d.rows if r.eval_id == E2).verdict == "MISSING"


def test_new_eval_has_no_bound_and_is_gated_on_errors_only():
    base = summary({E1: passing("P4", 5)})
    b = gate.baseline_from_summary(base, "v0", published="2026-01-01")
    new = summary({E1: passing("P4", 5), E2: [("P5-a", False, True)]})     # recall 0 but new
    assert gate.decide(b, new).exit_code == 0
    new = summary({E1: passing("P4", 5), E2: [("P5-a", True, True, "boom")]})
    assert gate.decide(b, new).exit_code == 1


def test_baseline_task_not_graded_is_a_warning_not_a_failure():
    base = summary({E1: passing("P4", 5)})
    b = gate.baseline_from_summary(base, "v0", published="2026-01-01")
    new = summary({E1: passing("P4", 4)})                          # P4-04 removed
    d = gate.decide(b, new)
    assert d.exit_code == 0 and d.missing_tasks == ["P4-04"]
    assert "not graded in this run" in gate.render_decision(d, b)


# ----------------------------------------------------------------- publish / read

def test_publish_read_round_trip(tmp_path: Path):
    bdir = tmp_path / "baselines"
    s = summary({E1: passing("P4", 5), E2: passing("P5", 3)}, run_id="r1", sha="aaaaaaa")
    path = gate.publish(s, "v0.1.1+evals", bdir, published="2026-01-01")
    assert path == bdir / "v0.1.1+evals.json" and path.is_file()
    latest = json.loads((bdir / "latest.json").read_text())
    assert latest["label"] == "v0.1.1+evals" and latest["file"] == path.name
    by_label = gate.load_baseline("v0.1.1+evals", bdir)
    by_latest = gate.load_baseline("latest", bdir)
    assert by_label == by_latest
    assert by_label["schema"] == gate.SCHEMA and by_label["run_id"] == "r1"
    assert by_label["evals"][E1]["recall_ci95"] == s["evals"][E1]["recall_ci95"]
    assert set(by_label["tasks"]) == {t["task_id"] for t in s["tasks"]}
    assert all(v["passed"] for v in by_label["tasks"].values())
    assert (tmp_path / "TRENDS.md").is_file()                      # beside the baselines dir
    # gating the same run against what was just published passes
    assert gate.decide(by_latest, s).exit_code == 0


def test_publish_defaults_label_to_the_run_sha_and_refuses_overwrite(tmp_path: Path):
    bdir = tmp_path / "baselines"
    s = summary({E1: passing("P4", 2)}, sha="abc1234")
    assert gate.publish(s, None, bdir, published="2026-01-01").name == "abc1234.json"
    with pytest.raises(gate.GateError, match="already exists"):
        gate.publish(s, "abc1234", bdir, published="2026-01-02")
    for bad in ("latest", "../x", "a b", ""):
        with pytest.raises(gate.GateError):
            gate.publish(s, bad, bdir)


def test_load_baseline_errors_are_gate_errors(tmp_path: Path):
    with pytest.raises(gate.GateError, match="no published baseline"):
        gate.load_baseline("latest", tmp_path)
    with pytest.raises(gate.GateError, match="not found"):
        gate.load_baseline("v9", tmp_path)
    (tmp_path / "old.json").write_text(json.dumps({"schema": 0, "label": "old"}))
    with pytest.raises(gate.GateError, match="schema"):
        gate.load_baseline("old", tmp_path)


# ----------------------------------------------------------------- trends

def test_trends_table_one_row_per_baseline_oldest_first(tmp_path: Path):
    bdir = tmp_path / "baselines"
    s1 = summary({E1: passing("P4", 10)}, run_id="r1", sha="aaaaaaa")
    s2 = summary({E1: passing("P4", 10) + [("P4-new", False, True)]}, run_id="r2", sha="bbbbbbb")
    gate.publish(s1, "v0.1.1", bdir, published="2026-01-01")
    gate.publish(s2, "v0.1.2", bdir, published="2026-02-01")
    text = (tmp_path / "TRENDS.md").read_text()
    rows = [l for l in text.splitlines() if l.startswith("| v") or l.startswith("| **")]
    assert len(rows) == 2
    assert rows[0].startswith("| v0.1.1 | 2026-01-01 | 0.1.1 | `r1` | 10 | 0 | 1.00 [0.72, 1.00] | 1.00 [0.72, 1.00] | 0 |")
    assert rows[1].startswith("| **v0.1.2** (latest) | 2026-02-01 | 0.1.1 | `r2` | 11 | 0 | 0.91 [")
    assert "| label | published | toolkit | run | cases | historical misses | recall | precision | errors |" in text
    assert not any(l != l.rstrip() for l in text.splitlines())      # no trailing whitespace


def test_trends_render_handles_no_baselines():
    text = gate.render_trends([])
    assert text.count("| —") == 9


# ----------------------------------------------------------------- CLI

def _write_summary(tmp_path: Path, s, name="summary.json") -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(s))
    return p


def test_cli_gate_exit_codes(tmp_path: Path, capsys):
    bdir = tmp_path / "baselines"
    base = summary({E1: [("P4-a", True, True), ("P4-b", True, True)]})
    same = _write_summary(tmp_path, base, "same.json")
    flipped = _write_summary(tmp_path, summary({E1: [("P4-a", False, True), ("P4-b", True, True)]}), "flip.json")

    assert cli(["gate", "--baselines", str(bdir), "--summary", str(same)]) == 2
    assert "no published baseline" in capsys.readouterr().err

    assert cli(["baseline", "publish", "--label", "v1", "--summary", str(same), "--baselines", str(bdir)]) == 0
    assert cli(["gate", "--baselines", str(bdir), "--summary", str(same)]) == 0
    assert "GATE: PASS" in capsys.readouterr().out

    assert cli(["gate", "--baselines", str(bdir), "--summary", str(flipped)]) == 1
    out = capsys.readouterr().out
    assert "GATE: FAIL" in out and "P4-a" in out

    assert cli(["gate", "--against", "nope", "--baselines", str(bdir), "--summary", str(same)]) == 2
    assert cli(["baseline", "list", "--baselines", str(bdir)]) == 0
    assert "v1 (latest)" in capsys.readouterr().out
    assert cli(["gate", "--quiet", "--baselines", str(bdir), "--summary", str(same)]) == 0
    assert capsys.readouterr().out.strip().startswith("GATE: PASS")


def test_cli_gate_reads_the_run_latest_json_points_to(tmp_path: Path):
    bdir, rdir = tmp_path / "baselines", tmp_path / "results"
    s = summary({E1: passing("P4", 3)}, run_id="rX")
    (rdir / "rX").mkdir(parents=True)
    (rdir / "rX" / "summary.json").write_text(json.dumps(s))
    (rdir / "latest.json").write_text(json.dumps({"run_id": "rX"}))
    assert cli(["baseline", "publish", "--label", "v1", "--results", str(rdir), "--baselines", str(bdir)]) == 0
    assert cli(["gate", "--results", str(rdir), "--baselines", str(bdir)]) == 0
    (rdir / "latest.json").write_text(json.dumps({"run_id": "gone"}))
    assert cli(["gate", "--results", str(rdir), "--baselines", str(bdir)]) == 2


# ----------------------------------------------------------------- the committed baseline

def test_committed_latest_baseline_is_well_formed():
    b = gate.load_baseline("latest")
    assert b["schema"] == gate.SCHEMA and b["label"]
    assert b["overall"]["n"] == len(b["tasks"]) > 0
    assert set(b["evals"]) == {t["eval_id"] for t in b["tasks"].values()}
    trends = gate.TRENDS.read_text()
    assert b["label"] in trends and b["run_id"] in trends
