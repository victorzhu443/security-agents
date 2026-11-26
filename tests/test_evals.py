"""The eval runner itself: seeds grade as expected, summary math is right, the
report is written. These are tests OF the evals, not evals."""
import json
from pathlib import Path

import pytest

from evals.graders import json_like, load_attr, resolve_exception
from evals.run import REPO, discover, grade_case, summarize, main
from evals.graders import default_graders

CASES = REPO / "evals" / "cases"


def test_discover_finds_seed_cases_with_both_variants():
    cases = discover(CASES)
    ids = {c.id for c in cases}
    assert {"P5-hardcoded-secret-01", "P2-redact-header-regex-01",
            "P1-option-node-shape-01", "P8-text-sink-01"} <= ids
    for c in cases:
        assert (c.path / "vuln").is_dir() and (c.path / "clean").is_dir()


def test_resolve_exception_knows_builtins_and_secprim():
    assert resolve_exception("ValueError") is ValueError
    from secprim import MalformedInput
    assert resolve_exception("MalformedInput") is MalformedInput


def test_load_attr_imports_from_the_variant_dir():
    case = next(c for c in discover(CASES) if c.id == "P1-option-node-shape-01")
    vuln = load_attr(case.variant_dir("vuln"), "parser:parse")
    clean = load_attr(case.variant_dir("clean"), "parser:parse")
    assert vuln is not clean and vuln.__module__ != clean.__module__


@pytest.mark.parametrize("cid", ["P1-option-node-shape-01", "P2-redact-header-regex-01", "P8-text-sink-01"])
def test_seed_case_detects_vuln_and_clears_clean(cid):
    case = next(c for c in discover(CASES) if c.id == cid)
    row = grade_case(case, default_graders(REPO))
    assert row["error"] is None, row
    assert row["vuln"]["detected"] is True, row["vuln"]
    assert row["clean"]["detected"] is False, row["clean"]
    assert row["passed"]


def test_semgrep_seed_passes_or_skips_cleanly():
    case = next(c for c in discover(CASES) if c.id == "P5-hardcoded-secret-01")
    row = grade_case(case, default_graders(REPO))
    if row["error"] and "not installed" in row["error"]:
        pytest.skip("semgrep not installed")
    assert row["passed"], row


def test_summary_math():
    rows = [
        {"property": "P1", "origin": "historical-miss", "recall_hit": True, "precision_hit": True, "passed": True, "error": None},
        {"property": "P1", "origin": "derived", "recall_hit": False, "precision_hit": True, "passed": False, "error": None},
        {"property": "P2", "origin": "derived", "recall_hit": True, "precision_hit": False, "passed": False, "error": None},
    ]
    s = summarize(rows)
    assert s["P1"]["recall"] == 0.5 and s["P1"]["precision"] == 1.0
    assert s["P2"]["recall"] == 1.0 and s["P2"]["precision"] == 0.0
    assert s["_overall"]["cases"] == 3 and s["_overall"]["historical_misses"] == 1


def test_runner_writes_json_and_markdown(tmp_path):
    out = tmp_path / "r.json"
    rc = main(["--out", str(out), "--only", "P1-option-node-shape-01,P8-text-sink-01"])
    assert rc == 0
    data = json.loads(out.read_text())
    assert data["summary"]["_overall"]["cases"] == 2
    assert (tmp_path / "latest.md").exists()


def test_json_like_produces_the_hostile_option_shape():
    # the strategy must be able to express {"options": ["a"]}, the real trigger
    from hypothesis import find
    found = find(json_like(), lambda v: isinstance(v, dict) and isinstance(v.get("options"), list)
                 and any(not isinstance(o, dict) for o in v["options"]))
    assert isinstance(found["options"], list)


def test_plugin_graders_are_discovered(tmp_path, monkeypatch):
    import importlib, sys as _sys
    import evals.graders as G
    plug = Path(G.__file__).parent / "graders_zz_test_plugin.py"
    plug.write_text("GRADERS = {'zz_probe': object()}\n")
    try:
        _sys.modules.pop("evals.graders_zz_test_plugin", None)
        assert "zz_probe" in G.default_graders(REPO)
    finally:
        plug.unlink()
        _sys.modules.pop("evals.graders_zz_test_plugin", None)


def test_fuzz_grader_is_deterministic_and_uses_examples_first():
    case = next(c for c in discover(CASES) if c.id == "P1-option-node-shape-01")
    g = default_graders(REPO)["fuzz"]
    a = g.grade(case, "vuln"); b = g.grade(case, "vuln")
    assert a.detected and b.detected and a.metrics == b.metrics == {"via": "example"}
    # without examples, hypothesis must still be reproducible run to run
    case.expect = {**case.expect, "examples": []}
    c1 = g.grade(case, "vuln"); c2 = g.grade(case, "vuln")
    assert c1.detected == c2.detected and c1.evidence == c2.evidence
