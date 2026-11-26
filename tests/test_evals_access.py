"""Tests OF the P6 access graders: each probe flags the handler shape it exists
for and clears the reference handler; the static token check sees == / != on a
credential and nothing else."""
from pathlib import Path

import pytest

from evals.graders import Case, default_graders
from evals.graders_access import AccessGrader, TokenCompareGrader, equality_on_credential, make_request
from evals.run import REPO, discover, grade_case

GOOD = (REPO / "evals/cases/P6/limiter-success-path-only-01/clean/api.py").read_text()
EXPECT = {"target": "api:handle", "token": "tok-test", "limit": 3, "allowed_origin": "https://ok.test"}


def _case(tmp_path: Path, vuln: str, clean: str = GOOD, grader="access", **expect) -> Case:
    for name, code in (("vuln", vuln), ("clean", clean)):
        (tmp_path / name).mkdir(parents=True)
        (tmp_path / name / "api.py").write_text(code)
    return Case(id="t", property="P6", origin="derived", grader=grader, path=tmp_path,
                expect={**EXPECT, **expect})


def test_reference_handler_clears_every_probe(tmp_path):
    c = _case(tmp_path, GOOD)
    r = AccessGrader().grade(c, "clean")
    assert not r.detected and r.error is None, r
    assert r.metrics["rejected_sequence"] == [401, 401, 401, 429]


def test_limiter_after_the_gate_is_flagged_only_on_the_rejected_sequence(tmp_path):
    vuln = GOOD.replace(
        "    counts = state.setdefault(\"counts\", {})\n    key = _limit_key(request, state)\n"
        "    counts[key] = counts.get(key, 0) + 1\n    if counts[key] > state[\"limit\"]:\n        return 429, headers\n"
        "    if not _token_ok(_presented(request), state):\n        return 401, {**headers, \"WWW-Authenticate\": \"Bearer\"}\n",
        "    if not _token_ok(_presented(request), state):\n        return 401, {**headers, \"WWW-Authenticate\": \"Bearer\"}\n"
        "    counts = state.setdefault(\"counts\", {})\n    key = _limit_key(request, state)\n"
        "    counts[key] = counts.get(key, 0) + 1\n    if counts[key] > state[\"limit\"]:\n        return 429, headers\n")
    assert vuln != GOOD
    r = AccessGrader().grade(_case(tmp_path, vuln), "vuln")
    assert r.detected and r.metrics["rejected_sequence"] == [401, 401, 401, 401]
    assert [b for b in r.evidence.split("; ")] == [r.evidence]   # exactly one breach


def test_open_handler_and_wildcard_cors_are_flagged(tmp_path):
    open_handler = "def handle(request, state):\n    return 200, {'Access-Control-Allow-Origin': '*'}\n"
    r = AccessGrader().grade(_case(tmp_path, open_handler), "vuln")
    assert r.detected
    assert "no token" in r.evidence and "Allow-Origin: *" in r.evidence and "want 429" in r.evidence


def test_handler_that_rejects_the_valid_token_is_an_error(tmp_path):
    r = AccessGrader().grade(_case(tmp_path, "def handle(request, state):\n    return 401, {}\n"), "vuln")
    assert r.error and "cannot be judged" in r.error


def test_make_request_shape():
    r = make_request(token="x", origin="https://o.test", preflight=True)
    assert r["headers"] == {"Authorization": "Bearer x", "Origin": "https://o.test",
                            "Access-Control-Request-Method": "GET"}


def test_equality_on_credential_sees_tokens_not_methods():
    src = ("def f(request, state):\n"
           "    if request['method'] == 'OPTIONS':\n        pass\n"
           "    if presented == state['api_key']:\n        pass\n"
           "    ok = token != expected\n")
    hits = equality_on_credential(src)
    assert len(hits) == 2 and all("OPTIONS" not in h for h in hits)
    assert equality_on_credential("ok = hmac.compare_digest(a, b)\n") == []


def test_token_compare_grader_flags_equality_and_requires_a_working_gate(tmp_path):
    vuln = GOOD.replace("hmac.compare_digest(\n        presented.encode(\"utf-8\"), state[\"api_key\"].encode(\"utf-8\"))",
                        "presented == state[\"api_key\"]")
    assert vuln != GOOD
    c = _case(tmp_path, vuln, grader="token_compare")
    g = TokenCompareGrader()
    assert g.grade(c, "vuln").detected and not g.grade(c, "clean").detected
    no_gate = _case(tmp_path / "ng", "def handle(request, state):\n    return 200, {}\n", grader="token_compare")
    assert "gate missing" in g.grade(no_gate, "vuln").error


@pytest.mark.parametrize("cid", [c.id for c in discover(REPO / "evals" / "cases") if c.property == "P6"])
def test_corpus_case_passes(cid):
    case = next(c for c in discover(REPO / "evals" / "cases") if c.id == cid)
    row = grade_case(case, default_graders(REPO))
    assert row["passed"], row
