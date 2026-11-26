"""Tests OF the P4 egress grader: it flags a fetcher that reaches a non-public,
off-list or oversize destination, clears one that goes through safe_fetch, and
never touches the network (resolver + MockTransport are injected)."""
from pathlib import Path

import pytest

httpx = pytest.importorskip("httpx")

from evals.graders import Case  # noqa: E402
from evals.graders_egress import (ALL_SCENARIOS, EgressGrader, PUBLIC_2,  # noqa: E402
                                  TABLE, make_resolver, make_transport, scenario)
from evals.run import REPO, discover, grade_case  # noqa: E402
from evals.graders import default_graders  # noqa: E402

RAW = """
import httpx
def fetch_page(url, *, resolver, transport):
    with httpx.Client(transport=transport, follow_redirects=True) as c:
        return c.get(url).content
"""
SAFE = """
from secprim.safe_fetch import safe_fetch
def fetch_page(url, *, resolver, transport):
    return safe_fetch(url, allow_hosts=["origin.test"], max_bytes=1000,
                      resolver=resolver, transport=transport).content
"""


def _case(tmp_path: Path, vuln: str, clean: str, **expect) -> Case:
    for name, code in (("vuln", vuln), ("clean", clean)):
        (tmp_path / name).mkdir(parents=True)
        (tmp_path / name / "f.py").write_text(code)
    return Case(id="t", property="P4", origin="derived", grader="egress", path=tmp_path,
                expect={"target": "f:fetch_page", "allowed_hosts": ["origin.test"],
                        "max_bytes": 1000, **expect})


def test_every_scenario_catches_the_raw_client_and_clears_safe_fetch(tmp_path):
    g = EgressGrader()
    for name in ALL_SCENARIOS:
        c = _case(tmp_path / name, RAW, SAFE, scenarios=[name])
        if name in ("rebinding", "derived_links"):   # need a validating / link-following fetcher
            continue
        rv = g.grade(c, "vuln")
        assert rv.detected and rv.error is None, (name, rv)
        rc = g.grade(c, "clean")
        assert not rc.detected and rc.error is None, (name, rc)


def test_rebinding_scenario_catches_validate_then_connect_by_name(tmp_path):
    vuln = """
import ipaddress, httpx
def fetch_page(url, *, resolver, transport):
    host = httpx.URL(url).host
    assert all(ipaddress.ip_address(i[4][0]).is_global for i in resolver(host, None))
    with httpx.Client(transport=transport) as c:
        return c.get(url).content
"""
    c = _case(tmp_path, vuln, SAFE, scenarios=["rebinding"])
    g = EgressGrader()
    assert g.grade(c, "vuln").detected
    assert not g.grade(c, "clean").detected


def test_public_table_entries_are_really_public():
    import ipaddress
    assert ipaddress.ip_address(PUBLIC_2).is_global
    assert ipaddress.ip_address(TABLE["origin.test"]).is_global
    assert not ipaddress.ip_address(TABLE["internal.test"]).is_global


def test_resolver_flaps_in_order_and_transport_records():
    res = make_resolver(TABLE)
    first = res("flap.test", None)[0][4][0]
    second = res("flap.test", None)[0][4][0]
    assert first != second and res.calls == ["flap.test", "flap.test"]
    with pytest.raises(OSError):
        res("unknown.test", None)
    start, routes = scenario("oversize", 10)
    tr = make_transport(routes)
    with httpx.Client(transport=tr) as c:
        assert len(c.get(start).content) == 11
    assert len(tr.seen) == 1


def test_missing_target_is_an_error_not_a_clean(tmp_path):
    c = _case(tmp_path, RAW, SAFE)
    c.expect["target"] = "nope:fetch_page"
    assert EgressGrader().grade(c, "vuln").error


@pytest.mark.parametrize("cid", [c.id for c in discover(REPO / "evals" / "cases") if c.property == "P4"])
def test_corpus_case_passes(cid):
    case = next(c for c in discover(REPO / "evals" / "cases") if c.id == cid)
    row = grade_case(case, default_graders(REPO))
    assert row["passed"], row
