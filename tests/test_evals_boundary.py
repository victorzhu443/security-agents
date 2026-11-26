"""Tests OF the `refuse` plugin grader (evals/graders_boundary.py): it detects a
known-bad target for every input kind, clears the known-good twin, treats a
refused `accept` input as an error, and leaves the stdlib alone afterwards."""
import textwrap
import zipfile
from pathlib import Path

import pytest

from evals.graders import Case, default_graders
from evals.graders_boundary import GRADERS, RefuseGrader, _NAMED
from evals.run import REPO, discover, grade_case

CASES = REPO / "evals" / "cases"
G = RefuseGrader()


def _case(tmp_path: Path, expect: dict, vuln_src: str, clean_src: str, mod: str = "m") -> Case:
    for variant, src in (("vuln", vuln_src), ("clean", clean_src)):
        d = tmp_path / variant
        d.mkdir(exist_ok=True)
        (d / f"{mod}.py").write_text(textwrap.dedent(src))
    return Case(id="T-refuse", property="P1", origin="derived", grader="refuse",
                expect={"target": f"{mod}:f", **expect}, path=tmp_path)


def _both(case: Case):
    v, c = G.grade(case, "vuln"), G.grade(case, "clean")
    assert v.error is None and c.error is None, (v, c)
    return v, c


def test_refuse_is_registered_as_a_plugin():
    assert "refuse" in GRADERS
    assert default_graders(REPO)["refuse"] is GRADERS["refuse"]


def test_nonfinite_float_detected_and_finite_float_cleared(tmp_path):
    case = _case(tmp_path, {"inputs": "nonfinite", "accept": "finite_ok", "refuse": ["MalformedInput"]},
                 "def f(v): return float(v)\n",
                 "from secprim import finite_float\ndef f(v): return finite_float(v, 'v')\n")
    v, c = _both(case)
    assert v.detected and "'nan'" in v.evidence
    assert not c.detected and c.metrics["refused"] == len(_NAMED["nonfinite"])


def test_path_escape_detected_and_contained_path_cleared(tmp_path):
    case = _case(tmp_path, {"inputs": "path_escape", "accept": "path_ok", "refuse": ["MalformedInput"]},
                 "from pathlib import Path\nR = Path('/srv/root')\ndef f(p): return R / p\n",
                 "from secprim import contained_path\ndef f(p): return contained_path('/srv/root', p)\n")
    v, c = _both(case)
    assert v.detected and "../outside.txt" in v.evidence
    assert not c.detected


def test_zip_member_counts_decompressed_bytes_so_read_then_raise_is_detected(tmp_path):
    # the vuln DOES raise TooLarge — but only after decompressing the whole member
    expect = {"inputs": [{"kind": "zip_member", "member": "big.xml", "size": 3_000_000}],
              "accept": [{"kind": "zip_member", "member": "big.xml", "size": 2000, "fill": "random"}],
              "refuse": ["TooLarge"], "max_read": 100_000}
    case = _case(tmp_path, expect, """
        import zipfile
        from secprim import TooLarge
        def f(p):
            with zipfile.ZipFile(p) as z:
                raw = z.read('big.xml')
            if len(raw) > 1_000_000: raise TooLarge('late')
            return raw
        """, """
        import zipfile
        from secprim import TooLarge
        def f(p):
            with zipfile.ZipFile(p) as z:
                info = z.getinfo('big.xml')
                if info.file_size > 1_000_000: raise TooLarge('early')
                return z.read(info)
        """)
    v, c = _both(case)
    assert v.detected and "read before refusing" in v.evidence and v.metrics["max_bytes_read"] == 3_000_000
    assert not c.detected and c.metrics["max_bytes_read"] == 0


def test_zip_counting_patch_is_restored(tmp_path):
    orig = zipfile.ZipFile.open
    case = _case(tmp_path, {"inputs": [{"kind": "zip_member", "size": 10}], "refuse": ["TooLarge"]},
                 "def f(p): return p\n", "from secprim import TooLarge\ndef f(p): raise TooLarge('x')\n")
    _both(case)
    assert zipfile.ZipFile.open is orig


def test_response_uncapped_read_detected_and_bounded_read_cleared(tmp_path):
    expect = {"inputs": [{"kind": "response", "size": 500_000}],
              "accept": [{"kind": "response", "size": 1000}], "refuse": ["TooLarge"], "max_read": 200_000}
    case = _case(tmp_path, expect,
                 "def f(r): return len(r.text)\n",
                 "from secprim import bounded_read\ndef f(r): return len(bounded_read(r, 100_000))\n")
    v, c = _both(case)
    assert v.detected and v.metrics["max_bytes_read"] == 500_000
    assert not c.detected and c.metrics["max_bytes_read"] <= 100_000 + 65_536


def test_xml_dtd_accepted_detected_and_safe_xml_cleared(tmp_path):
    expect = {"inputs": [{"kind": "xml_dtd"}], "accept": [{"kind": "xml_plain"}], "refuse": ["MalformedInput"]}
    case = _case(tmp_path, expect,
                 "import xml.etree.ElementTree as ET\ndef f(b): return ET.fromstring(b).tag\n",
                 "from secprim import safe_xml_fromstring\ndef f(b): return safe_xml_fromstring(b).tag\n")
    v, c = _both(case)
    assert v.detected and "xml_dtd" in v.evidence
    assert not c.detected


def test_undeclared_exception_is_not_a_refusal(tmp_path):
    case = _case(tmp_path, {"inputs": ["nan"], "refuse": ["MalformedInput"]},
                 "def f(v): raise RuntimeError('boom')\n",
                 "from secprim import MalformedInput\ndef f(v): raise MalformedInput('no')\n")
    v, c = _both(case)
    assert v.detected and "RuntimeError" in v.evidence
    assert not c.detected


def test_refusing_a_legitimate_input_is_an_error_not_a_pass(tmp_path):
    case = _case(tmp_path, {"inputs": "nonfinite", "accept": "finite_ok", "refuse": ["MalformedInput"]},
                 "def f(v): return float(v)\n",
                 "from secprim import MalformedInput\ndef f(v): raise MalformedInput('everything')\n")
    c = G.grade(case, "clean")
    assert c.error and "legitimate" in c.error and not c.detected


def test_bad_expect_blocks_are_errors(tmp_path):
    case = _case(tmp_path, {"inputs": "no_such_set"}, "def f(v): return v\n", "def f(v): return v\n")
    assert G.grade(case, "vuln").error
    case = _case(tmp_path, {"inputs": []}, "def f(v): return v\n", "def f(v): return v\n")
    assert "empty" in G.grade(case, "vuln").error


@pytest.mark.parametrize("cid", [
    "P1-nonfinite-float-01", "P1-path-from-content-01", "P2-read-before-size-check-01",
    "P2-xml-dtd-01", "P2-zip-no-budget-01", "P2-html-no-cap-01",
])
def test_corpus_refuse_cases_detect_vuln_and_clear_clean(cid):
    case = next(c for c in discover(CASES) if c.id == cid)
    row = grade_case(case, default_graders(REPO))
    assert row["error"] is None, row
    assert row["vuln"]["detected"] is True, row["vuln"]
    assert row["clean"]["detected"] is False, row["clean"]
