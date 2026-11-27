"""Tests of evals/calib/ingest.py on the three benign fixtures (tests/fixtures/calib/osv-*.json).

Offline by construction: the fixtures name `example.invalid` hosts, the PR resolver is a fake,
no zip or clone is read, no `gh`, no network, no model."""
from __future__ import annotations

import copy
import json
import zipfile
from pathlib import Path

import pytest

from evals import calib
from evals.calib import ingest
from evals.calib.ingest import (Candidate, GhPRResolver, OSVFixtureSource, OSVZipSource, candidate_from_osv,
                                dedupe, extract_fix_refs, is_candidate, render_review, resolve_fix_commits, scan)

FIXTURES = ingest.FIXTURES_DIR
CONTRACT_KEYS = {"ghsa_id", "cve_id", "cwe", "package", "ecosystem", "project", "repo_url", "disclosure_date",
                 "fix_refs", "fix_commit", "vuln_commit", "severity", "summary_category", "sub_scenario",
                 "library", "status", "exclusion_reason", "source",
                 # amendments A2 / A3 (2026-11-27)
                 "fix_commit_source", "review_underspecified", "review_test_unfair"}
SHA1 = "0123456789abcdef0123456789abcdef01234567"


def _load(n: int) -> dict:
    return json.loads((FIXTURES / f"osv-{n}.json").read_text())


@pytest.fixture(scope="module")
def recs():
    return {n: _load(n) for n in (1, 2, 3)}


# ------------------------------------------------------------------ fixtures are benign and shaped as agreed

def test_fixtures_are_hand_written_and_benign(recs):
    for adv in recs.values():
        assert "FIXTURE-ONLY-DETAILS-MARKER" in adv["details"]
        for r in adv["references"]:
            assert "example.invalid" in r["url"]        # no real repository is ever named
    assert [a["package"]["ecosystem"] for a in recs[3]["affected"]] == ["npm"]
    assert not any(ingest.FIX_REF_RE.search(r["url"]) for r in recs[2]["references"])   # no fix ref at all


# ------------------------------------------------------------------ is_candidate

def test_is_candidate_filters_ecosystem_cwe_and_withdrawn(recs):
    assert is_candidate(recs[1]) and is_candidate(recs[2])
    assert not is_candidate(recs[3])                                     # npm
    assert is_candidate(recs[3], ecosystem="npm")
    assert not is_candidate(recs[1], cwe="CWE-79")
    withdrawn = {**recs[1], "withdrawn": "2025-04-01T00:00:00Z"}
    assert not is_candidate(withdrawn)
    assert not is_candidate({}) and not is_candidate({"affected": [{"package": {"ecosystem": "PyPI"}}]})


# ------------------------------------------------------------------ fix refs

def test_fix_ref_extraction_commit_and_pull(recs):
    c = candidate_from_osv(recs[1])
    assert c.fix_refs == [f"https://git.example.invalid/acme/fetchkit/commit/{SHA1}",
                          "https://git.example.invalid/acme/fetchkit/pull/42"]
    assert c.fix_commit == SHA1 and c.fix_commit_source == "commit-url"
    assert c.project == "acme/fetchkit" and c.repo_url == "https://git.example.invalid/acme/fetchkit"


def test_fix_ref_extraction_none(recs):
    c = candidate_from_osv(recs[2])
    assert c.fix_refs == [] and c.fix_commit == "" and c.fix_commit_source == ""
    assert c.status == "raw" and c.exclusion_reason == ""           # kept raw; build.py says no_fix_ref
    assert c.project == "example-org/linkpreview"                   # from the PACKAGE reference


def test_fix_typed_reference_decides_fix_commit_over_other_commit_urls():
    other = "https://github.com/o/n/commit/" + "a" * 40
    refs = [{"type": "WEB", "url": other}, {"type": "FIX", "url": f"https://github.com/o/n/commit/{SHA1}"}]
    fix_refs, fix_commit, project = extract_fix_refs(refs)
    assert fix_commit == SHA1 and fix_refs[0].endswith(SHA1) and project == "o/n"
    # two commits, none FIX-typed -> ambiguous -> ""
    _, fix_commit2, _ = extract_fix_refs([r["url"] for r in refs])
    assert fix_commit2 == ""


def test_fix_ref_shapes_are_canonicalised():
    urls = [f"https://github.com/O/N/commit/{SHA1.upper()}.patch#diff-1",
            f"https://github.com/O/N/pull/7/commits/{SHA1}",
            "https://gitlab.example.invalid/g/p/-/merge_requests/3",
            "https://gitlab.example.invalid/g/p/-/commit/" + "b" * 40,
            "https://github.com/O/N/pull/7/files",
            "https://github.com/O/N/releases/tag/v1.2.3",             # not a fix ref
            "https://github.com/O/N/commits/main"]                     # not a fix ref
    fix_refs, fix_commit, _ = extract_fix_refs(urls)
    assert fix_refs == [f"https://github.com/O/N/commit/{SHA1}",
                        "https://gitlab.example.invalid/g/p/-/merge_requests/3",
                        "https://gitlab.example.invalid/g/p/-/commit/" + "b" * 40,
                        "https://github.com/O/N/pull/7"]
    assert fix_commit == ""                                             # two distinct commits


# ------------------------------------------------------------------ PR -> merge commit (fake resolver)

def _pr_only(recs, n="99"):
    adv = copy.deepcopy(recs[1])
    adv["id"] = "GHSA-f1x1-pppp-0009"
    adv["references"] = [{"type": "WEB", "url": f"https://github.com/acme/fetchkit/pull/{n}"},
                         {"type": "PACKAGE", "url": "https://github.com/acme/fetchkit"}]
    return candidate_from_osv(adv)


def test_resolve_fix_commits_uses_the_lone_github_pr(recs):
    c = _pr_only(recs)
    assert c.fix_commit == "" and c.fix_refs == ["https://github.com/acme/fetchkit/pull/99"]
    seen = []

    def fake(url):
        seen.append(url)
        return "c" * 40

    out = resolve_fix_commits([c, candidate_from_osv(recs[1]), candidate_from_osv(recs[2])], fake)
    assert out[0].fix_commit == "c" * 40 and out[0].fix_commit_source == "github-api-pr-merge"
    assert out[1] == candidate_from_osv(recs[1])            # already had a commit: untouched
    assert out[2] == candidate_from_osv(recs[2])            # no refs: untouched
    assert seen == ["https://github.com/acme/fetchkit/pull/99"]
    assert resolve_fix_commits([c], None) == [c]            # no resolver -> no change
    assert resolve_fix_commits([c], lambda u: "") == [c]    # unresolved -> left as is


def test_gh_pr_resolver_caches_and_stops_on_auth_failure(tmp_path):
    calls = []

    def runner(argv):
        calls.append(argv)
        return 0, json.dumps({"merge_commit_sha": "D" * 40, "merged": True, "merged_at": "x", "html_url": "u"}), ""

    r = GhPRResolver(tmp_path, runner=runner)
    assert r("https://github.com/acme/fetchkit/pull/5") == "d" * 40
    assert r("https://github.com/acme/fetchkit/pull/5") == "d" * 40      # cached: no second call
    assert len(calls) == 1 and "repos/acme/fetchkit/pulls/5" in calls[0]
    assert r.cache_path("acme", "fetchkit", "5").is_file()
    assert r("https://gitlab.example.invalid/g/p/-/merge_requests/3") == ""   # not GitHub: never called
    assert len(calls) == 1

    def unmerged(argv):
        return 0, json.dumps({"merge_commit_sha": "e" * 40, "merged": False}), ""
    assert GhPRResolver(tmp_path / "b", runner=unmerged)("https://github.com/a/b/pull/1") == ""

    def denied(argv):
        calls.append(argv)
        return 1, "", "gh: HTTP 403: API rate limit exceeded"
    before = len(calls)
    d = GhPRResolver(tmp_path / "c", runner=denied)
    assert d("https://github.com/a/b/pull/1") == "" and d("https://github.com/a/b/pull/2") == ""
    assert len(calls) == before + 1 and "rate limit" in d.disabled_reason     # one call, then disabled


# ------------------------------------------------------------------ record shape and suggestions

def test_to_record_keys_are_the_contract_set(recs):
    for adv in (recs[1], recs[2]):
        rec = candidate_from_osv(adv).to_record()
        assert set(rec) == CONTRACT_KEYS
        assert rec["vuln_commit"] == "" and rec["ecosystem"] == "PyPI" and rec["source"] == "osv"
        assert rec["review_underspecified"] == -1 and rec["review_test_unfair"] == -1
        assert Candidate(**rec) == candidate_from_osv(adv)              # round-trips
    assert set(ingest.RECORD_KEYS) == CONTRACT_KEYS


def test_categorical_suggestions_never_copy_advisory_text(recs):
    c1, c2 = candidate_from_osv(recs[1]), candidate_from_osv(recs[2])
    assert c1.summary_category == "redirect to internal address not re-validated" and c1.sub_scenario == "redirect"
    assert c1.library == "requests"
    assert c2.summary_category == "host re-resolved after validation (DNS rebinding)" and c2.sub_scenario == "rebinding"
    assert c2.library == "httpx"
    for c, adv in ((c1, recs[1]), (c2, recs[2])):
        assert len(c.summary_category.split()) <= 12
        assert c.summary_category.lower() not in adv["summary"].lower()
        assert c.summary_category.lower() not in adv["details"].lower()
        assert c.sub_scenario in ingest.SUB_SCENARIOS and c.library in ingest.LIBRARIES
    for _, cat, sub in ingest.CATEGORY_RULES:
        assert len(cat.split()) <= 12 and sub in ingest.SUB_SCENARIOS
    assert ingest.categorize("", "") == (ingest.FALLBACK_CATEGORY, "")
    assert ingest.suggest_library("the server sends requests to the URL") == ""      # prose, not a client
    assert ingest.suggest_library("uses pycurl") == "other"


def test_metadata_fields(recs):
    c = candidate_from_osv(recs[1])
    assert c.ghsa_id == "GHSA-f1x1-aaaa-0001" and c.cve_id == "CVE-2025-00001"
    assert c.cwe == ["CWE-918"] and c.package == "fetchkit" and c.severity == "MODERATE"
    assert c.disclosure_date == "2025-03-14"
    c2 = candidate_from_osv(recs[2])
    assert c2.cwe == ["CWE-918", "CWE-367"] and c2.severity == "LOW"


# ------------------------------------------------------------------ dedupe

def test_dedupe_marks_later_same_project_fix_commit_as_duplicate(recs):
    a = candidate_from_osv(recs[1])
    dup = copy.deepcopy(recs[1])
    dup["id"] = "GHSA-f1x1-dddd-0004"
    dup["published"] = "2025-05-01T00:00:00Z"
    b = candidate_from_osv(dup)
    none = candidate_from_osv(recs[2])
    none2 = Candidate(**{**none.to_record(), "ghsa_id": "GHSA-f1x2-eeee-0005"})
    out = dedupe([b, a, none, none2])
    by_id = {c.ghsa_id: c for c in out}
    assert [c.ghsa_id for c in out] == [b.ghsa_id, a.ghsa_id, none.ghsa_id, none2.ghsa_id]   # order kept
    assert by_id[a.ghsa_id].status == "raw" and by_id[a.ghsa_id].exclusion_reason == ""     # earliest kept
    assert by_id[b.ghsa_id].status == "excluded" and by_id[b.ghsa_id].exclusion_reason == "duplicate"
    assert by_id[b.ghsa_id].exclusion_reason in calib.EXCLUSION_REASONS
    assert by_id[none.ghsa_id].status == "raw" and by_id[none2.ghsa_id].status == "raw"    # no refs: never collapsed
    # same project, different commit -> both kept
    other = Candidate(**{**a.to_record(), "ghsa_id": "GHSA-f1x1-ffff-0006", "fix_commit": "f" * 40,
                         "fix_refs": ["https://git.example.invalid/acme/fetchkit/commit/" + "f" * 40]})
    assert all(c.status == "raw" for c in dedupe([a, other]))


# ------------------------------------------------------------------ scan / review / sources

def test_scan_on_fixtures_reports_the_funnel():
    cands, funnel = scan(OSVFixtureSource(FIXTURES))
    assert [c.ghsa_id for c in cands] == ["GHSA-f1x2-bbbb-0002", "GHSA-f1x1-aaaa-0001"]   # sorted by date
    assert funnel == {"scanned": 3, "ecosystem": 2, "cwe": 2, "withdrawn": 0, "with_fix_ref": 1,
                      "pr_resolved": 0, "pr_unresolved": 0, "after_dedupe": 2, "raw_with_fix_ref": 1,
                      "raw_with_fix_commit": 1}


def test_render_review_one_row_per_candidate_and_no_advisory_text(recs):
    cands, _ = scan(OSVFixtureSource(FIXTURES))
    dup = Candidate(**{**cands[1].to_record(), "ghsa_id": "GHSA-f1x1-dddd-0004", "disclosure_date": "2025-05-01"})
    cands = dedupe(list(cands) + [dup])
    text = render_review(cands, repo_sizes={"acme/fetchkit": 12})
    table = [ln for ln in text.splitlines() if ln.startswith("| GHSA-")]
    assert len(table) == len(cands) == 3
    header = next(ln for ln in text.splitlines() if ln.startswith("| advisory"))
    assert header == "| " + " | ".join(ingest.REVIEW_COLUMNS) + " |"
    row1 = next(ln for ln in table if "GHSA-f1x1-aaaa-0001" in ln)
    assert f"https://git.example.invalid/acme/fetchkit/commit/{SHA1}" in row1 and "| 12 |" in row1
    assert "| redirect |" in row1 and "| requests |" in row1
    row2 = next(ln for ln in table if "GHSA-f1x2-bbbb-0002" in ln)
    assert "| — |" in row2 and "| ? |" in row2                           # no fix ref; size unknown
    rowd = next(ln for ln in table if "GHSA-f1x1-dddd-0004" in ln)
    assert "excluded (duplicate)" in rowd
    for adv in recs.values():                                              # nothing from the advisories leaks
        assert "FIXTURE-ONLY-DETAILS-MARKER" not in text
        assert adv["summary"] not in text
        for sentence in adv["details"].split(". "):
            assert sentence.strip() not in text
    assert "## Fixable candidates by project" in text and "| acme/fetchkit | 1 |" in text
    assert "## Candidates by disclosure year" in text and "| 2025 |" in text and "| 2024 |" in text
    assert "15%" in text                                                    # the co-selection cap is stated
    assert all(ln.endswith("|   |   |") for ln in table)                   # two blank rubric cells


def test_fixture_source_and_zip_source_agree(tmp_path):
    zp = tmp_path / "all.zip"
    with zipfile.ZipFile(zp, "w") as zf:
        for p in sorted(FIXTURES.glob("osv-*.json")):
            zf.writestr(p.name, p.read_bytes())
        zf.writestr("README.txt", "not json")
    zs = OSVZipSource(zp)
    assert zs.id == "osv" and [a["id"] for a in zs.records()] == [a["id"] for a in OSVFixtureSource(FIXTURES).records()]
    meta = zs.describe()
    assert len(meta["sha256"]) == 64 and meta["size_bytes"] == str(zp.stat().st_size) and "mtime" in meta
    a, _ = scan(zs)
    b, _ = scan(OSVFixtureSource(FIXTURES))
    strip = lambda c: {k: v for k, v in c.to_record().items() if k != "source"}   # noqa: E731
    assert [strip(c) for c in a] == [strip(c) for c in b]
    assert {c.source for c in a} == {"osv"} and {c.source for c in b} == {"osv-fixtures"}
    with pytest.raises(FileNotFoundError):
        OSVZipSource(tmp_path / "missing.zip")
    with pytest.raises(FileNotFoundError):
        ingest.OSVDirectorySource(tmp_path)


def test_main_fixtures_end_to_end(tmp_path):
    out, review = tmp_path / "c.jsonl", tmp_path / "r.md"
    assert ingest.main(["--source", "osv-fixtures", "--out", str(out), "--review", str(review)]) == 0
    lines = out.read_text().splitlines()
    assert len(lines) == 3 and "_meta" in json.loads(lines[0])
    meta = json.loads(lines[0])["_meta"]
    assert meta["source"] == "osv-fixtures" and meta["funnel"]["scanned"] == 3
    cands, meta2 = ingest.read_candidates(out)
    assert meta2 == meta and len(cands) == 2 and all(set(c.to_record()) == CONTRACT_KEYS for c in cands)
    text = review.read_text()
    assert text.startswith(ingest.REVIEW_TITLE) and "Funnel: 3 records scanned" in text
    assert "FIXTURE-ONLY-DETAILS-MARKER" not in text
    # refuses to overwrite the real outputs with fixture data
    assert ingest.main(["--source", "osv-fixtures"]) == 2
    assert ingest.main(["--source", "osv-zip", str(tmp_path / "nope.zip"), "--out", str(out), "--review", str(review)]) == 2


def test_ingest_writes_meta_and_sorted_records(tmp_path):
    out = tmp_path / "x.jsonl"
    cands = ingest.ingest(OSVFixtureSource(FIXTURES), out=out)
    assert [c.disclosure_date for c in cands] == sorted(c.disclosure_date for c in cands)
    got, meta = ingest.read_candidates(out)
    assert got == cands and meta["funnel"]["cwe"] == 2
