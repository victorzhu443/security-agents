"""Advisory ingest: public CWE-918 advisories -> egress/candidates.jsonl (+ CANDIDATES-REVIEW.md).

Step 1 of the P4 calibration pipeline (plan "Build order", CONTRACTS.md "W-A" and amendment A3).
The output is the raw candidate list Victor and the governor co-select from in step 2;
`build.py` (W-B) turns the selected records into Harbor task directories.

    Source               the ingest abstraction: `id` + `records()` -> raw advisory JSON objects
    OSVZipSource         the OSV.dev PyPI dump (`PyPI/all.zip`, CC-BY-4.0) — the PRIMARY source
    OSVDirectorySource   a clone of github/advisory-database (same OSV records, kept as a second impl)
    OSVFixtureSource     the three benign fixtures under tests/fixtures/calib/ (tests only)
    is_candidate         ecosystem + CWE filter (and not withdrawn)
    candidate_from_osv   one OSV record -> Candidate (pure)
    resolve_fix_commits  PR-only fix refs -> merge commit, through an injectable resolver (gh api)
    dedupe               collapse duplicates by (project, fix_commit)
    scan / ingest        source -> sorted candidates (+ funnel counts) -> candidates.jsonl
    render_review        the co-selection sheet (Markdown)
    main                 `--source osv-zip <zip> | osv-dir <path> | osv-fixtures [<dir>]  [--out] [--review] [--gh-cache DIR]`

**The ingest is an abstraction over sources.** OSV (which mirrors GHSA, whose records carry
`database_specific.cwe_ids`) is the first source; every later one (CVEfixes as a cross-check,
NVD as a fallback for a missing CWE/date, ...) is added as another `Source` with its own
`candidate_from_<source>` mapping to the same `Candidate`, never ad hoc. Nothing here reaches
the network except the opt-in PR resolution (`--gh-cache`), which goes through the `gh` CLI
and caches every answer; the zip itself is downloaded once, by hand, outside the repository.

Decisions recorded here (the brief asked for each to be documented):

* **Provenance lives in two places**: the first line of `candidates.jsonl` is a
  `{"_meta": {...}}` record (source id, zip size / mtime / sha256 or clone HEAD, the funnel),
  and the same facts head the review sheet. **Readers of the jsonl must skip the `_meta`
  line** (`read_candidates` does); every other line is one `Candidate.to_record()`.
* **Withdrawn advisories are not candidates.** `is_candidate` returns False when the OSV record
  carries a `withdrawn` timestamp (retracted upstream); they are counted in the funnel and do
  not appear in the jsonl (no `EXCLUSION_REASONS` value describes "retracted upstream").
* **Records with no fix ref stay `raw` with `fix_refs: []`.** They are kept so that the review
  sheet shows them (Victor may supply a fix ref by hand at co-selection); `build.py` excludes
  what is still unresolved as `no_fix_ref`. Only `dedupe` sets `status: excluded` here.
* **Fix refs**: `references[*]` of `type == "FIX"` are considered first, then any URL whose path
  is `/commit/<sha>`, `/pull/<n>` (also `/pull/<n>/commits/<sha>` = that commit) or GitLab's
  `/-/commit/<sha>` / `/-/merge_requests/<n>`. Any host is accepted — the path shape is the
  filter (self-hosted GitLab, Codeberg and the fixtures' `example.invalid` all work). URLs are
  canonicalised to `https://<host>/<owner>/<name>[/-]/commit/<sha>` or `.../pull/<n>`; query
  strings, fragments and `.patch`/`.diff` suffixes are dropped. `fix_refs` lists FIX-typed refs
  first, then the rest, in reference order.
* **`fix_commit`** is the sha when exactly one distinct commit ref exists among the FIX-typed
  refs, else among all refs (`fix_commit_source: "commit-url"`). Otherwise, when the record names
  exactly one GitHub pull request and a resolver is supplied, the PR's `merge_commit_sha` (only
  for a *merged* PR) is used (`fix_commit_source: "github-api-pr-merge"`). Anything else leaves
  `fix_commit` "" with `fix_refs` kept, for `build.py`'s `resolve_commits` or co-selection.
* **PR resolution** is `gh api repos/<owner>/<repo>/pulls/<n>` (the user's own `gh` login),
  cached as one JSON file per PR under `--gh-cache DIR` (never committed). An unauthenticated
  or rate-limited `gh` stops further calls for the run and the gap is reported in the funnel
  (`pr_unresolved`); nothing retries or routes around it.
* **`dedupe` key**: `(project, fix_commit)` when `fix_commit` is set; `(project, sorted fix_refs)`
  when the record has refs but no single commit (two advisories naming the same PR); records
  with no refs are never collapsed. The earliest `disclosure_date` (then lowest id) is kept.
* **`summary_category`, `sub_scenario` and `library` are keyword suggestions.** The category
  text is always one of the fixed strings in `CATEGORY_RULES` — never a sentence from the
  advisory — chosen by the first rule that matches the *summary*; only when no rule matches the
  summary are the rules run over `details` (whose impact boilerplate — cloud metadata,
  internal services, 127.0.0.1 — would otherwise dominate). The fallback category leaves
  `sub_scenario` "" (unknown) rather than guessing.
* **Review rubric (amendment A2)**: `review_underspecified` and `review_test_unfair` (0–3,
  SWE-bench Verified's axes; drop at >= 2) are `-1` = unscored from ingest and two blank
  columns in the review sheet for Victor to fill.
* **Monoculture (amendment A3)**: the review sheet shows per-project counts and the per-year
  distribution of fixable candidates and states the co-selection cap (<= 15 % of positives
  from any one project).
"""
from __future__ import annotations

import argparse
import dataclasses
import datetime as _dt
import hashlib
import json
import re
import subprocess
import sys
import zipfile
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Protocol, Sequence, Tuple

from evals.calib import CANDIDATES_FILE, CANDIDATES_REVIEW, CWE, EXCLUSION_REASONS, REPO

FIXTURES_DIR = REPO / "tests" / "fixtures" / "calib"
#: Where `OSVDirectorySource` looks inside an advisory-database clone.
GITHUB_REVIEWED = Path("advisories") / "github-reviewed"
#: The primary source (amendment A3). Downloaded once by hand; never fetched by this module.
OSV_PYPI_ZIP_URL = "https://osv-vulnerabilities.storage.googleapis.com/PyPI/all.zip"

STATUS_RAW, STATUS_SELECTED, STATUS_EXCLUDED = "raw", "selected", "excluded"
SUB_SCENARIOS = ("redirect", "rebinding", "off_list", "derived_links", "oversize", "scheme", "other")
LIBRARIES = ("requests", "httpx", "urllib", "aiohttp", "other")
FIX_FROM_COMMIT_URL, FIX_FROM_PR_MERGE = "commit-url", "github-api-pr-merge"
#: Co-selection cap stated in the review legend (amendment A3).
PROJECT_CAP = 0.15

#: A fix reference inside `references[*].url`: a commit or a pull/merge request on any forge
#: host. Group names: host, owner, name, then exactly one of commit_sha | pr (+ optional
#: pr_sha: a commit page inside a PR) | mr.
FIX_REF_RE = re.compile(
    r"https?://(?P<host>[^/\s]+)/(?P<owner>[^/\s]+)/(?P<name>[^/\s#?]+?)(?:\.git)?/(?:-/)?"
    r"(?:commit/(?P<commit_sha>[0-9a-fA-F]{7,40})"
    r"|pull/(?P<pr>\d+)(?:/commits/(?P<pr_sha>[0-9a-fA-F]{7,40}))?"
    r"|merge_requests/(?P<mr>\d+))"
    r"(?![0-9a-zA-Z])"
)
PULL_REF_RE = re.compile(r"^https://github\.com/(?P<owner>[^/]+)/(?P<name>[^/]+)/pull/(?P<n>\d+)$")
#: A bare repository URL (`https://host/owner/name`), used for `project` when no fix ref exists.
REPO_URL_RE = re.compile(r"^https?://(?P<host>[^/\s]+)/(?P<owner>[^/\s]+)/(?P<name>[^/\s#?]+?)(?:\.git)?/?$")
FORGE_HOSTS = ("github.com", "gitlab.com", "codeberg.org", "bitbucket.org")
#: Repositories that index advisories; a WEB reference into one of them is not the project.
INDEX_REPOS = ("github/advisory-database", "pypa/advisory-database")


# --------------------------------------------------------------------- the record

@dataclass(frozen=True)
class Candidate:
    """One advisory, as a line of candidates.jsonl. The key set of `to_record()` is fixed by
    CONTRACTS.md + amendments A2/A3 (W-B's `build_task(cand: Dict)` reads it); add nothing
    without a contract change."""
    ghsa_id: str                    # the GHSA id (the record id, or its GHSA alias for a PYSEC record)
    cve_id: str                     # first CVE alias, or ""
    cwe: List[str]                  # every cwe_ids entry (CWE-918 among them)
    package: str                    # PyPI distribution name(s), comma-joined when the advisory names several
    ecosystem: str
    project: str                    # owner/name of the repository, or ""
    repo_url: str                   # https://<host>/<owner>/<name>, or ""
    disclosure_date: str            # YYYY-MM-DD (`published`)
    fix_refs: List[str]             # every /commit/<sha> and /pull/<n> URL in references (canonicalised, FIX-typed first)
    fix_commit: str                 # one commit sha, or "" (module docstring)
    fix_commit_source: str = ""     # commit-url | github-api-pr-merge | ""
    vuln_commit: str = ""           # always "" from ingest; build.py resolves it
    severity: str = ""              # database_specific.severity: LOW | MODERATE | HIGH | CRITICAL
    summary_category: str = ""      # categorical, <= 12 words, from CATEGORY_RULES (never advisory text)
    sub_scenario: str = ""          # suggested: one of SUB_SCENARIOS or ""
    library: str = ""               # suggested: one of LIBRARIES or ""
    status: str = STATUS_RAW        # raw | selected | excluded
    exclusion_reason: str = ""      # one of evals.calib.EXCLUSION_REASONS or ""
    source: str = "osv"             # the ingest Source.id
    review_underspecified: int = -1     # 0–3 at co-selection; -1 = unscored (amendment A2)
    review_test_unfair: int = -1        # 0–3 at co-selection; -1 = unscored

    def to_record(self) -> Dict[str, object]:
        return dataclasses.asdict(self)


RECORD_KEYS: Tuple[str, ...] = tuple(f.name for f in dataclasses.fields(Candidate))


# --------------------------------------------------------------------- sources

class Source(Protocol):
    """The ingest abstraction. OSV first; other sources are added behind this interface."""
    id: str

    def records(self) -> Iterable[dict]: ...        # raw advisory JSON objects


def _git(root: Path, *args: str) -> str:
    try:
        out = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True,
                             timeout=30, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return "unknown"
    return out.stdout.strip() if out.returncode == 0 and out.stdout.strip() else "unknown"


class OSVZipSource:
    """Every record of an OSV.dev ecosystem dump (`all.zip`: one `<id>.json` per entry). Yields
    all of them (the ecosystem filter is `is_candidate`'s, so the funnel's "scanned" count is
    honest); `ecosystem` is what `scan` filters for."""
    id = "osv"

    def __init__(self, zip_path: Path, *, ecosystem: str = "PyPI") -> None:
        self.zip_path = Path(zip_path)
        self.ecosystem = ecosystem
        if not self.zip_path.is_file():
            raise FileNotFoundError(f"{self.zip_path} is not a file; download {OSV_PYPI_ZIP_URL} once, by hand")

    def records(self) -> Iterator[dict]:
        with zipfile.ZipFile(self.zip_path) as zf:
            for name in sorted(zf.namelist()):
                if not name.endswith(".json"):
                    continue
                try:
                    adv = json.loads(zf.read(name))
                except (ValueError, KeyError, zipfile.BadZipFile):
                    continue                       # an unreadable entry is not an advisory
                if isinstance(adv, dict):
                    yield adv

    def describe(self) -> Dict[str, str]:
        """Pinned provenance of the dump: size, mtime and sha256 of the zip."""
        st = self.zip_path.stat()
        sha = hashlib.sha256(self.zip_path.read_bytes()).hexdigest()
        mtime = _dt.datetime.fromtimestamp(st.st_mtime, tz=_dt.timezone.utc).isoformat(timespec="seconds")
        return {"source": self.id, "repository": f"OSV.dev ecosystem dump {OSV_PYPI_ZIP_URL} (CC-BY-4.0)",
                "path": self.zip_path.name, "size_bytes": str(st.st_size), "mtime": mtime,
                "sha256": sha, "ecosystem": self.ecosystem}


class OSVDirectorySource:
    """Every OSV record under `<root>/advisories/github-reviewed/**/*.json` of a
    github/advisory-database clone (the same records the OSV dump mirrors; kept as a second
    implementation of `Source`)."""
    id = "osv-dir"

    def __init__(self, root: Path, *, ecosystem: str = "PyPI") -> None:
        self.root = Path(root)
        self.ecosystem = ecosystem
        if not (self.root / GITHUB_REVIEWED).is_dir():
            raise FileNotFoundError(f"{self.root / GITHUB_REVIEWED} is not a directory; "
                                    "pass the root of a github/advisory-database clone")

    def records(self) -> Iterator[dict]:
        for path in sorted((self.root / GITHUB_REVIEWED).rglob("*.json")):
            try:
                adv = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(adv, dict):
                yield adv

    def describe(self) -> Dict[str, str]:
        """Pinned provenance of the clone: HEAD sha and commit date (read-only `git`)."""
        return {"source": self.id, "repository": "github/advisory-database",
                "path": str(self.root / GITHUB_REVIEWED), "head_sha": _git(self.root, "rev-parse", "HEAD"),
                "head_date": _git(self.root, "log", "-1", "--format=%cI"), "ecosystem": self.ecosystem}


class OSVFixtureSource:
    """The hand-written, benign fixtures `tests/fixtures/calib/osv-*.json` (tests only)."""
    id = "osv-fixtures"

    def __init__(self, root: Path = FIXTURES_DIR, *, ecosystem: str = "PyPI") -> None:
        self.root = Path(root)
        self.ecosystem = ecosystem

    def records(self) -> Iterator[dict]:
        for path in sorted(self.root.glob("osv-*.json")):
            yield json.loads(path.read_text(encoding="utf-8"))

    def describe(self) -> Dict[str, str]:
        return {"source": self.id, "repository": "tests/fixtures/calib (hand-written, benign)",
                "path": self.root.name, "ecosystem": self.ecosystem}


# --------------------------------------------------------------------- filter and mapping

def _ecosystems(adv: dict) -> List[str]:
    out = []
    for a in adv.get("affected") or []:
        eco = (a.get("package") or {}).get("ecosystem") if isinstance(a, dict) else None
        if isinstance(eco, str):
            out.append(eco)
    return out


def _cwes(adv: dict) -> List[str]:
    return [str(c) for c in ((adv.get("database_specific") or {}).get("cwe_ids") or [])]


def is_candidate(adv: dict, *, cwe: str = CWE, ecosystem: str = "PyPI") -> bool:
    """True iff some affected package is in `ecosystem`, `database_specific.cwe_ids` names `cwe`,
    and the advisory has not been withdrawn."""
    if not isinstance(adv, dict) or adv.get("withdrawn"):
        return False
    return ecosystem in _ecosystems(adv) and cwe in _cwes(adv)


def _canonical_fix_ref(m: "re.Match[str]") -> Tuple[str, str]:
    """-> (kind, canonical url); kind is "commit" or "pull"."""
    base = f"https://{m['host']}/{m['owner']}/{m['name']}"
    dash = "/-" if "/-/" in m.group(0) else ""
    sha = m["commit_sha"] or m["pr_sha"]
    if sha:
        return "commit", f"{base}{dash}/commit/{sha.lower()}"
    if m["mr"]:
        return "pull", f"{base}{dash}/merge_requests/{m['mr']}"
    return "pull", f"{base}{dash}/pull/{m['pr']}"


def extract_fix_refs(refs: Iterable[object]) -> Tuple[List[str], str, str]:
    """`refs`: reference dicts (`{type, url}`) or bare URL strings. -> (fix_refs, fix_commit,
    project). FIX-typed refs come first and decide `fix_commit` when they name exactly one
    commit; otherwise all refs do. `project` is owner/name of the first fix ref (or "")."""
    typed: List[Tuple[bool, str]] = []
    for r in refs:
        if isinstance(r, dict):
            typed.append((r.get("type") == "FIX", str(r.get("url") or "")))
        else:
            typed.append((False, str(r or "")))
    ordered = [u for is_fix, u in typed if is_fix] + [u for is_fix, u in typed if not is_fix]
    refs_out: List[str] = []
    fix_shas: List[str] = []
    all_shas: List[str] = []
    project = ""
    n_fix_typed = sum(1 for is_fix, _ in typed if is_fix)
    for i, url in enumerate(ordered):
        m = FIX_REF_RE.search(url)
        if not m:
            continue
        kind, canon = _canonical_fix_ref(m)
        if canon not in refs_out:
            refs_out.append(canon)
        if kind == "commit":
            sha = canon.rsplit("/", 1)[1]
            if sha not in all_shas:
                all_shas.append(sha)
            if i < n_fix_typed and sha not in fix_shas:
                fix_shas.append(sha)
        if not project:
            project = f"{m['owner']}/{m['name']}"
    if len(fix_shas) == 1:
        return refs_out, fix_shas[0], project
    if not fix_shas and len(all_shas) == 1:
        return refs_out, all_shas[0], project
    return refs_out, "", project


def _project_from_refs(refs: Sequence[dict], fix_project: str) -> Tuple[str, str]:
    """-> (project, repo_url). Precedence: the fix ref's repository, then a PACKAGE-type
    repository URL on any host, then a WEB repository URL on a known forge (never an index repo)."""
    if fix_project:
        for r in refs:                       # recover the host from the fix ref itself
            m = FIX_REF_RE.search(r.get("url") or "")
            if m and f"{m['owner']}/{m['name']}" == fix_project:
                return fix_project, f"https://{m['host']}/{m['owner']}/{m['name']}"
    for want_type, any_host in (("PACKAGE", True), ("WEB", False)):
        for r in refs:
            if r.get("type") != want_type:
                continue
            m = REPO_URL_RE.match(r.get("url") or "")
            if not m:
                continue
            proj = f"{m['owner']}/{m['name']}"
            if proj in INDEX_REPOS or (not any_host and m["host"] not in FORGE_HOSTS):
                continue
            return proj, f"https://{m['host']}/{proj}"
    return "", ""


#: (regex over the lowercased text, category text, suggested sub_scenario), first match wins.
#: Category texts are ours (<= 12 words, categorical); the regex is only the trigger.
CATEGORY_RULES: Tuple[Tuple["re.Pattern[str]", str, str], ...] = tuple(
    (re.compile(p), cat, sub) for p, cat, sub in (
        (r"\bredirect", "redirect to internal address not re-validated", "redirect"),
        (r"\b(dns[- ]?rebind|rebinding|toctou|re-?resolv|never resolves dns|literal ips? only)",
         "host re-resolved after validation (DNS rebinding)", "rebinding"),
        (r"\b(ipv6|ipv4[- ]mapped|ipv4[- ]compatible|nat64|6to4|octal|decimal (ip|form)|"
         r"alternate .{0,30}encodings?|transition (address|form|wrapper)|encoded (ip|host|address)|"
         r"loopback host encodings?)",
         "internal address allow-list misses an address encoding", "off_list"),
        (r"\b(oversize|unbounded (response|size|read)|response size|size limit|denial of service|"
         r"ddos|amplification)",
         "response size or outbound volume not bounded", "oversize"),
        (r"\b(private (ip |address )?ranges?|block-?list|blacklist|incomplete (ip |host )?validation|"
         r"misses some|incomplete fix|protection bypass|filter bypass|guard bypass|ssrf bypass|"
         r"bypass(ing|es)? (the |of |its )?(ssrf|validate_url|allowed|protection|guard|filter|check))",
         "internal address block-list incomplete", "off_list"),
        (r"\b(unc path|ntlm|\\\\\\\\)", "UNC path accepted as a URL (credential leak)", "scheme"),
        (r"\b(scheme|file://|ftp://|gopher|dict://|local file (read|loading|inclusion)|"
         r"arbitrary (local )?file (read|loading)|lfi)",
         "URL scheme not restricted", "scheme"),
        (r"\bproxy\b", "proxy setting from user input routes outbound traffic", "other"),
        (r"\b(request )?header\b|\bx-[a-z]+(-[a-z]+)*-url\b",
         "URL taken from a request header fetched unchecked", "off_list"),
        (r"\b(sitemap|crawl|oembed|<img|img tags?|svg|external resources?|html rendering|"
         r"page capture|links? derived|derived urls?|previews?|screenshot|crl|ocsp|wsdl|"
         r"www-authenticate|realm|ccip|offchain|saml metadata)",
         "links derived from fetched content fetched without host check", "derived_links"),
        (r"\b(webhook|callback|lnurl)", "webhook or callback URL fetched without host check", "off_list"),
        (r"\b(openapi|servers\[0\]\.url|base_?url|api_base|spec_path|searxng_url|server url|"
         r"configuration|settings|machinery|registration|provider url|endpoint url)",
         "server base URL from configuration fetched unchecked", "off_list"),
        (r"\b(image|avatar|picture|favicon|media|img)\b",
         "image URL from user input fetched without host check", "off_list"),
        (r"\b(download|upload|import|remote (file|resource|fetch)|fetch(ing)? (url|remote)|"
         r"web[- ]?fetch|url (download|handling|processing|input|parameter))",
         "download URL from user input fetched without host check", "off_list"),
    )
)
FALLBACK_CATEGORY = "URL from user input fetched without host check"

#: Library hints: a hit is a use of the client, not the word "request(s)" in prose.
LIBRARY_RES: Tuple[Tuple[str, "re.Pattern[str]"], ...] = (
    ("requests", re.compile(r"\brequests\.(get|post|put|head|patch|delete|request|session)\b|"
                            r"\brequests library\b|\bimport requests\b|\brequests\.sessions?\b", re.I)),
    ("httpx", re.compile(r"\bhttpx\b", re.I)),
    ("aiohttp", re.compile(r"\baiohttp\b", re.I)),
    ("urllib", re.compile(r"\burllib3?\b|\burlopen\b|\burlretrieve\b", re.I)),
)
OTHER_LIBRARY_RE = re.compile(r"\b(pycurl|curl_cffi|libcurl|playwright|chromium|selenium|pyppeteer|"
                              r"wget|curl)\b", re.I)


def categorize(summary: str, details: str) -> Tuple[str, str]:
    """-> (summary_category, sub_scenario) from CATEGORY_RULES: summary first, details only when
    the summary decides nothing; the fallback category leaves sub_scenario ""."""
    for text in (summary or "", details or ""):
        low = text.lower()
        if not low.strip():
            continue
        for rx, cat, sub in CATEGORY_RULES:
            if rx.search(low):
                return cat, sub
    return FALLBACK_CATEGORY, ""


def suggest_library(text: str) -> str:
    """The client library with the most hits in `text`; "" on a tie or no hit; "other" when
    only a non-Python-HTTP client (curl, a browser engine) is named."""
    hits = {name: len(rx.findall(text or "")) for name, rx in LIBRARY_RES}
    best = max(hits.values()) if hits else 0
    if best > 0:
        tops = [n for n, v in hits.items() if v == best]
        return tops[0] if len(tops) == 1 else ""
    return "other" if OTHER_LIBRARY_RE.search(text or "") else ""


def candidate_from_osv(adv: dict, *, ecosystem: str = "PyPI", source: str = "osv") -> Candidate:
    """One OSV record -> Candidate. Pure: no I/O, no network, no PR resolution."""
    refs = [r for r in (adv.get("references") or []) if isinstance(r, dict)]
    fix_refs, fix_commit, fix_project = extract_fix_refs(refs)
    project, repo_url = _project_from_refs(refs, fix_project)
    names: List[str] = []
    for a in adv.get("affected") or []:
        pkg = a.get("package") or {}
        if pkg.get("ecosystem") == ecosystem and pkg.get("name") and pkg["name"] not in names:
            names.append(str(pkg["name"]))
    aliases = [a for a in (adv.get("aliases") or []) if isinstance(a, str)]
    rec_id = str(adv.get("id") or "")
    ghsa = rec_id if rec_id.startswith("GHSA-") else next((a for a in aliases if a.startswith("GHSA-")), rec_id)
    cves = [a for a in aliases if a.startswith("CVE-")]
    dbs = adv.get("database_specific") or {}
    summary, details = str(adv.get("summary") or ""), str(adv.get("details") or "")
    category, sub = categorize(summary, details)
    return Candidate(
        ghsa_id=ghsa, cve_id=cves[0] if cves else "", cwe=_cwes(adv), package=", ".join(names),
        ecosystem=ecosystem, project=project, repo_url=repo_url,
        disclosure_date=str(adv.get("published") or "")[:10], fix_refs=fix_refs, fix_commit=fix_commit,
        fix_commit_source=FIX_FROM_COMMIT_URL if fix_commit else "",
        severity=str(dbs.get("severity") or ""), summary_category=category, sub_scenario=sub,
        library=suggest_library(summary + "\n" + details), source=source,
    )


# --------------------------------------------------------------------- PR -> merge commit

#: A resolver maps a canonical GitHub pull URL to its merge commit sha ("" when unknown).
PRResolver = Callable[[str], str]


class GhPRResolver:
    """`gh api repos/<owner>/<repo>/pulls/<n>`, one cached JSON file per PR under `cache_dir`.
    Uses the user's own `gh` login; an auth or rate-limit failure disables further calls for
    this instance (`disabled_reason`) — no retries, no other route."""

    def __init__(self, cache_dir: Path, *, runner: Optional[Callable[[Sequence[str]], Tuple[int, str, str]]] = None) -> None:
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)
        self.runner = runner or self._run_gh
        self.disabled_reason = ""
        self.calls = 0

    @staticmethod
    def _run_gh(argv: Sequence[str]) -> Tuple[int, str, str]:
        try:
            out = subprocess.run(list(argv), capture_output=True, text=True, timeout=60, check=False)
        except FileNotFoundError:
            return 127, "", "gh: command not found"
        except subprocess.TimeoutExpired:
            return 124, "", "gh: timed out"
        return out.returncode, out.stdout, out.stderr

    def cache_path(self, owner: str, name: str, n: str) -> Path:
        return self.cache_dir / f"{owner}__{name}__{n}.json"

    def __call__(self, pull_url: str) -> str:
        m = PULL_REF_RE.match(pull_url)
        if not m:
            return ""
        path = self.cache_path(m["owner"], m["name"], m["n"])
        data: Optional[dict] = None
        if path.is_file():
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except ValueError:
                data = None
        if data is None:
            if self.disabled_reason:
                return ""
            rc, out, err = self.runner(["gh", "api", f"repos/{m['owner']}/{m['name']}/pulls/{m['n']}",
                                        "--jq", "{merge_commit_sha: .merge_commit_sha, merged: .merged, "
                                                "merged_at: .merged_at, html_url: .html_url}"])
            self.calls += 1
            low = (err or "").lower()
            if rc != 0 and any(s in low for s in ("rate limit", "authentication", "not logged", "401", "403", "command not found")):
                self.disabled_reason = (err or f"gh exit {rc}").strip().splitlines()[0][:200]
                return ""
            try:
                data = json.loads(out) if rc == 0 else {"error": (err or f"gh exit {rc}").strip()[:500]}
            except ValueError:
                data = {"error": f"unparseable gh output (rc {rc})"}
            path.write_text(json.dumps(data, indent=1) + "\n", encoding="utf-8")
        if data.get("merged") is True and isinstance(data.get("merge_commit_sha"), str):
            return data["merge_commit_sha"].lower()
        return ""


def resolve_fix_commits(cands: Iterable[Candidate], resolver: Optional[PRResolver]) -> List[Candidate]:
    """Fill `fix_commit` from the merge commit of the ONE GitHub pull request a record names when
    it has no commit ref. Records with several PRs, a non-GitHub host, or an unresolved PR are
    left as they are. `resolver=None` -> no change (offline runs, tests, fixtures)."""
    out: List[Candidate] = []
    for c in cands:
        if resolver is None or c.fix_commit or not c.fix_refs:
            out.append(c)
            continue
        pulls = [r for r in c.fix_refs if PULL_REF_RE.match(r)]
        if len(pulls) != 1:
            out.append(c)
            continue
        sha = resolver(pulls[0])
        out.append(dataclasses.replace(c, fix_commit=sha, fix_commit_source=FIX_FROM_PR_MERGE) if sha else c)
    return out


# --------------------------------------------------------------------- dedupe

def _sort_key(c: Candidate) -> Tuple[str, str]:
    return (c.disclosure_date, c.ghsa_id)


def _dedupe_key(c: Candidate) -> Optional[Tuple[str, Tuple[str, ...]]]:
    if c.fix_commit:
        return (c.project, (c.fix_commit,))
    if c.fix_refs:
        return (c.project, tuple(sorted(c.fix_refs)))
    return None


def dedupe(cands: Iterable[Candidate]) -> List[Candidate]:
    """Collapse by (project, fix_commit) — see the module docstring for the key when
    `fix_commit` is "". The earliest disclosure is kept; later ones become
    `status: excluded, exclusion_reason: duplicate`. Order of the input is preserved."""
    assert "duplicate" in EXCLUSION_REASONS
    items = list(cands)
    keeper: Dict[Tuple[str, Tuple[str, ...]], str] = {}
    for c in sorted(items, key=_sort_key):
        key = _dedupe_key(c)
        if key is not None and c.status != STATUS_EXCLUDED:
            keeper.setdefault(key, c.ghsa_id)
    out: List[Candidate] = []
    for c in items:
        key = _dedupe_key(c)
        if key is not None and c.status != STATUS_EXCLUDED and keeper.get(key) != c.ghsa_id:
            c = dataclasses.replace(c, status=STATUS_EXCLUDED, exclusion_reason="duplicate")
        out.append(c)
    return out


# --------------------------------------------------------------------- the funnel

FUNNEL_KEYS = ("scanned", "ecosystem", "cwe", "withdrawn", "with_fix_ref", "pr_resolved", "pr_unresolved",
               "after_dedupe", "raw_with_fix_ref", "raw_with_fix_commit")


def scan(source: Source, *, cwe: str = CWE, ecosystem: Optional[str] = None,
         resolver: Optional[PRResolver] = None) -> Tuple[List[Candidate], Dict[str, int]]:
    """Filter, map, resolve PRs (when a resolver is given), dedupe and sort every record of
    `source`. -> (candidates, funnel counts)."""
    eco = ecosystem or getattr(source, "ecosystem", "PyPI")
    funnel = dict.fromkeys(FUNNEL_KEYS, 0)
    cands: List[Candidate] = []
    for adv in source.records():
        funnel["scanned"] += 1
        if eco not in _ecosystems(adv):
            continue
        funnel["ecosystem"] += 1
        if cwe not in _cwes(adv):
            continue
        funnel["cwe"] += 1
        if not is_candidate(adv, cwe=cwe, ecosystem=eco):
            funnel["withdrawn"] += 1
            continue
        cands.append(candidate_from_osv(adv, ecosystem=eco, source=source.id))
    funnel["with_fix_ref"] = sum(1 for c in cands if c.fix_refs)
    cands = resolve_fix_commits(cands, resolver)
    funnel["pr_resolved"] = sum(1 for c in cands if c.fix_commit_source == FIX_FROM_PR_MERGE)
    funnel["pr_unresolved"] = sum(1 for c in cands if c.fix_refs and not c.fix_commit)
    cands = dedupe(sorted(cands, key=_sort_key))
    funnel["after_dedupe"] = sum(1 for c in cands if c.status == STATUS_RAW)
    funnel["raw_with_fix_ref"] = sum(1 for c in cands if c.status == STATUS_RAW and c.fix_refs)
    funnel["raw_with_fix_commit"] = sum(1 for c in cands if c.status == STATUS_RAW and c.fix_commit)
    return cands, funnel


def write_candidates(cands: Sequence[Candidate], out: Path, *, meta: Optional[Dict[str, object]] = None) -> None:
    """One record per line; when `meta` is given the FIRST line is `{"_meta": meta}`."""
    out.parent.mkdir(parents=True, exist_ok=True)
    lines = [json.dumps({"_meta": meta}, ensure_ascii=False)] if meta is not None else []
    lines += [json.dumps(c.to_record(), ensure_ascii=False) for c in cands]
    out.write_text("".join(line + "\n" for line in lines), encoding="utf-8")


def read_candidates(path: Path = CANDIDATES_FILE) -> Tuple[List[Candidate], Optional[Dict[str, object]]]:
    """-> (candidates, meta or None). Skips the `_meta` line."""
    cands: List[Candidate] = []
    meta: Optional[Dict[str, object]] = None
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        rec = json.loads(line)
        if "_meta" in rec:
            meta = rec["_meta"]
            continue
        cands.append(Candidate(**rec))
    return cands, meta


def ingest(source: Source, *, out: Path = CANDIDATES_FILE) -> List[Candidate]:
    """scan (no PR resolution) + write `out` with a `_meta` line; sorted by disclosure_date then id."""
    cands, funnel = scan(source)
    meta = dict(source.describe()) if hasattr(source, "describe") else {"source": source.id}
    write_candidates(cands, out, meta={**meta, "funnel": funnel})
    return cands


# --------------------------------------------------------------------- the review sheet

REVIEW_TITLE = f"# {CWE} candidates — co-selection sheet"
REVIEW_COLUMNS = ("advisory", "project", "disclosure date", "fix ref", "categorical description",
                  "suggested sub_scenario", "suggested library", "repo size (.py files)",
                  "review_underspecified (0–3)", "review_test_unfair (0–3)")
BLANK = " "     # a cell left for Victor


def _cell(text: str) -> str:
    return (text or "").replace("|", "\\|").replace("\n", " ").strip() or "—"


def _review_fix_ref(c: Candidate) -> str:
    """One URL: the commit ref when `fix_commit` came from a commit URL, else the first fix ref
    (a PR whose merge commit is `fix_commit`), else —."""
    if c.fix_commit and c.fix_commit_source == FIX_FROM_COMMIT_URL:
        for r in c.fix_refs:
            if r.endswith("/" + c.fix_commit):
                return r
    return c.fix_refs[0] if c.fix_refs else ""


def _table(header: Sequence[str], rows: Iterable[Sequence[str]]) -> List[str]:
    out = ["| " + " | ".join(header) + " |", "|" + "---|" * len(header)]
    out += ["| " + " | ".join(rows_) + " |" for rows_ in rows]
    return out


def render_review(cands: Sequence[Candidate], *, repo_sizes: Dict[str, int] | None = None) -> str:
    """CANDIDATES-REVIEW.md: funnel (what is derivable from `cands`), legend, per-project and
    per-year distributions of the fixable candidates, then one row per candidate. Descriptions are
    the categorical `summary_category` strings only — no advisory summary or details text is
    ever rendered. `repo_sizes` maps project -> Python-file count; "?" when absent."""
    sizes = repo_sizes or {}
    raw = [c for c in cands if c.status == STATUS_RAW]
    fixable = [c for c in raw if c.fix_refs]
    lines = [REVIEW_TITLE, "",
             f"Rows: {len(cands)} advisories naming {CWE} · {sum(1 for c in cands if c.fix_refs)} with a fix ref · "
             f"{len(raw)} raw after dedupe · {len(fixable)} raw with a fix ref "
             f"({sum(1 for c in fixable if c.fix_commit)} with a resolved fix commit) · "
             f"{sum(1 for c in cands if c.status == STATUS_EXCLUDED)} excluded here (duplicates).",
             "",
             "Legend: **fix ref** is the single `/commit/<sha>` when the advisory names exactly one, else its "
             "PR or first ref (a lone merged GitHub PR is resolved to its merge commit, `fix_commit_source: "
             "github-api-pr-merge`), else — (no ref: kept raw; `build.py` excludes it as `no_fix_ref` unless one "
             "is supplied at co-selection). **categorical description**, **sub_scenario** and **library** are "
             "keyword suggestions from a fixed table (summary first, details as fallback) — confirm or correct "
             "them; a blank sub_scenario means no keyword decided. A description of `excluded (duplicate)` marks "
             "a later advisory for the same (project, fix) as a kept row. **repo size** is `?` unless known "
             "without cloning. **review_underspecified** / **review_test_unfair** (SWE-bench Verified's axes, "
             "0 = fine … 3 = unusable) are yours to fill at co-selection; a task is dropped at >= 2 on either. "
             f"**Co-selection cap: no project supplies more than {PROJECT_CAP:.0%} of the positives** (see the "
             "per-project table). sub_scenario ∈ {" + ", ".join(SUB_SCENARIOS) + "}; library ∈ {" + ", ".join(LIBRARIES) + "}.",
             ""]
    # Monoculture view (amendment A3): projects and years among the fixable raw candidates.
    by_project = Counter(c.project or "(unknown)" for c in fixable)
    cap_n = int(PROJECT_CAP * len(fixable)) if fixable else 0
    lines += [f"## Fixable candidates by project ({len(by_project)} projects; cap {PROJECT_CAP:.0%} = at most {cap_n} per project)", ""]
    lines += _table(("project", "fixable candidates", "share", "over cap?"),
                    ((_cell(p), str(n), f"{n / len(fixable):.0%}" if fixable else "—", "yes" if n > cap_n else "")
                     for p, n in sorted(by_project.items(), key=lambda kv: (-kv[1], kv[0]))))
    by_year_all = Counter((c.disclosure_date or "????")[:4] for c in cands)
    by_year_fix = Counter((c.disclosure_date or "????")[:4] for c in fixable)
    lines += ["", "## Candidates by disclosure year", ""]
    lines += _table(("year", "advisories", "fixable raw", "share of fixable"),
                    ((y, str(by_year_all[y]), str(by_year_fix.get(y, 0)),
                      f"{by_year_fix.get(y, 0) / len(fixable):.0%}" if fixable else "—")
                     for y in sorted(by_year_all)))
    lines += ["", "## Candidates", ""]
    rows = []
    for c in cands:
        desc = c.summary_category if c.status != STATUS_EXCLUDED else f"excluded ({c.exclusion_reason or 'other'})"
        size = sizes.get(c.project)
        rows.append(tuple(_cell(x) for x in (c.ghsa_id, c.project, c.disclosure_date, _review_fix_ref(c), desc,
                                               c.sub_scenario, c.library, str(size) if size is not None else "?"))
                    + (BLANK, BLANK))
    lines += _table(REVIEW_COLUMNS, rows)
    return "\n".join(lines) + "\n"


def provenance_block(meta: Dict[str, object], funnel: Dict[str, int]) -> str:
    """The header `main` inserts under the title: the pinned source and the full funnel."""
    pin = (f"sha256 `{meta['sha256']}`, {meta.get('size_bytes', '?')} bytes, mtime {meta.get('mtime', '?')}"
           if "sha256" in meta else f"HEAD `{meta.get('head_sha', '?')}` ({meta.get('head_date', '?')})")
    eco = meta.get("ecosystem", "?")
    return "\n".join([
        "",
        f"Source: `{meta.get('source', '?')}` — {meta.get('repository', '?')} at `{meta.get('path', '?')}`; "
        f"pinned: {pin}; ecosystem {eco}; {CWE}.",
        "",
        f"Funnel: {funnel.get('scanned', 0)} records scanned → {funnel.get('ecosystem', 0)} {eco} → "
        f"{funnel.get('cwe', 0)} naming {CWE} ({funnel.get('withdrawn', 0)} withdrawn upstream, dropped) → "
        f"{funnel.get('with_fix_ref', 0)} with a fix ref ({funnel.get('pr_resolved', 0)} PR-only refs resolved to a "
        f"merge commit, {funnel.get('pr_unresolved', 0)} refs still without a single commit) → "
        f"{funnel.get('after_dedupe', 0)} raw after dedupe → {funnel.get('raw_with_fix_ref', 0)} raw with a fix ref "
        f"({funnel.get('raw_with_fix_commit', 0)} with a fix commit).",
    ])


# --------------------------------------------------------------------- CLI

def main(argv=None) -> int:
    ap = argparse.ArgumentParser(prog="python -m evals.calib.ingest",
                                 description=f"Ingest {CWE} advisories into candidates.jsonl and the review sheet.")
    ap.add_argument("--source", nargs="+", required=True, metavar="SPEC",
                    help="`osv-zip <PyPI/all.zip>` (primary) | `osv-dir <advisory-database clone>` | `osv-fixtures [<dir>]`")
    ap.add_argument("--out", type=Path, default=None, help=f"candidates jsonl (default {CANDIDATES_FILE})")
    ap.add_argument("--review", type=Path, default=None, help=f"review sheet (default {CANDIDATES_REVIEW})")
    ap.add_argument("--gh-cache", type=Path, default=None, dest="gh_cache",
                    help="resolve lone PR refs to merge commits with `gh api`, caching under DIR (off without it)")
    args = ap.parse_args(argv)

    kind, *rest = args.source
    try:
        if kind == "osv-zip":
            if len(rest) != 1:
                ap.error("--source osv-zip needs exactly one zip path")
            source: Source = OSVZipSource(Path(rest[0]))
        elif kind == "osv-dir":
            if len(rest) != 1:
                ap.error("--source osv-dir needs exactly one path")
            source = OSVDirectorySource(Path(rest[0]))
        elif kind == "osv-fixtures":
            if len(rest) > 1:
                ap.error("--source osv-fixtures takes at most one directory")
            source = OSVFixtureSource(Path(rest[0]) if rest else FIXTURES_DIR)
        else:
            ap.error(f"unknown source {kind!r}; use osv-zip, osv-dir or osv-fixtures")
    except FileNotFoundError as e:
        print(f"ingest: {e}", file=sys.stderr)
        return 2
    out = args.out or CANDIDATES_FILE
    review = args.review or CANDIDATES_REVIEW
    if kind == "osv-fixtures" and (out == CANDIDATES_FILE or review == CANDIDATES_REVIEW):
        print("ingest: refusing to write fixture output over the real candidates; pass --out and --review",
              file=sys.stderr)
        return 2

    resolver = GhPRResolver(args.gh_cache) if args.gh_cache else None
    cands, funnel = scan(source, resolver=resolver)
    meta: Dict[str, object] = dict(source.describe()) if hasattr(source, "describe") else {"source": source.id}
    meta["funnel"] = funnel
    if resolver is not None:
        meta["pr_resolution"] = {"gh_api_calls_this_run": resolver.calls, "cached_prs": len(list(resolver.cache_dir.glob("*.json"))),
                                 "disabled_reason": resolver.disabled_reason}
    write_candidates(cands, out, meta=meta)
    text = render_review(cands).replace(REVIEW_TITLE, REVIEW_TITLE + "\n" + provenance_block(meta, funnel), 1)
    review.parent.mkdir(parents=True, exist_ok=True)
    review.write_text(text, encoding="utf-8")
    print(f"{source.id}: " + " -> ".join(f"{k} {funnel[k]}" for k in FUNNEL_KEYS))
    if resolver is not None and resolver.disabled_reason:
        print(f"PR resolution stopped: {resolver.disabled_reason}", file=sys.stderr)
    print(f"wrote {len(cands)} records (+ _meta) to {out}\nwrote {review}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
