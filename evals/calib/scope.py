"""Reachable-from-fix scope rule for calibration tasks (evals/calib/CONTRACTS.md, W-B).

    scope_files(repo, commit, fix_files) -> the files the agent may edit on a positive task:
        fix_files ∪ their direct importers, read from the clone at `commit` (the vulnerable
        tree) with a best-effort static scan of `import` / `from ... import` statements —
        always a superset of fix_files, sorted, no duplicates.
    allowed_prefixes()                   -> ("tests/", "test/"): directories the scope grader
        allows on every task (a regression test for a fix is in scope; on negatives they are
        the ONLY allowed edits).

What "direct importer" means here: a `.py` file at `commit` with a statement that names a
fix module — `import pkg.sub.mod`, `from pkg.sub.mod import x`, `from pkg.sub import mod`,
`from .mod import x`, `from . import mod` (relative forms match on the module's last
component, which over-approximates across packages; the rule is deliberately permissive —
the scope grader punishes edits OUTSIDE the set, so a wider set only ever makes the grade
more lenient, never wrong in the other direction). Non-`.py` fix files (a pyproject, a
data file) have no importers. Call-graph reachability beyond one hop is not attempted.

Everything is read with `git show` / `git grep` at `commit`; the working tree is never read,
so the scan does not depend on what is checked out.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path, PurePosixPath
from typing import Dict, List, Sequence, Set, Tuple

__all__ = ["scope_files", "allowed_prefixes", "module_names", "imports_module"]


def allowed_prefixes() -> Tuple[str, ...]:
    """Directory prefixes the scope grader allows on every calib task."""
    return ("tests/", "test/")


def _git(repo: Path, *args: str, check: bool = True, timeout: int = 300) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=str(repo), capture_output=True, text=True,
                          check=check, timeout=timeout)


def module_names(path: str) -> List[str]:
    """Dotted module names a `.py` path can be imported by, longest first.

    `pkg/sub/mod.py` -> ["pkg.sub.mod", "sub.mod", "mod"]; `pkg/sub/__init__.py` -> ["pkg.sub", "sub"];
    `src/pkg/mod.py` also yields the names without the `src` layout prefix. Non-`.py` -> [].
    """
    p = PurePosixPath(path)
    if p.suffix != ".py":
        return []
    parts = list(p.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    if not parts:
        return []
    names: List[str] = []
    for i in range(len(parts)):
        tail = parts[i:]
        if all(re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", t) for t in tail):
            names.append(".".join(tail))
    return names


_FROM_IMPORT = re.compile(r"^\s*from\s+(\.*)([\w.]*)\s+import\s+(.+?)\s*(#.*)?$")
_IMPORT = re.compile(r"^\s*import\s+(.+?)\s*(#.*)?$")


def _imported_items(items: str) -> Set[str]:
    """Names in an import list, aliases dropped: `a, mod as m, (c)` -> {a, mod, c}."""
    out: Set[str] = set()
    for chunk in items.strip("()").split(","):
        words = chunk.split()
        if words:
            out.add(words[0])
    return out


def imports_module(text: str, names: Sequence[str]) -> bool:
    """True when `text` has an import statement naming one of `names` (see module docstring).

    Single-line statements only (a parenthesised list split over lines is matched on its first
    line, which holds the module path — the common case `from pkg.mod import (\\n a,\\n b)` works;
    `from pkg import (\\n mod)` does not). Best effort by contract."""
    wanted = set(names)
    parents = {n.rsplit(".", 1)[0] for n in names if "." in n}
    lasts = {n.rsplit(".", 1)[-1] for n in names}
    for raw in text.splitlines():
        line = raw.strip()
        m = _FROM_IMPORT.match(line)
        if m:
            dots, mod, items = m.group(1), m.group(2), m.group(3)
            if mod in wanted:                                   # from pkg.sub.mod import x
                return True
            if dots and mod and mod.rsplit(".", 1)[-1] in lasts:   # from .mod import x
                return True
            if (dots or mod in parents) and _imported_items(items) & lasts:
                return True                                     # from pkg.sub import mod / from . import mod
            continue
        m = _IMPORT.match(line)
        if m:                                                   # import pkg.sub.mod [as m], other
            for chunk in m.group(1).split(","):
                words = chunk.split()
                if words and words[0] in wanted:
                    return True
    return False


def _py_files_at(repo: Path, commit: str) -> List[str]:
    out = _git(repo, "ls-tree", "-r", "--name-only", commit).stdout.splitlines()
    return [p for p in out if p.endswith(".py")]


def _candidates_via_git_grep(repo: Path, commit: str, lasts: Set[str]) -> List[str] | None:
    """Files at `commit` whose text mentions an import of one of the last components; None when
    `git grep` is unavailable (the caller falls back to scanning every .py file)."""
    if not lasts:
        return []
    # POSIX ERE (git grep -E has no \b): a word boundary is spelled out. This is only a coarse
    # pre-filter; `imports_module` decides.
    alt = "|".join(sorted(re.escape(x) for x in lasts))
    pattern = rf"^[[:space:]]*(from|import)[[:space:]].*(^|[^[:alnum:]_])({alt})([^[:alnum:]_]|$)"
    r = _git(repo, "grep", "-l", "-I", "-E", "-e", pattern, commit, "--", "*.py", check=False)
    if r.returncode not in (0, 1):
        return None
    prefix = f"{commit}:"
    return [ln[len(prefix):] if ln.startswith(prefix) else ln.split(":", 1)[-1]
            for ln in r.stdout.splitlines() if ln]


def scope_files(repo: Path, commit: str, fix_files: Sequence[str]) -> List[str]:
    """fix_files ∪ direct importers of the fix modules at `commit`; sorted, deduplicated,
    always ⊇ fix_files (fix files are included even when absent at `commit`, e.g. a module
    the fix adds)."""
    repo = Path(repo)
    out: Set[str] = set(fix_files)
    names_by_file: Dict[str, List[str]] = {f: module_names(f) for f in fix_files}
    all_names = [n for ns in names_by_file.values() for n in ns]
    if not all_names:
        return sorted(out)
    lasts = {n.rsplit(".", 1)[-1] for n in all_names}
    cands = _candidates_via_git_grep(repo, commit, lasts)
    if cands is None:
        cands = _py_files_at(repo, commit)
    for path in cands:
        if path in out or not path.endswith(".py"):
            continue
        shown = _git(repo, "show", f"{commit}:{path}", check=False)
        if shown.returncode != 0:
            continue
        if imports_module(shown.stdout, all_names):
            out.add(path)
    return sorted(out)
