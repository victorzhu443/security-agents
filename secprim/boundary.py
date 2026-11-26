"""RC-1 — validate untrusted input at the boundary, once.

Every function that first touches external data calls one of these before any
other logic. They raise a single declared type, `MalformedInput`, with a dotted
path naming where the bad value was, so the failure is a clean 400 / reported
failure instead of an undeclared AttributeError/TypeError deep in the code.
"""
from __future__ import annotations

import math
import os
from pathlib import Path
from typing import Any, Dict, List, Optional


class MalformedInput(ValueError):
    """The one failure type for 'this input is not what the boundary allows'."""


def as_dict(value: Any, path: str, *, optional: bool = False) -> Dict[str, Any]:
    """`value` must be a JSON object. `optional=True` turns None into {}."""
    if value is None and optional:
        return {}
    if isinstance(value, dict):
        return value
    raise MalformedInput(f"{path}: expected an object, got {type(value).__name__}")


def as_list(value: Any, path: str, *, optional: bool = False) -> List[Any]:
    """`value` must be a JSON array (never a str, which is also iterable)."""
    if value is None and optional:
        return []
    if isinstance(value, list):
        return value
    raise MalformedInput(f"{path}: expected a list, got {type(value).__name__}")


def as_str(value: Any, path: str, *, max_len: Optional[int] = None,
           optional: bool = False) -> str:
    """`value` must be a str (not coerced), optionally length-capped."""
    if value is None and optional:
        return ""
    if not isinstance(value, str):
        raise MalformedInput(f"{path}: expected a string, got {type(value).__name__}")
    if max_len is not None and len(value) > max_len:
        raise MalformedInput(f"{path}: longer than {max_len} characters")
    if "\x00" in value:
        raise MalformedInput(f"{path}: contains NUL")
    return value


def finite_float(value: Any, path: str, *, lo: Optional[float] = None,
                 hi: Optional[float] = None, coerce: bool = True) -> float:
    """A real, finite number — never NaN/±Inf, never a bool, within [lo, hi].

    `coerce=True` accepts numeric strings (query params); `"nan"`/`"1e999"`
    still fail because the check runs after conversion.
    """
    if isinstance(value, bool):
        raise MalformedInput(f"{path}: expected a number, got bool")
    if isinstance(value, (int, float)):
        f = float(value)
    elif coerce and isinstance(value, str):
        try:
            f = float(value.strip())
        except ValueError:
            raise MalformedInput(f"{path}: not a number") from None
    else:
        raise MalformedInput(f"{path}: expected a number, got {type(value).__name__}")
    if not math.isfinite(f):
        raise MalformedInput(f"{path}: must be finite (got {f})")
    if lo is not None and f < lo:
        raise MalformedInput(f"{path}: below minimum {lo}")
    if hi is not None and f > hi:
        raise MalformedInput(f"{path}: above maximum {hi}")
    return f


def contained_path(root: os.PathLike, relpath: Any) -> Path:
    """Join `relpath` under `root` only if the result stays inside `root`.

    Rejects NUL, absolute paths, Windows drive/UNC forms, and any `..`/symlink
    route that resolves outside `root`. Returns the *unresolved* join so callers
    that later do `.relative_to(root)` see the path they expect.
    """
    rel = as_str(relpath, "path")
    if not rel or rel.strip() != rel and False:  # keep simple: empty is invalid
        raise MalformedInput("path: empty")
    if os.path.isabs(rel) or rel.startswith(("/", "\\")) or (len(rel) > 1 and rel[1] == ":"):
        raise MalformedInput(f"path: absolute paths are not allowed ({rel!r})")
    root_p = Path(root)
    root_resolved = root_p.resolve()
    candidate = root_p / rel
    resolved = candidate.resolve()
    try:
        resolved.relative_to(root_resolved)
    except ValueError:
        raise MalformedInput(f"path: escapes the allowed directory ({rel!r})") from None
    return candidate
