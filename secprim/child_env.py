"""RC-3 / RC-5 — build a child-process environment from an allow-list.

Inherit-minus-a-denylist leaks whatever nobody thought to deny (HF tokens, AWS
keys, DB URLs). Build from nothing and name what the child may see.
"""
from __future__ import annotations

import os
import re
from typing import Dict, Iterable, Mapping, Optional

# What a Python subprocess legitimately needs to run at all.
DEFAULT_ALLOW = frozenset({"PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ", "TERM",
                           "PYTHONIOENCODING"})

_SECRET_LIKE = re.compile(r"(?i)(api[_-]?key|secret|token|passw(or)?d|credential|"
                          r"private[_-]?key|auth)")


def child_env(*, allow: Iterable[str] = DEFAULT_ALLOW, set: Optional[Mapping[str, str]] = None,
              home: Optional[str] = None, source: Optional[Mapping[str, str]] = None
              ) -> Dict[str, str]:
    """An environment containing only `allow`-listed keys from `source`
    (default: os.environ), plus explicit `set` values and an optional HOME.

    Explicit `set` wins over inherited values; nothing else gets through.
    """
    src = os.environ if source is None else source
    env: Dict[str, str] = {k: src[k] for k in allow if k in src}
    if home is not None:
        env["HOME"] = home
    if set:
        env.update(dict(set))
    env.setdefault("PYTHONDONTWRITEBYTECODE", "1")
    return env


def assert_no_secrets(env: Mapping[str, str]) -> None:
    """Raise if any key in `env` looks like a credential. For tests and for a
    belt-and-braces check right before `subprocess.run(env=...)`."""
    leaked = sorted(k for k in env if _SECRET_LIKE.search(k))
    if leaked:
        raise AssertionError(f"secret-looking keys in child env: {leaked}")
