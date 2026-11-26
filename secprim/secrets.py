"""RC-5 — secrets come from one place and go to as few places as possible.

`require_secret` makes a missing production secret a startup failure instead of
a silent dev default. `write_private` makes "this file holds a credential" a
0600 file, atomically, regardless of the process umask.
"""
from __future__ import annotations

import os
import tempfile
from typing import Mapping, Optional, Union

_PROD = {"prod", "production"}


class MissingSecret(RuntimeError):
    """A required secret is absent in a non-development environment."""


def app_env(env: Optional[Mapping[str, str]] = None) -> str:
    src = os.environ if env is None else env
    return (src.get("APP_ENV") or "dev").strip().lower()


def is_production(env: Optional[Mapping[str, str]] = None) -> bool:
    return app_env(env) in _PROD


def require_secret(name: str, *, dev_default: Optional[str] = None,
                   env: Optional[Mapping[str, str]] = None) -> str:
    """Return the secret from the environment.

    If absent: in dev/test (APP_ENV unset, "dev" or "test") return `dev_default`
    when one is given; in production raise `MissingSecret` so the service
    refuses to boot on a placeholder key.
    """
    src = os.environ if env is None else env
    value = src.get(name)
    if value:
        return value
    if dev_default is not None and not is_production(src):
        return dev_default
    raise MissingSecret(
        f"{name} is not set (APP_ENV={app_env(src)!r}). Set the environment variable; "
        f"no default is used outside development.")


def write_private(path: Union[str, os.PathLike], data: Union[bytes, str], *,
                  mode: int = 0o600) -> None:
    """Write `data` to `path` with permission `mode` (default owner-only),
    atomically (temp file + rename), under a restrictive umask so the file is
    never world-readable even for an instant."""
    path = os.fspath(path)
    payload = data.encode("utf-8") if isinstance(data, str) else data
    directory = os.path.dirname(path) or "."
    old_umask = os.umask(0o077)
    try:
        fd, tmp = tempfile.mkstemp(prefix=".private-", dir=directory)
        try:
            with os.fdopen(fd, "wb") as f:
                f.write(payload)
                f.flush()
                os.fsync(f.fileno())
            os.chmod(tmp, mode)
            os.replace(tmp, path)
        except Exception:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise
    finally:
        os.umask(old_umask)
