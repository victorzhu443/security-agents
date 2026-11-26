"""RC-5 — secrets come from one place and go to as few places as possible.

`require_secret` makes a missing secret a startup failure everywhere except an
explicitly development/test environment, instead of a silent dev default.
`write_private` makes "this file holds a credential" a 0600 file, atomically,
regardless of the process umask.

APP_ENV labels (case-insensitive, whitespace-trimmed):

    dev set   unset / "" / dev / development / test / testing / local
              -> a `dev_default` may be used
    prod set  prod / production
              -> never a default
    anything else (staging, qa, uat, prd, live, a typo ...)
              -> never a default — FAIL CLOSED

The last line is the point: an unrecognised label is treated like production
for secrets. Derive DEBUG-style switches from `is_dev()`, never from
`not is_production()`, or a staging box inherits development behaviour.
"""
from __future__ import annotations

import os
import tempfile
from typing import Mapping, Optional, Union

_DEV = frozenset({"dev", "development", "test", "testing", "local"})
_PROD = frozenset({"prod", "production"})


class MissingSecret(RuntimeError):
    """A required secret is absent outside a development/test environment."""


def app_env(env: Optional[Mapping[str, str]] = None) -> str:
    """The normalised APP_ENV label; unset or empty means "dev"."""
    src = os.environ if env is None else env
    return (src.get("APP_ENV") or "dev").strip().lower()


def is_dev(env: Optional[Mapping[str, str]] = None) -> bool:
    """True only for an explicit development/test label, or no label at all."""
    return app_env(env) in _DEV


def is_production(env: Optional[Mapping[str, str]] = None) -> bool:
    """True for prod/production.

    This is NOT the complement of `is_dev`: a label such as "staging" is neither,
    and `require_secret` treats it like production. Use `is_dev()` to decide
    whether development behaviour (DEBUG, dev defaults) is allowed.
    """
    return app_env(env) in _PROD


def require_secret(name: str, *, dev_default: Optional[str] = None,
                   env: Optional[Mapping[str, str]] = None) -> str:
    """Return the secret from the environment.

    If absent: when `is_dev()` and a `dev_default` is given, return it; in every
    other environment raise `MissingSecret`, so a deployment with a missing or
    mislabelled environment refuses to boot on a placeholder key.
    """
    src = os.environ if env is None else env
    value = src.get(name)
    if value:
        return value
    if dev_default is not None and is_dev(src):
        return dev_default
    raise MissingSecret(
        f"{name} is not set (APP_ENV={app_env(src)!r}). A development default is used "
        f"only when APP_ENV is unset or one of {sorted(_DEV)}; set the environment "
        f"variable — unrecognised labels fail closed on purpose.")


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
