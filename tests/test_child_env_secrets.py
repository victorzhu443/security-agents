"""RC-3/RC-5 primitives: allow-listed child env; secrets from one place, 0600 files."""
import os
import stat

import pytest

from secprim.child_env import child_env, assert_no_secrets, DEFAULT_ALLOW
from secprim.secrets import MissingSecret, require_secret, write_private


def test_child_env_is_built_from_allow_list_only():
    parent = {"PATH": "/usr/bin", "LANG": "C", "HOME": "/Users/me",
              "ANTHROPIC_API_KEY": "k", "HF_TOKEN": "t", "AWS_SECRET_ACCESS_KEY": "s",
              "DATABASE_URL": "postgres://x"}
    env = child_env(source=parent)
    assert env["PATH"] == "/usr/bin" and env["LANG"] == "C"
    for leaked in ("ANTHROPIC_API_KEY", "HF_TOKEN", "AWS_SECRET_ACCESS_KEY", "DATABASE_URL", "HOME"):
        assert leaked not in env
    assert env["PYTHONDONTWRITEBYTECODE"] == "1"
    assert_no_secrets(env)  # must not raise


def test_child_env_explicit_set_and_home_win():
    env = child_env(source={"PATH": "/bin"}, set={"PYTHONPATH": "/work", "PATH": "/custom"},
                    home="/tmp/h")
    assert env["PYTHONPATH"] == "/work" and env["PATH"] == "/custom" and env["HOME"] == "/tmp/h"


def test_assert_no_secrets_catches_credential_like_keys():
    with pytest.raises(AssertionError):
        assert_no_secrets({"PATH": "/bin", "MY_SERVICE_TOKEN": "x"})
    with pytest.raises(AssertionError):
        assert_no_secrets({"OPENAI_API_KEY": "x"})
    assert_no_secrets({k: "v" for k in DEFAULT_ALLOW})


def test_require_secret_dev_default_only_outside_production():
    assert require_secret("K", env={"K": "real"}) == "real"
    assert require_secret("K", dev_default="dev", env={}) == "dev"
    assert require_secret("K", dev_default="dev", env={"APP_ENV": "test"}) == "dev"
    with pytest.raises(MissingSecret):
        require_secret("K", dev_default="dev", env={"APP_ENV": "production"})
    with pytest.raises(MissingSecret):
        require_secret("K", dev_default="dev", env={"APP_ENV": "prod"})
    with pytest.raises(MissingSecret):
        require_secret("K", env={})  # no default, even in dev


def test_write_private_is_owner_only_and_atomic(tmp_path):
    target = tmp_path / "session.json"
    write_private(target, '{"cookie": "x"}')
    assert target.read_text() == '{"cookie": "x"}'
    mode = stat.S_IMODE(os.stat(target).st_mode)
    assert mode == 0o600, oct(mode)
    assert [p.name for p in tmp_path.iterdir()] == ["session.json"]  # no temp left behind
    write_private(target, b"bytes too")  # overwrite path works
    assert target.read_bytes() == b"bytes too"
    assert stat.S_IMODE(os.stat(target).st_mode) == 0o600
