"""P5 secrets graders (plugin): the two oracles a scanner cannot be.

    secrets_boot  expect: {module: settings, secret: API_KEY,
                           envs: [staging, qa, "prod ", produciton]}
        Imports `<module>.py` from the variant directory in a fresh subprocess
        with APP_ENV set to each label and the secret UNSET. Detected = the
        module boots (exit 0) on a default under any non-development label.
        Two sanity runs guard the verdict: the module must boot under
        APP_ENV=dev, and must boot under APP_ENV=staging once the secret is
        set — otherwise the module is broken, not clean, and the grader errors.

    secrets_mode  expect: {target: "session:write_session"}
        Calls `fn(path, data)` in a temp dir under umask 022 and stats the
        result. Detected = any group/other permission bit is set.
"""
from __future__ import annotations

import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List

from .graders import Case, Result, load_attr

REPO = Path(__file__).resolve().parents[1]
DEFAULT_LABELS = ["staging", "qa", "uat", "prd", "live", "prod ", "produciton"]


class SecretsBootGrader:
    name = "secrets_boot"

    @staticmethod
    def _boots(variant_dir: Path, module: str, env: Dict[str, str]) -> bool:
        base = {"PATH": os.environ.get("PATH", ""), "HOME": os.environ.get("HOME", ""),
                "PYTHONPATH": str(REPO), "PYTHONDONTWRITEBYTECODE": "1"}
        out = subprocess.run([sys.executable, "-c", f"import {module}"], cwd=str(variant_dir),
                             env={**base, **env}, capture_output=True, text=True, timeout=60)
        return out.returncode == 0

    def grade(self, case: Case, variant: str) -> Result:
        vdir = case.variant_dir(variant)
        module = case.expect.get("module", "settings")
        secret = case.expect["secret"]
        labels: List[str] = list(case.expect.get("envs", DEFAULT_LABELS))
        if not (vdir / f"{module}.py").exists():
            return Result(False, error=f"{vdir / (module + '.py')} does not exist")
        if not self._boots(vdir, module, {"APP_ENV": "dev"}):
            return Result(False, error="module does not boot under APP_ENV=dev with the secret unset")
        if not self._boots(vdir, module, {"APP_ENV": "staging", secret: "set-by-grader"}):
            return Result(False, error="module does not boot under APP_ENV=staging with the secret set")
        booted = [l for l in labels if self._boots(vdir, module, {"APP_ENV": l})]
        return Result(detected=bool(booted),
                      metrics={"booted_on_default": booted, "probed": labels},
                      evidence=(f"booted on a default under APP_ENV={booted}" if booted
                                else "refused to boot without the secret under every probed label"))


class SecretsModeGrader:
    name = "secrets_mode"

    def grade(self, case: Case, variant: str) -> Result:
        try:
            fn = load_attr(case.variant_dir(variant), case.expect["target"])
        except Exception as e:  # noqa: BLE001
            return Result(False, error=f"load: {e!r}")
        with tempfile.TemporaryDirectory(prefix="evals-secrets-") as d:
            path = Path(d) / "session.json"
            old = os.umask(0o022)       # the usual interactive default
            try:
                fn(str(path), {"token": "canary-token-not-a-real-secret"})
            except Exception as e:  # noqa: BLE001
                return Result(False, error=f"write_session raised {e!r}")
            finally:
                os.umask(old)
            if not path.exists():
                return Result(False, error="write_session did not create the file")
            mode = stat.S_IMODE(path.stat().st_mode)
        leaked = mode & 0o077
        return Result(detected=bool(leaked), metrics={"mode": oct(mode)},
                      evidence=f"mode {oct(mode)}" + (" (group/other bits set)" if leaked else " (owner-only)"))


GRADERS = {"secrets_boot": SecretsBootGrader(), "secrets_mode": SecretsModeGrader()}
