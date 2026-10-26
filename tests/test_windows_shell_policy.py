"""Stock Windows shell selection and actual parser checks, without installing pwsh."""

import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
from unittest.mock import patch

import pytest

from scripts.console_windows import creation_flags
import test_native_setup as native


def test_native_default_selects_builtin_powershell_without_probing_pwsh():
    lookups = []

    def which(name):
        lookups.append(name)
        return "synthetic-" + name

    with patch.dict(os.environ), patch("shutil.which", which):
        os.environ.pop("BOTBRIDGE_TEST_NODE", None)
        os.environ.pop("BOTBRIDGE_TEST_POWERSHELL", None)
        values = runpy.run_path(str(native.ROOT / "tests/test_native_setup.py"))
    assert values["POWERSHELL"] == "synthetic-powershell.exe"
    assert lookups == ["node", "powershell.exe"]


def test_native_explicit_shell_override_and_missing_runtime_guidance():
    with patch.dict(os.environ, BOTBRIDGE_TEST_POWERSHELL="explicit-shell"):
        values = runpy.run_path(str(native.ROOT / "tests/test_native_setup.py"))
    assert values["POWERSHELL"] == "explicit-shell"
    for node, shell in ((None, "shell"), ("node", None)):
        with patch.object(native, "NODE", node), patch.object(native, "POWERSHELL", shell):
            with pytest.raises(pytest.fail.Exception, match="Windows PowerShell 5.1"):
                native.require_windows_runtime()


@pytest.mark.skipif(sys.platform != "win32", reason="Actual Windows PowerShell parser")
def test_stock_parser_still_rejects_wrapper_branches(tmp_path):
    native.require_windows_runtime()
    target = tmp_path / "conditional-wrapper.ps1"
    target.write_text("if ($true) { Write-Output 'must never run' }", encoding="utf-8")
    result = subprocess.run(
        [
            native.POWERSHELL,
            "-NoProfile",
            "-File",
            str(native.ROOT / "tests/verify_wrappers.ps1"),
            "-Target",
            str(target),
            "-Receipt",
            str(tmp_path / "receipt.json"),
        ],
        capture_output=True,
        text=True,
        timeout=30,
        creationflags=creation_flags(),
    )
    assert result.returncode != 0
    assert "Setup decisions must remain" in result.stderr
    assert "must never run" not in result.stdout


def test_credential_import_does_not_load_the_http_stack():
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "import sys,time,json; start=time.perf_counter(); import bridge_credentials; print(json.dumps({'http_loaded':'aiohttp' in sys.modules,'seconds':time.perf_counter()-start}))",
        ],
        cwd=Path(__file__).resolve().parent.parent,
        capture_output=True,
        text=True,
        timeout=15,
        creationflags=creation_flags(),
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["http_loaded"] is False
    assert report["seconds"] >= 0  # Diagnostic only; no hardware-dependent timing threshold.
