"""Real Windows ACL denial, scoped to a fresh test directory; no simulated I/O."""

import os
import subprocess
import sys
from pathlib import Path

import pytest
import log_manager as manager
from test_log_manager import config, log


@pytest.mark.skipif(sys.platform != "win32", reason="Actual Windows directory ACL semantics")
def test_denied_scope_preserves_safe_cleanup_and_reports_unknown_budget(tmp_path):
    blocked = tmp_path / "denied-scope"
    blocked.mkdir()
    assert blocked.resolve().parent == tmp_path.resolve()
    protected = log(blocked, "denied.log", 20)
    good = log(tmp_path, "good.log", 500)
    unrelated = tmp_path / "protected.txt"
    unrelated.write_text("SYNTHETIC-PROTECTED-CONTENT")
    data = config(tmp_path)
    data["scopes"].append({"directory": str(blocked)})
    user = os.environ["USERDOMAIN"] + "\\" + os.environ["USERNAME"]
    icacls = Path(os.environ["SYSTEMROOT"]) / "System32/icacls.exe"

    def acl(*args):
        subprocess.run(
            [str(icacls), str(blocked), *args],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=10,
        )

    try:
        acl("/deny", user + ":(RD)")
        with pytest.raises(PermissionError):
            list(blocked.iterdir())
        state = manager.enforce(data)
        assert good.stat().st_size <= 100
        assert state["status"] == "error" and state["inventory_complete"] is False
        assert any(error["path"] == str(blocked) for error in state["errors"])
        assert unrelated.read_text() == "SYNTHETIC-PROTECTED-CONTENT"
    finally:
        acl("/remove:d", user)
    assert protected.stat().st_size == 20
    recovered = manager.enforce(data)
    assert recovered["status"] == "ok" and recovered["inventory_complete"] is True
