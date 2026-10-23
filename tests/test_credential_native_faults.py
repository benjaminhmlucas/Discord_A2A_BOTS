"""Only the native API/spawn boundary is injected; store logic remains real."""

import ctypes
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from bridge_credentials import CredentialError, LinuxCredentials, MacCredentials


@pytest.mark.parametrize("operation", ["set", "delete"])
def test_mac_mutations_never_read_or_decode_existing_malformed_blob(operation):
    calls = []

    def find(_chain, _size, _key, _account_size, _account, length, password, item):
        assert length is None and password is None
        ctypes.cast(item, ctypes.POINTER(ctypes.c_void_p))[0] = ctypes.c_void_p(1)
        calls.append("find-item-only")
        return 0

    def mutate(*_):
        calls.append("mutate")
        return 0

    backend = object.__new__(MacCredentials)
    backend.security = SimpleNamespace(
        SecKeychainFindGenericPassword=find,
        SecKeychainItemModifyAttributesAndData=mutate,
        SecKeychainItemDelete=mutate,
        SecKeychainItemFreeContent=lambda *_: pytest.fail("No password buffer was allocated"),
    )
    backend.core = SimpleNamespace(CFRelease=lambda *_: calls.append("release"))
    if operation == "set":
        backend.set("fixture", "new-valid-secret")
    else:
        backend.delete("fixture")
    assert calls == ["find-item-only", "mutate", "release"]


def test_linux_hung_native_worker_is_killed_and_waited_before_error():
    real_popen = subprocess.Popen
    children = []

    def launch(command, *args, **kwargs):
        # Native operation withholds its reply, represented by a real sleeping process.
        assert Path(command[1]).name == "bridge_credential_host.py"
        child = real_popen([sys.executable, "-c", "import time; time.sleep(20)"], *args, **kwargs)
        children.append(child)
        return child

    started = time.monotonic()
    with patch("subprocess.Popen", launch):
        with pytest.raises(CredentialError, match="timed out"):
            LinuxCredentials().get("BotBridge.MCP/fixture")
    assert 2.5 <= time.monotonic() - started < 8
    assert len(children) == 1 and children[0].poll() is not None
    # A new worker runs immediately; there is no abandoned executor/native process.
    with patch(
        "subprocess.Popen",
        lambda command, *args, **kwargs: real_popen(
            [sys.executable, "-c", "print('{\"value\":null}')"], *args, **kwargs
        ),
    ):
        assert LinuxCredentials().get("BotBridge.MCP/fixture") is None
