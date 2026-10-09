"""Real Windows launch paths must not allocate a console for their helpers."""

import asyncio
import json
import os
import shutil
import subprocess
import sys
from unittest.mock import patch

import pytest

import bridge_providers as providers
from scripts import manage

pytestmark = pytest.mark.skipif(sys.platform != "win32", reason="Native Windows console check")

PROBE = r"""
import ctypes, json, os, sys
from ctypes import wintypes
kernel = ctypes.WinDLL('kernel32')
kernel.GetConsoleWindow.restype = wintypes.HWND
user = ctypes.WinDLL('user32')
user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
user.IsWindowVisible.argtypes = [wintypes.HWND]
visible = []
@ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
def visit(hwnd, unused):
    pid = wintypes.DWORD()
    user.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    if pid.value == os.getpid() and user.IsWindowVisible(hwnd):
        visible.append(int(hwnd))
    return True
user.EnumWindows(visit, 0)
payload = json.dumps({'console': int(kernel.GetConsoleWindow() or 0), 'visible_windows': visible})
if '-o' in sys.argv:
    with open(sys.argv[sys.argv.index('-o') + 1], 'w') as file:
        file.write(payload)
elif '--probe-json' in sys.argv:
    with open(sys.argv[sys.argv.index('--probe-json') + 1], 'w') as file:
        file.write(payload)
else:
    print(json.dumps({'result': payload, 'is_error': False}))
"""


@pytest.mark.parametrize("mode", ["codex_public", "codex_work", "claude", "management"])
def test_actual_helper_has_no_console_or_visible_window(tmp_path, mode):
    probe = tmp_path / "probe.py"
    probe.write_text(PROBE, encoding="utf-8")
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"codex_model": "", "codex_reasoning_effort": "high"}))
    (tmp_path / "chat_runtime").mkdir()
    with (
        patch.object(providers, "ROOT", tmp_path),
        patch.object(providers, "NODE", sys.executable),
        patch.object(providers, "CODEX", str(probe)),
        patch.object(providers, "CLAUDE", str(probe)),
        patch.object(providers, "MEMORY", str(tmp_path)),
        patch.object(providers, "config_path", return_value=config),
        patch.object(providers, "secret", return_value="synthetic-oauth"),
    ):
        if mode.startswith("codex"):
            result = json.loads(
                asyncio.run(providers.codex("synthetic request", mode == "codex_work"))
            )
        elif mode == "claude":
            result = json.loads(asyncio.run(providers.claude("synthetic request")))
        else:
            output = tmp_path / "management.json"
            manage.run([sys.executable, probe, "--probe-json", output], tmp_path, os.environ.copy())
            result = json.loads(output.read_text())
    assert result == {"console": 0, "visible_windows": []}


@pytest.mark.parametrize("method", ["spawn", "spawnSync"])
def test_provider_node_descendant_does_not_create_a_visible_console(tmp_path, method):
    node = os.environ.get("BOTBRIDGE_TEST_NODE") or shutil.which("node")
    assert node, "Native helper check requires Node"
    probe = tmp_path / "probe.py"
    probe.write_text(PROBE, encoding="utf-8")
    output = tmp_path / "descendant.json"
    code = (
        "const cp=require('node:child_process');"
        f"const child=cp.{method}(process.argv[1],process.argv.slice(2),{{stdio:'inherit'}});"
        + (
            "child.on('exit',code=>process.exit(code));"
            if method == "spawn"
            else "process.exit(child.status);"
        )
    )
    subprocess.run(
        [node, "-e", code, sys.executable, str(probe), "--probe-json", str(output)],
        env=providers.child_env(),
        creationflags=subprocess.CREATE_NO_WINDOW,
        check=True,
        timeout=20,
    )
    assert json.loads(output.read_text()) == {"console": 0, "visible_windows": []}
