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
    print('WINDOW-PROBE-OUTPUT', flush=True)
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
            code = "import os,sys; from pathlib import Path; from scripts.manage import run; run(sys.argv[2:],Path(sys.argv[1]),os.environ.copy())"
            child = subprocess.run(
                [
                    sys.executable,
                    "-c",
                    code,
                    str(tmp_path),
                    sys.executable,
                    str(probe),
                    "--probe-json",
                    str(output),
                ],
                cwd=manage.ROOT,
                creationflags=subprocess.CREATE_NO_WINDOW,
                capture_output=True,
                text=True,
                check=True,
                timeout=20,
            )
            assert "WINDOW-PROBE-OUTPUT" in child.stdout
            result = json.loads(output.read_text())
    assert result == {"console": 0, "visible_windows": []}


@pytest.mark.parametrize(
    "method", ["spawn", "spawnSync", "fork", "exec", "execSync", "execFile", "execFileSync"]
)
def test_provider_node_descendant_does_not_create_a_visible_console(tmp_path, method):
    node = os.environ.get("BOTBRIDGE_TEST_NODE") or shutil.which("node")
    assert node, "Native helper check requires Node"
    probe = tmp_path / "probe.py"
    probe.write_text(PROBE, encoding="utf-8")
    output = tmp_path / "descendant.json"
    prefix = "const cp=require('node:child_process');"
    if method in ("exec", "execSync"):
        command = f'"{sys.executable}" "{probe}" --probe-json "{output}"'
        invocation = f"cp.{method}({json.dumps(command)},{{}}"
    else:
        options = (
            "{execPath:process.argv[1],execArgv:[],stdio:['ignore','pipe','pipe','ipc']}"
            if method == "fork"
            else "{stdio:'inherit'}"
            if method.startswith("spawn")
            else "{}"
        )
        executable = "process.argv[2]" if method == "fork" else "process.argv[1]"
        argv = "process.argv.slice(3)" if method == "fork" else "process.argv.slice(2)"
        invocation = f"cp.{method}({executable},{argv},{options}"
    if method in ("exec", "execFile"):
        code = (
            prefix
            + invocation
            + ", (err,out)=>{process.stdout.write(out);process.exit(err?1:0);});"
        )
    elif method in ("execSync", "execFileSync"):
        code = prefix + "process.stdout.write(" + invocation + "));"
    elif method == "fork":
        code = (
            prefix
            + "const child="
            + invocation
            + ");child.stdout.pipe(process.stdout);child.on('exit',code=>process.exit(code));"
        )
    else:
        code = (
            prefix
            + "const child="
            + invocation
            + ");"
            + (
                "child.on('exit',code=>process.exit(code));"
                if method == "spawn"
                else "process.exit(child.status);"
            )
        )
    result = subprocess.run(
        [node, "-e", code, sys.executable, str(probe), "--probe-json", str(output)],
        env=providers.child_env(),
        creationflags=subprocess.CREATE_NO_WINDOW,
        capture_output=True,
        text=True,
        check=True,
        timeout=20,
    )
    assert json.loads(output.read_text()) == {"console": 0, "visible_windows": []}
    assert "WINDOW-PROBE-OUTPUT" in result.stdout
