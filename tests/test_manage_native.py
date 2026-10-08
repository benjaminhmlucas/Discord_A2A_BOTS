"""Actual command failure/deadline and Windows descendant cleanup."""
import ctypes
import os
import subprocess
import sys
import time
from pathlib import Path

import pytest
from test_setup_paths import manage


def test_real_command_success_failure_and_missing_executable(tmp_path):
    assert manage.run([sys.executable, '-c', 'raise SystemExit(0)'], tmp_path, os.environ.copy()).returncode == 0
    with pytest.raises(subprocess.CalledProcessError) as failed:
        manage.run([sys.executable, '-c', 'raise SystemExit(7)'], tmp_path, os.environ.copy())
    assert failed.value.returncode == 7
    with pytest.raises(OSError):
        manage.run([tmp_path / 'absent-executable'], tmp_path, os.environ.copy())


@pytest.mark.skipif(sys.platform != 'win32', reason='Actual taskkill descendant semantics')
def test_real_timeout_kills_owned_child_and_grandchild(tmp_path):
    pidfile = tmp_path / 'synthetic-child.pid'
    program = ("import subprocess,sys,time; from pathlib import Path; "
               "child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(30)']); "
               f"Path({str(pidfile)!r}).write_text(str(child.pid)); time.sleep(30)")
    began = time.monotonic()
    with pytest.raises(subprocess.TimeoutExpired):
        manage.run([sys.executable, '-c', program], tmp_path, os.environ.copy(), timeout=1)
    assert time.monotonic() - began < 15
    pid = int(pidfile.read_text())
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
    kernel.OpenProcess.restype = ctypes.c_void_p
    kernel.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
    kernel.CloseHandle.argtypes = [ctypes.c_void_p]
    handle = kernel.OpenProcess(0x100000, False, pid)
    if handle:
        try:
            assert kernel.WaitForSingleObject(handle, 0) == 0
        finally:
            kernel.CloseHandle(handle)
