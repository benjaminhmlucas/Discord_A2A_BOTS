"""Measure the actual owned host in subprocesses, including its Windows job."""

import os
from pathlib import Path
import runpy
import subprocess
import sys

import coverage

ROOT = Path(__file__).resolve().parent.parent


def test_real_host_pipes_exit_codes_and_launch_failure(tmp_path):
    # Import guard without running main in the pytest process (which must not own a job).
    runpy.run_path(str(ROOT / "scripts/mcp_host.py"), run_name="host_library")
    commands = [
        (
            [
                sys.executable,
                "-c",
                "import sys; print('host stdout'); print('host stderr',file=sys.stderr); sys.exit(7)",
            ],
            7,
        ),
        ([str(tmp_path / "missing-executable")], 1),
    ]
    for number, (command, expected) in enumerate(commands):
        datafile = tmp_path / f"host-{number}.coverage"
        env = {
            k: v
            for k, v in os.environ.items()
            if k.upper()
            in {
                "SYSTEMROOT",
                "WINDIR",
                "PATH",
                "TEMP",
                "TMP",
                "USERPROFILE",
                "APPDATA",
                "LOCALAPPDATA",
            }
        }
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "coverage",
                "run",
                "--data-file",
                str(datafile),
                "scripts/mcp_host.py",
                *command,
            ],
            cwd=ROOT,
            env=env,
            input="",
            capture_output=True,
            text=True,
            timeout=15,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        assert result.returncode == expected
        if expected == 7:
            assert result.stdout.strip() == "host stdout" and result.stderr.strip() == "host stderr"
        else:
            assert result.stdout == result.stderr == ""
        active = coverage.Coverage.current()
        if active:
            child = coverage.CoverageData(basename=str(datafile))
            child.read()
            active.get_data().update(child)
