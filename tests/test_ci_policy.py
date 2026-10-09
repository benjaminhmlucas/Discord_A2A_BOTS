"""CI controls must fail closed rather than merely upload findings."""

import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent


def test_workflows_pin_actions_and_avoid_privileged_pr_execution():
    for path in (ROOT / ".github/workflows").glob("*.yml"):
        workflow = yaml.safe_load(path.read_text())
        assert "pull_request_target" not in path.read_text()
        assert workflow["permissions"] == {"contents": "read"}
        for job in workflow["jobs"].values():
            for step in job["steps"]:
                if "uses" in step:
                    assert re.fullmatch(r"(?:actions|github)/[\w/-]+@[a-f0-9]{40}", step["uses"])
                    if step["uses"].startswith("actions/checkout@"):
                        assert step["with"]["persist-credentials"] is False
    workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
    assert workflow["jobs"]["test"]["strategy"]["matrix"]["os"] == ["ubuntu-24.04", "windows-2022"]


@pytest.mark.parametrize(
    "severity,level,expected",
    [
        (None, None, 1),
        ("0", "warning", 0),
        ("3.9", "warning", 0),
        ("4", "warning", 1),
        ("9", "warning", 1),
        ("0", "error", 1),
    ],
)
def test_codeql_gate_blocks_missing_results_and_medium_or_higher_findings(
    tmp_path, severity, level, expected
):
    workflow = yaml.safe_load((ROOT / ".github/workflows/codeql.yml").read_text())
    script = next(step["run"] for step in workflow["jobs"]["analyze"]["steps"] if "run" in step)
    script = script.split("python - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    if severity is not None:
        report = {
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "rules": [
                                {"id": "synthetic", "properties": {"security-severity": severity}}
                            ]
                        }
                    },
                    "results": [{"ruleId": "synthetic", "level": level}],
                }
            ]
        }
        (tmp_path / "synthetic.sarif").write_text(json.dumps(report))
    env = {
        key: value
        for key, value in os.environ.items()
        if key in ("SYSTEMROOT", "PATH", "TEMP", "TMP")
    }
    env["SARIF_DIRECTORY"] = str(tmp_path)
    result = subprocess.run(
        [sys.executable, "-c", script], env=env, capture_output=True, text=True, timeout=10
    )
    assert result.returncode == expected, result.stdout + result.stderr
