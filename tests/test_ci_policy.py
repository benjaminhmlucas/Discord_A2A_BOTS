"""CI controls must fail closed rather than merely upload findings."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent


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
@pytest.mark.parametrize(
    "location", ["driver", "extension_id", "extension_index", "extension_name"]
)
def test_codeql_gate_blocks_missing_results_and_medium_or_higher_findings(
    tmp_path, severity, level, expected, location
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
        run = report["runs"][0]
        if location != "driver":
            rules = run["tool"]["driver"].pop("rules")
            run["tool"]["extensions"] = [{"name": "synthetic-pack", "rules": rules}]
            if location == "extension_index":
                run["results"][0]["rule"] = {"index": 0, "toolComponent": {"index": 0}}
            elif location == "extension_name":
                run["results"][0]["rule"] = {
                    "id": "synthetic",
                    "toolComponent": {"name": "synthetic-pack"},
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
    assert "Traceback" not in result.stderr
    if severity is not None:
        assert f"Blocking CodeQL findings: {expected}" in result.stdout
        assert "Unresolved CodeQL findings: 0" in result.stdout


@pytest.mark.parametrize(
    "fault",
    ["unknown", "ambiguous", "negative_component", "bad_component", "bad_rule", "mismatch", "nan"],
)
def test_codeql_gate_fails_closed_with_clear_unresolved_rule_diagnostic(tmp_path, fault):
    workflow = yaml.safe_load((ROOT / ".github/workflows/codeql.yml").read_text())
    script = next(step["run"] for step in workflow["jobs"]["analyze"]["steps"] if "run" in step)
    script = script.split("python - <<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    rule = {"id": "synthetic", "properties": {"security-severity": "4"}}
    result = {"ruleId": "synthetic", "level": "warning"}
    tool = {"driver": {"rules": [rule]}}
    if fault == "unknown":
        result["ruleId"] = "missing"
    elif fault == "ambiguous":
        tool["extensions"] = [{"rules": [rule]}]
    elif fault == "nan":
        rule["properties"]["security-severity"] = "NaN"
    elif fault in ("negative_component", "bad_component"):
        result["rule"] = {
            "index": 0,
            "toolComponent": {"index": -1 if fault == "negative_component" else 10},
        }
    elif fault == "bad_rule":
        result["ruleIndex"] = 10
    else:
        result.update(ruleId="wrong", ruleIndex=0)
    (tmp_path / "finding.sarif").write_text(
        json.dumps({"runs": [{"tool": tool, "results": [result]}]})
    )
    process = subprocess.run(
        [sys.executable, "-c", script],
        env={**os.environ, "SARIF_DIRECTORY": str(tmp_path)},
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert process.returncode == 1
    assert "Unresolved CodeQL findings: 1" in process.stdout
    assert "Traceback" not in process.stderr
