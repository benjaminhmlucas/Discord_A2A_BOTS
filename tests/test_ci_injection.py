"""Execute the actual policy checker against hostile workflow files; no checker mocks."""

import copy
import os
import runpy
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

from test_setup import module

ROOT = Path(__file__).resolve().parent.parent
gate = module("ci_injection_gate", "scripts/check_ci_policy.py")


@pytest.fixture
def candidate(tmp_path):
    destination = tmp_path / ".github/workflows"
    shutil.copytree(ROOT / ".github/workflows", destination)
    return tmp_path


def load(root, name="ci.yml"):
    return yaml.load((root / ".github/workflows" / name).read_text(), Loader=gate.UniqueLoader)


def save(root, data, name="ci.yml"):
    (root / ".github/workflows" / name).write_text(yaml.safe_dump(data, sort_keys=False))


@pytest.mark.parametrize(
    "fault",
    [
        "trigger",
        "branches",
        "permissions",
        "ambient_env",
        "cancellation",
        "job_set",
        "job_type",
        "environment",
        "job_secrets",
        "reusable",
        "job_env",
        "container",
        "services",
        "job_permission",
        "runner",
        "runner_matrix",
        "steps_empty",
        "steps_type",
        "step_type",
        "step_both",
        "step_neither",
        "action",
        "action_type",
        "credentials",
        "missing_checkout",
        "missing_gate",
        "pr_title_expression",
        "pr_body_expression",
        "pr_comment_expression",
        "secrets_expression",
        "codeql_permission",
    ],
)
def test_hostile_pr_workflow_changes_fail_closed(candidate, fault):
    name = "codeql.yml" if fault == "codeql_permission" else "ci.yml"
    data = load(candidate, name)
    job = data["jobs"]["analyze" if name == "codeql.yml" else "quality"]
    if fault == "trigger":
        data["on"]["pull_request_target"] = data["on"].pop("pull_request")
    elif fault == "branches":
        data["on"]["pull_request"] = {"branches": ["*"]}
    elif fault == "permissions":
        data["permissions"] = "write-all"
    elif fault == "ambient_env":
        data["env"] = {"TOKEN": "synthetic"}
    elif fault == "cancellation":
        data["concurrency"]["cancel-in-progress"] = True
    elif fault == "job_set":
        data["jobs"]["extra"] = copy.deepcopy(job)
    elif fault == "job_type":
        data["jobs"]["quality"] = "untrusted"
    elif fault in ("environment", "job_secrets", "reusable", "job_env", "container", "services"):
        job[{"job_secrets": "secrets", "reusable": "uses", "job_env": "env"}.get(fault, fault)] = (
            "production"
        )
    elif fault in ("job_permission", "codeql_permission"):
        job["permissions"] = {"contents": "write", "security-events": "write"}
    elif fault == "runner":
        job["runs-on"] = "self-hosted"
    elif fault == "runner_matrix":
        data["jobs"]["test"]["strategy"]["matrix"]["os"].append("self-hosted")
    elif fault in ("steps_empty", "steps_type"):
        job["steps"] = [] if fault == "steps_empty" else "not a list"
    elif fault == "step_type":
        job["steps"][0] = "not a step"
    elif fault in ("step_both", "step_neither"):
        job["steps"][0].update(run="echo injected") if fault == "step_both" else job["steps"][
            0
        ].pop("uses")
    elif fault in ("action", "action_type"):
        job["steps"][0]["uses"] = "actions/checkout@main" if fault == "action" else 7
    elif fault == "credentials":
        job["steps"][0]["with"]["persist-credentials"] = True
    elif fault == "missing_checkout":
        job["steps"] = [
            step
            for step in job["steps"]
            if not step.get("uses", "").startswith("actions/checkout@")
        ]
    elif fault == "missing_gate":
        job["steps"] = [
            step for step in job["steps"] if step.get("run") != "python scripts/check_ci_policy.py"
        ]
    else:
        expression = {
            "pr_title_expression": "github.event.pull_request.title",
            "pr_body_expression": "github.event.pull_request.body",
            "pr_comment_expression": "github.event.comment.body",
            "secrets_expression": "secrets.PRODUCTION_CREDENTIAL",
        }[fault]
        job["steps"].append({"run": "echo ${{ " + expression + " }}"})
    save(candidate, data, name)
    with pytest.raises(gate.PolicyError):
        gate.validate_directory(candidate)


@pytest.mark.parametrize(
    "text",
    [
        "[]",
        "on: {}\non: {}",
        "on: &scope {}",
        "on: *scope",
        "on: !!python/object:danger {}",
        "[unclosed",
        "? [unhashable, key]\n: value",
        "on: {}\nconcurrency: wrong",
    ],
)
def test_malformed_yaml_and_aliases_reject_without_echoing_payload(
    candidate, text, monkeypatch, capsys
):
    (candidate / ".github/workflows/ci.yml").write_text(text)
    monkeypatch.setattr(sys, "argv", ["check_ci_policy.py", str(candidate)])
    assert gate.main() == 1
    output = capsys.readouterr().out
    assert "CI policy rejected:" in output
    assert "danger" not in output and "Traceback" not in output


def test_inventory_and_unsafe_files_fail_closed(candidate):
    path = candidate / ".github/workflows/ci.yml"
    original = path.read_bytes()
    path.unlink()
    with pytest.raises(gate.PolicyError, match="inventory"):
        gate.validate_directory(candidate)
    path.write_bytes(original + b" " * 100_001)
    with pytest.raises(gate.PolicyError, match="unsafe_workflow_file"):
        gate.validate_directory(candidate)


def test_real_cli_passes_valid_input_and_rejects_injection_without_execution(candidate, tmp_path):
    env = {
        key: value
        for key, value in os.environ.items()
        if key.upper() in {"PATH", "SYSTEMROOT", "TEMP", "TMP"}
    }
    script = ROOT / "scripts/check_ci_policy.py"
    result = subprocess.run(
        [sys.executable, script, candidate], env=env, capture_output=True, text=True, timeout=10
    )
    assert result.returncode == 0 and "CI policy passed" in result.stdout
    # Candidate source is data only; the real checker must not execute this run text.
    owned = tmp_path / "injection-owned.txt"
    data = load(candidate)
    data["jobs"]["quality"]["steps"].append(
        {"run": "echo ${{ github.event.pull_request.title }} > " + str(owned)}
    )
    save(candidate, data)
    result = subprocess.run(
        [sys.executable, script, candidate], env=env, capture_output=True, text=True, timeout=10
    )
    assert result.returncode == 1 and "expression_in_execution" in result.stdout
    assert not owned.exists() and "Traceback" not in result.stderr


def test_actual_cli_main_success_and_read_error(candidate, monkeypatch, capsys):
    monkeypatch.setattr(sys, "argv", ["check_ci_policy.py", str(candidate)])
    assert gate.main() == 0
    path = candidate / ".github/workflows/ci.yml"
    path.unlink()
    path.mkdir()
    assert gate.main() == 1
    assert "CI policy rejected:" in capsys.readouterr().out
    monkeypatch.setattr(sys, "argv", ["check_ci_policy.py", "--help"])
    with pytest.raises(SystemExit) as stopped:
        runpy.run_path(str(ROOT / "scripts/check_ci_policy.py"), run_name="__main__")
    assert stopped.value.code == 0


@pytest.mark.parametrize("expression", ["github.workflow", "matrix.os", "matrix.language"])
@pytest.mark.parametrize("sink", ["run", "env"])
def test_expression_safe_for_display_cannot_enter_shell_or_environment(candidate, expression, sink):
    data = load(candidate)
    value = "${{ " + expression + " }}"
    step = (
        {"run": "echo " + value}
        if sink == "run"
        else {"run": "echo safe", "env": {"PAYLOAD": value}}
    )
    data["jobs"]["quality"]["steps"].append(step)
    save(candidate, data)
    with pytest.raises(gate.PolicyError, match="expression_in_execution"):
        gate.validate_directory(candidate)


@pytest.mark.parametrize("fault", ["concurrency", "quality_matrix", "codeql_matrix", "test_matrix"])
def test_pr_controlled_structural_fields_cannot_disguise_dynamic_inputs(candidate, fault):
    name = "codeql.yml" if fault == "codeql_matrix" else "ci.yml"
    data = load(candidate, name)
    if fault == "concurrency":
        data["concurrency"]["group"] = "${{ github.workflow }}"
    elif fault == "quality_matrix":
        data["jobs"]["quality"]["strategy"] = {
            "matrix": {"language": ["$(create injection-owned.txt)"]}
        }
    else:
        job = data["jobs"]["analyze" if name == "codeql.yml" else "test"]
        job["strategy"]["matrix"]["include"] = [{"language": "$(create injection-owned.txt)"}]
    save(candidate, data, name)
    with pytest.raises(gate.PolicyError, match="matrix|concurrency"):
        gate.validate_directory(candidate)


def test_unsupported_expression_in_action_input_is_rejected(candidate):
    data = load(candidate)
    data["jobs"]["quality"]["steps"][0]["with"]["token"] = "${{ secrets.PRODUCTION_CREDENTIAL }}"
    save(candidate, data)
    with pytest.raises(gate.PolicyError, match="untrusted_expression"):
        gate.validate_directory(candidate)


def test_native_yaml_object_command_never_runs(candidate, monkeypatch, capsys):
    owned = candidate / "injection-owned.txt"
    payload = "!!python/object/apply:os.system ['echo OWNED > " + owned.as_posix() + "']"
    (candidate / ".github/workflows/ci.yml").write_text(payload)
    monkeypatch.setattr(sys, "argv", ["check_ci_policy.py", str(candidate)])
    assert gate.main() == 1
    assert not owned.exists()
    assert "OWNED" not in capsys.readouterr().out
