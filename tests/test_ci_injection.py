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
    with pytest.raises(gate.PolicyError, match="unapproved_action_input"):
        gate.validate_directory(candidate)


def test_native_yaml_object_command_never_runs(candidate, monkeypatch, capsys):
    owned = candidate / "injection-owned.txt"
    payload = "!!python/object/apply:os.system ['echo OWNED > " + owned.as_posix() + "']"
    (candidate / ".github/workflows/ci.yml").write_text(payload)
    monkeypatch.setattr(sys, "argv", ["check_ci_policy.py", str(candidate)])
    assert gate.main() == 1
    assert not owned.exists()
    assert "OWNED" not in capsys.readouterr().out


@pytest.mark.parametrize(
    "fault",
    [
        "action_script",
        "shell_expression",
        "working_directory_expression",
        "defaults",
        "gate_if",
        "gate_nonblocking",
        "gate_directory",
        "job_if",
        "job_nonblocking",
        "runner_detached",
        "run_list",
        "run_empty",
        "with_list",
        "env_list",
        "input_list",
        "action_input_expression",
        "workflow_name_expression",
        "upper_case_workflow",
    ],
)
def test_adversarial_review_regressions_with_real_checker(candidate, fault, monkeypatch, capsys):
    data = load(candidate)
    job = data["jobs"]["quality"]
    policy = next(
        step for step in job["steps"] if step.get("run") == "python scripts/check_ci_policy.py"
    )
    if fault == "action_script":
        job["steps"].append(
            {
                "uses": "actions/github-script@" + "a" * 40,
                "with": {"script": "${{ github.workflow }}"},
            }
        )
    elif fault in ("shell_expression", "working_directory_expression"):
        job["steps"].append(
            {
                "run": "echo safe",
                "shell"
                if fault == "shell_expression"
                else "working-directory": "${{ github.workflow }}",
            }
        )
    elif fault == "defaults":
        data["defaults"] = {"run": {"shell": "${{ github.workflow }}"}}
    elif fault in ("gate_if", "gate_nonblocking", "gate_directory"):
        policy[
            {
                "gate_if": "if",
                "gate_nonblocking": "continue-on-error",
                "gate_directory": "working-directory",
            }[fault]
        ] = {"gate_if": False, "gate_nonblocking": True, "gate_directory": "other-checkout"}[fault]
    elif fault in ("job_if", "job_nonblocking"):
        job["if" if fault == "job_if" else "continue-on-error"] = fault != "job_if"
    elif fault == "runner_detached":
        data["jobs"]["test"]["runs-on"] = "ubuntu-24.04"
    elif fault in ("run_list", "run_empty"):
        job["steps"].append({"run": ["echo invalid"] if fault == "run_list" else "  "})
    elif fault == "with_list":
        job["steps"][0]["with"] = ["invalid"]
    elif fault == "env_list":
        job["steps"].append({"run": "echo safe", "env": ["invalid"]})
    elif fault == "input_list":
        job["steps"][1]["with"]["python-version"] = ["invalid"]
    elif fault == "action_input_expression":
        job["steps"][1]["with"]["python-version"] = "${{ github.workflow }}"
    elif fault == "workflow_name_expression":
        data["name"] = "${{ github.event.pull_request.title }}"
    else:
        (candidate / ".github/workflows/extra.YAML").write_text("on: pull_request_target")
    save(candidate, data)
    monkeypatch.setattr(sys, "argv", ["check_ci_policy.py", str(candidate)])
    assert gate.main() == 1
    assert "CI policy rejected:" in capsys.readouterr().out


@pytest.mark.parametrize("level", ["root", "github", "workflows", "leaf"])
def test_actual_workflow_links_are_rejected(candidate, level):
    mapping = {
        "root": candidate,
        "github": candidate / ".github",
        "workflows": candidate / ".github/workflows",
        "leaf": candidate / ".github/workflows/ci.yml",
    }
    linked = mapping[level]
    target = candidate.parent / (candidate.name + "-link-target-" + level)
    # Every move/create stays in this test's owned temporary parent; no shared paths.
    assert linked.resolve().is_relative_to(candidate.parent.resolve())
    assert target.resolve().is_relative_to(candidate.parent.resolve()) and not target.exists()
    if os.name == "nt" and level == "leaf":
        # A directory named ci.yml is a real malformed leaf; no symlink privilege needed.
        linked.rename(target)
        linked.mkdir()
        with pytest.raises(gate.PolicyError, match="unsafe_workflow_file"):
            gate.validate_directory(candidate)
        return
    linked.rename(target)
    if os.name == "nt":

        def quote(value):
            return "'" + str(value).replace("'", "''") + "'"

        subprocess.run(
            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "New-Item -ItemType Junction -Path "
                + quote(linked)
                + " -Target "
                + quote(target)
                + " | Out-Null",
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )
    else:
        linked.symlink_to(target, target_is_directory=target.is_dir())
    with pytest.raises(gate.PolicyError, match="linked_workflow_path"):
        gate.validate_directory(candidate)


@pytest.mark.parametrize(
    "fault", ["scan_skip", "test_nonblocking", "diagnostic_condition", "run_with"]
)
def test_other_security_steps_cannot_be_silenced(candidate, fault):
    data = load(candidate)
    if fault == "scan_skip":
        data["jobs"]["quality"]["steps"][-1]["if"] = False
    elif fault == "test_nonblocking":
        data["jobs"]["test"]["steps"][4]["continue-on-error"] = True
    elif fault == "diagnostic_condition":
        next(step for step in data["jobs"]["test"]["steps"] if "if" in step)["if"] = True
    else:
        data["jobs"]["quality"]["steps"].append({"run": "echo safe", "with": {}})
    save(candidate, data)
    with pytest.raises(gate.PolicyError):
        gate.validate_directory(candidate)
