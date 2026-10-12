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
    "fault,code",
    [
        ("trigger", "untrusted_workflow_trigger"),
        ("branches", "unbounded_branch_trigger"),
        ("permissions", "workflow_permissions"),
        ("ambient_env", "ambient_workflow_environment"),
        ("cancellation", "main_run_cancellation"),
        ("job_set", "unexpected_ci_jobs"),
        ("job_type", "job_mapping_required"),
        ("environment", "unapproved_job_key"),
        ("job_secrets", "unapproved_job_key"),
        ("reusable", "unapproved_job_key"),
        ("job_env", "unapproved_job_key"),
        ("container", "unapproved_job_key"),
        ("services", "unapproved_job_key"),
        ("job_permission", "job_permissions"),
        ("runner", "untrusted_runner"),
        ("runner_matrix", "untrusted_job_matrix"),
        ("steps_empty", "steps_required"),
        ("steps_type", "steps_required"),
        ("step_type", "step_mapping_required"),
        ("step_both", "step_operation_required"),
        ("step_neither", "step_operation_required"),
        ("action", "unpinned_or_untrusted_action"),
        ("action_type", "unpinned_or_untrusted_action"),
        ("imposter_pin", "unapproved_action_pin"),
        ("credentials", "persisted_checkout_credentials"),
        ("missing_checkout", "checkout_required"),
        ("missing_gate", "policy_gate_required"),
        ("pr_title_expression", "expression_in_execution"),
        ("pr_body_expression", "expression_in_execution"),
        ("pr_comment_expression", "expression_in_execution"),
        ("secrets_expression", "expression_in_execution"),
        ("codeql_permission", "job_permissions"),
    ],
)
def test_hostile_pr_workflow_changes_fail_closed(candidate, fault, code):
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
    elif fault == "imposter_pin":
        # Approved family, well-formed but unreviewed commit (older or fork-network SHA).
        job["steps"][0]["uses"] = "actions/checkout@" + "f" * 40
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
    with pytest.raises(gate.PolicyError, match=f"^{code}$"):
        gate.validate_directory(candidate)


@pytest.mark.parametrize("job_name", ["test", "quality", "analyze"])
@pytest.mark.parametrize(
    "setting",
    [{"group": "shared-lock", "cancel-in-progress": True}, "shared-lock"],
    ids=["mapping", "string"],
)
def test_job_concurrency_cannot_cancel_protected_runs(candidate, job_name, setting):
    # A literal job group is shared by every run, including main; even without
    # cancel-in-progress, GitHub cancels the older pending job in that group.
    name = "codeql.yml" if job_name == "analyze" else "ci.yml"
    data = load(candidate, name)
    data["jobs"][job_name]["concurrency"] = setting
    save(candidate, data, name)
    command = [sys.executable, ROOT / "scripts/check_ci_policy.py", candidate]
    result = subprocess.run(command, capture_output=True, text=True, timeout=10)
    assert result.returncode == 1
    assert result.stdout.strip() == "CI policy rejected: unapproved_job_key"


@pytest.mark.parametrize(
    "text,code",
    [
        ("[]", "workflow_mapping_required"),
        ("on: {}\non: {}", "duplicate_yaml_key"),
        ("on: &scope {}", "yaml_alias_or_anchor"),
        ("on: *scope", "yaml_alias_or_anchor"),
        ("on: !!python/object:danger {}", "ConstructorError"),
        ("[unclosed", "ParserError"),
        ("? [unhashable, key]\n: value", "TypeError"),
        (None, "AttributeError"),
    ],
)
def test_malformed_yaml_and_aliases_reject_without_echoing_payload(
    candidate, text, code, monkeypatch, capsys
):
    path = candidate / ".github/workflows/ci.yml"
    if text is None:
        # Valid triggers reach the workflow concurrency check with a non-mapping value.
        original = path.read_text()
        block = original[original.index("concurrency:") : original.index("permissions:")]
        text = original.replace(block, "concurrency: wrong\n")
    path.write_text(text)
    monkeypatch.setattr(sys, "argv", ["check_ci_policy.py", str(candidate)])
    assert gate.main() == 1
    output = capsys.readouterr().out
    assert output.strip() == "CI policy rejected: " + code
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
    "fault,code",
    [
        ("action_script", "unapproved_action_family"),
        ("shell_expression", "untrusted_expression"),
        ("working_directory_expression", "untrusted_expression"),
        ("defaults", "workflow_defaults"),
        ("gate_if", "step_execution"),
        ("gate_nonblocking", "step_failure_ignored"),
        ("gate_directory", "policy_gate_execution"),
        ("job_if", "unapproved_job_key"),
        ("job_nonblocking", "unapproved_job_key"),
        ("runner_detached", "untrusted_runner"),
        ("run_list", "run_string_required"),
        ("run_empty", "run_string_required"),
        ("with_list", "action_input_mapping"),
        ("env_list", "step_environment_mapping"),
        ("input_list", "action_input_scalar"),
        ("action_input_expression", "untrusted_expression"),
        ("workflow_name_expression", "untrusted_expression"),
        ("upper_case_workflow", "workflow_inventory"),
    ],
)
def test_adversarial_review_regressions_with_real_checker(
    candidate, fault, code, monkeypatch, capsys
):
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
    assert capsys.readouterr().out.strip() == "CI policy rejected: " + code


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
    "fault,code",
    [
        ("scan_skip", "step_execution"),
        ("test_nonblocking", "step_failure_ignored"),
        ("diagnostic_condition", "diagnostic_condition"),
        ("run_with", "run_action_inputs"),
    ],
)
def test_other_security_steps_cannot_be_silenced(candidate, fault, code):
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
    with pytest.raises(gate.PolicyError, match=f"^{code}$"):
        gate.validate_directory(candidate)
