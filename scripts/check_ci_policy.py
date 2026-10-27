"""Read workflow YAML as data and reject unsafe PR/CI configurations.

Run this checker from a trusted checkout when inspecting another checkout. It does
not execute candidate code or detect every semantic prompt-injection attempt.
"""

import argparse
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
PRINTABLE = re.compile(r"[\t\n\r\x20-\x7e]*")
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.S)
ACTION_INPUTS = {
    "actions/checkout": {"persist-credentials": ()},
    "actions/setup-python": {"python-version": ()},
    "actions/setup-node": {"node-version": (), "package-manager-cache": ()},
    "actions/upload-artifact": {
        "name": (),
        "path": ("runner.temp",),
        "if-no-files-found": (),
        "retention-days": (),
        "include-hidden-files": (),
    },
    "github/codeql-action/init": {
        "languages": ("matrix.language",),
        "build-mode": (),
        "queries": (),
    },
    "github/codeql-action/analyze": {
        "category": ("matrix.language",),
        "output": ("runner.temp",),
    },
}
# Exact reviewed commits: an action update must change this trusted list deliberately.
ACTION_PINS = {
    "actions/checkout": "3d3c42e5aac5ba805825da76410c181273ba90b1",
    "actions/setup-python": "5fda3b95a4ea91299a34e894583c3862153e4b97",
    "actions/setup-node": "949feb2413d6458794dcd2491c4babbbce0c15c1",
    "actions/upload-artifact": "cf430e030ddbb5b0abf93d22962f4752f3646cd9",
    "github/codeql-action/init": "24c54180a607b1449ed407dd24f251e4e9147c8d",
    "github/codeql-action/analyze": "24c54180a607b1449ed407dd24f251e4e9147c8d",
}
# Allowlist, not denylist: if/continue-on-error/concurrency/env/uses etc. are rejected.
JOB_KEYS = {"name", "runs-on", "timeout-minutes", "permissions", "strategy", "steps"}
STEP_KEYS = {"name", "id", "uses", "with", "run", "env", "if"}


class PolicyError(ValueError):
    """Only checker-owned static codes may enter workflow diagnostics."""


def require(condition, code):
    if not condition:
        raise PolicyError(code)


class UniqueLoader(yaml.SafeLoader):
    """Duplicate YAML keys must not conceal settings from a policy reviewer."""

    def construct_mapping(self, node, deep=False):
        keys = [self.construct_object(key, deep=deep) for key, _ in node.value]
        require(len(set(keys)) == len(keys), "duplicate_yaml_key")
        return super().construct_mapping(node, deep=deep)


# GitHub uses YAML 1.2 booleans: keep `on` as a string without changing SafeLoader.
UniqueLoader.yaml_implicit_resolvers = {
    key: [rule for rule in rules if rule[0] != "tag:yaml.org,2002:bool"]
    for key, rules in yaml.SafeLoader.yaml_implicit_resolvers.items()
}
UniqueLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool", re.compile(r"^(?:true|false|True|False|TRUE|FALSE)$"), list("tTfF")
)


def strings(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield from strings(key)
            yield from strings(item)
    elif isinstance(value, list):
        for item in value:
            yield from strings(item)
    elif isinstance(value, str):
        yield value


def validate_expressions(value, permitted=(), code="untrusted_expression"):
    for text in strings(value):
        for match in EXPRESSION.finditer(text):
            require(match.group(1).strip() in permitted, code)


def validate_workflow(text, name):
    # YAML 1.1 (PyYAML) ends comments at U+0085/U+2028/U+2029; YAML 1.2 does not. Plain
    # printable ASCII removes that and other parser disagreements about hidden fields.
    require(PRINTABLE.fullmatch(text) is not None, "non_ascii_workflow")
    # Reject aliases as well as anchors: cyclic or shared structures can hide fields.
    # Explicit tags (e.g. `!!bool off`) are resolved differently across YAML versions.
    tokens = list(yaml.scan(text))
    require(
        not any(isinstance(token, (yaml.AnchorToken, yaml.AliasToken)) for token in tokens),
        "yaml_alias_or_anchor",
    )
    require(not any(isinstance(token, yaml.TagToken) for token in tokens), "yaml_tag")
    loader = UniqueLoader(text)
    try:
        workflow = loader.get_single_data()
    finally:
        loader.dispose()
    require(isinstance(workflow, dict), "workflow_mapping_required")
    triggers = workflow.get("on")
    allowed = {"push", "pull_request"} | ({"schedule"} if name == "codeql.yml" else set())
    require(isinstance(triggers, dict) and set(triggers) == allowed, "untrusted_workflow_trigger")
    for event in ("push", "pull_request"):
        require(triggers[event] == {"branches": ["main"]}, "unbounded_branch_trigger")
    if name == "codeql.yml":
        require(triggers["schedule"] == [{"cron": "23 8 * * 1"}], "untrusted_schedule")
    require(workflow.get("permissions") == {"contents": "read"}, "workflow_permissions")
    require("env" not in workflow, "ambient_workflow_environment")
    require("defaults" not in workflow, "workflow_defaults")
    concurrency = workflow.get("concurrency", {})
    require(
        concurrency.get("cancel-in-progress") == "${{ github.event_name == 'pull_request' }}",
        "main_run_cancellation",
    )
    expected_group = (
        "codeql-${{ github.event_name == 'pull_request' && github.ref || github.run_id }}"
        if name == "codeql.yml"
        else "verify-${{ github.workflow }}-${{ github.event_name == 'pull_request' && github.ref || github.run_id }}"
    )
    require(concurrency.get("group") == expected_group, "concurrency_group")
    for key, value in workflow.items():
        if key not in {"concurrency", "jobs"}:
            validate_expressions([key, value])
    jobs = workflow.get("jobs")
    expected_jobs = (
        {"analyze"}
        if name == "codeql.yml"
        else {"test", "quality", "credentials-linux", "credentials-macos"}
    )
    require(isinstance(jobs, dict) and set(jobs) == expected_jobs, "unexpected_ci_jobs")
    for identity, job in jobs.items():
        require(isinstance(job, dict), "job_mapping_required")
        require(set(job) <= JOB_KEYS, "unapproved_job_key")
        permissions = {"contents": "read"}
        if name == "codeql.yml":
            permissions["security-events"] = "write"
        require(job.get("permissions", workflow["permissions"]) == permissions, "job_permissions")
        runner = job.get("runs-on")
        # Only the isolated native credential job may use the pinned macOS image.
        expected_runner = {"test": "${{ matrix.os }}", "credentials-macos": "macos-15"}.get(
            identity, "ubuntu-24.04"
        )
        require(runner == expected_runner, "untrusted_runner")
        if identity not in ("test", "analyze"):
            require("strategy" not in job, "untrusted_job_matrix")
        else:
            matrix = (
                {"language": ["python", "javascript-typescript"]}
                if name == "codeql.yml"
                else {"os": ["ubuntu-24.04", "windows-2022"]}
            )
            strategy = job.get("strategy")
            require(
                strategy == {"fail-fast": False, "matrix": matrix}
                and strategy["fail-fast"] is False,  # 0 == False, but 0 is not a boolean.
                "untrusted_job_matrix",
            )
        for key, value in job.items():
            if key not in {"steps", "runs-on", "name"}:
                validate_expressions([key, value])
        validate_expressions(job.get("name"), ("matrix.language",) if name == "codeql.yml" else ())
        steps = job.get("steps")
        require(isinstance(steps, list) and bool(steps), "steps_required")
        checkout = False
        for step in steps:
            require(isinstance(step, dict), "step_mapping_required")
            require(("uses" in step) != ("run" in step), "step_operation_required")
            require(set(step) <= STEP_KEYS, "unapproved_step_key")
            diagnostic = str(step.get("uses", "")).startswith("actions/upload-artifact@")
            if diagnostic:
                require(
                    step.get("if") == "failure() && runner.os == 'Windows'", "diagnostic_condition"
                )
            else:
                require("if" not in step, "step_execution")
            if "run" in step:
                require(
                    isinstance(step["run"], str) and bool(step["run"].strip()),
                    "run_string_required",
                )
                require("with" not in step, "run_action_inputs")
            require(isinstance(step.get("env", {}), dict), "step_environment_mapping")
            validate_expressions(
                [step.get("run"), step.get("env")], ("runner.temp",), "expression_in_execution"
            )
            for key, value in step.items():
                if key not in {"run", "env", "with"}:
                    validate_expressions([key, value])
            if "uses" in step:
                action = step["uses"]
                require(
                    isinstance(action, str)
                    and re.fullmatch(r"(?:actions|github)/[\w/-]+@[a-f0-9]{40}", action),
                    "unpinned_or_untrusted_action",
                )
                family, pin = action.rsplit("@", 1)
                require(family in ACTION_INPUTS, "unapproved_action_family")
                require(pin == ACTION_PINS[family], "unapproved_action_pin")
                inputs = step.get("with", {})
                require(isinstance(inputs, dict), "action_input_mapping")
                require(set(inputs) <= set(ACTION_INPUTS[family]), "unapproved_action_input")
                for key, value in inputs.items():
                    require(type(value) in (str, bool, int, float), "action_input_scalar")
                    validate_expressions(value, ACTION_INPUTS[family][key])
                if action.startswith("actions/checkout@"):
                    checkout = True
                    require(
                        step.get("with", {}).get("persist-credentials") is False,
                        "persisted_checkout_credentials",
                    )
        require(checkout, "checkout_required")
        if name == "ci.yml" and identity == "quality":
            gates = [
                step for step in steps if step.get("run") == "python scripts/check_ci_policy.py"
            ]
            require(
                len(gates) == 1,
                "policy_gate_required",
            )
            require(set(gates[0]) <= {"name", "run"}, "policy_gate_execution")


def owned_path(path):
    require(
        not path.is_symlink() and not getattr(path.lstat(), "st_file_attributes", 0) & 0x400,
        "linked_workflow_path",
    )


def validate_directory(root=ROOT):
    root = Path(root).absolute()
    directory = root / ".github/workflows"
    for ancestor in (root, root / ".github", directory):
        owned_path(ancestor)
    paths = sorted(path for path in directory.iterdir() if path.suffix.lower() in {".yml", ".yaml"})
    require({path.name for path in paths} == {"ci.yml", "codeql.yml"}, "workflow_inventory")
    for path in paths:
        owned_path(path)
        require(path.is_file() and path.stat().st_size <= 100_000, "unsafe_workflow_file")
        validate_workflow(path.read_text(encoding="utf-8"), path.name)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("root", nargs="?", type=Path, default=ROOT)
    args = parser.parse_args()
    try:
        validate_directory(args.root)
    except (
        OSError,
        ValueError,
        TypeError,
        AttributeError,
        RecursionError,
        yaml.YAMLError,
    ) as error:
        # Static codes/types only: hostile YAML and credentials never reach logs.
        code = str(error) if isinstance(error, PolicyError) else type(error).__name__
        print("CI policy rejected: " + code)
        return 1
    print("CI policy passed: workflow permissions, runners, actions and expressions validated.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
