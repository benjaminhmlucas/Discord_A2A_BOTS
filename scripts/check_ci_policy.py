"""Read workflow YAML as data and reject unsafe PR/CI configurations.

Run this checker from a trusted checkout when inspecting another checkout. It does
not execute candidate code or detect every semantic prompt-injection attempt.
"""

import argparse
import re
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
EXPRESSION = re.compile(r"\$\{\{(.*?)\}\}", re.S)
SAFE_EXPRESSIONS = {
    "runner.temp",
    "matrix.language",
    "matrix.os",
    "github.workflow",
    "github.event_name == 'pull_request' && github.ref || github.run_id",
    "github.event_name == 'pull_request'",
}


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


def validate_workflow(text, name):
    # Reject aliases as well as anchors: cyclic or shared structures can hide fields.
    require(
        not any(
            isinstance(token, (yaml.AnchorToken, yaml.AliasToken)) for token in yaml.scan(text)
        ),
        "yaml_alias_or_anchor",
    )
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
    require(workflow.get("permissions") == {"contents": "read"}, "workflow_permissions")
    require("env" not in workflow, "ambient_workflow_environment")
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
    jobs = workflow.get("jobs")
    expected_jobs = {"analyze"} if name == "codeql.yml" else {"test", "quality"}
    require(isinstance(jobs, dict) and set(jobs) == expected_jobs, "unexpected_ci_jobs")
    for identity, job in jobs.items():
        require(isinstance(job, dict), "job_mapping_required")
        require(
            not set(job) & {"environment", "secrets", "uses", "env", "container", "services"},
            "privileged_job_context",
        )
        permissions = {"contents": "read"}
        if name == "codeql.yml":
            permissions["security-events"] = "write"
        require(job.get("permissions", workflow["permissions"]) == permissions, "job_permissions")
        runner = job.get("runs-on")
        require(runner in ("ubuntu-24.04", "windows-2022", "${{ matrix.os }}"), "untrusted_runner")
        if runner == "${{ matrix.os }}":
            require(
                job.get("strategy", {}).get("matrix", {}).get("os")
                == ["ubuntu-24.04", "windows-2022"],
                "untrusted_runner_matrix",
            )
        if identity == "quality":
            require("strategy" not in job, "untrusted_job_matrix")
        else:
            matrix = (
                {"language": ["python", "javascript-typescript"]}
                if name == "codeql.yml"
                else {"os": ["ubuntu-24.04", "windows-2022"]}
            )
            require(
                job.get("strategy") == {"fail-fast": False, "matrix": matrix},
                "untrusted_job_matrix",
            )
        steps = job.get("steps")
        require(isinstance(steps, list) and bool(steps), "steps_required")
        checkout = False
        for step in steps:
            require(isinstance(step, dict), "step_mapping_required")
            require(("uses" in step) != ("run" in step), "step_operation_required")
            # PR-controlled workflow names and matrices are data, never shell input.
            for value in strings([step.get("run"), step.get("env")]):
                for match in EXPRESSION.finditer(value):
                    require(match.group(1).strip() == "runner.temp", "expression_in_execution")
            if "uses" in step:
                action = step["uses"]
                require(
                    isinstance(action, str)
                    and re.fullmatch(r"(?:actions|github)/[\w/-]+@[a-f0-9]{40}", action),
                    "unpinned_or_untrusted_action",
                )
                if action.startswith("actions/checkout@"):
                    checkout = True
                    require(
                        step.get("with", {}).get("persist-credentials") is False,
                        "persisted_checkout_credentials",
                    )
        require(checkout, "checkout_required")
        if name == "ci.yml" and identity == "quality":
            require(
                any(step.get("run") == "python scripts/check_ci_policy.py" for step in steps),
                "policy_gate_required",
            )
    for value in strings(workflow):
        for match in EXPRESSION.finditer(value):
            require(match.group(1).strip() in SAFE_EXPRESSIONS, "untrusted_expression")


def validate_directory(root=ROOT):
    directory = Path(root) / ".github/workflows"
    paths = sorted(directory.glob("*.y*ml"))
    require({path.name for path in paths} == {"ci.yml", "codeql.yml"}, "workflow_inventory")
    for path in paths:
        require(not path.is_symlink() and path.stat().st_size <= 100_000, "unsafe_workflow_file")
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
