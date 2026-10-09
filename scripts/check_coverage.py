"""Require exact complete statement/branch coverage of every shipped Python module."""

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def validate_report(report, root=ROOT):
    root = Path(root)
    data = json.loads(Path(report).read_text(encoding="utf-8"))
    if not data["meta"]["branch_coverage"]:
        raise ValueError("Branch measurement is required")
    paths = list(root.glob("*.py"))
    for directory in ("scripts", "AntigravityBot"):
        paths.extend((root / directory).rglob("*.py"))
    expected = {path.relative_to(root).as_posix() for path in paths}
    measured = {name.replace("\\", "/") for name in data["files"]}
    if not expected or measured != expected:
        raise ValueError("Measured files differ from the complete shipped Python source set")
    for name, coverage in data["files"].items():
        summary = coverage["summary"]
        if summary["missing_lines"] or summary["missing_branches"] or summary["excluded_lines"]:
            raise ValueError("Incomplete or excluded coverage in " + name)
    print("Exact coverage gate passed: every shipped Python statement and branch, zero exclusions.")
    return data["totals"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", nargs="?", default="coverage.json")
    validate_report(parser.parse_args().report)


if __name__ == "__main__":
    main()
