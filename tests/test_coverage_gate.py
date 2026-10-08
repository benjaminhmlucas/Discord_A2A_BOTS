import json
import runpy
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from test_setup import module

ROOT = Path(__file__).resolve().parent.parent
gate = module('coverage_gate', 'scripts/check_coverage.py')


@pytest.mark.parametrize('fault', [None, 'no_branches', 'files', 'empty', 'lines', 'branches', 'excluded'])
def test_exact_gate_rejects_incomplete_rounded_or_excluded_coverage(tmp_path, fault):
    (tmp_path / 'scripts').mkdir()
    (tmp_path / 'module.py').write_text('pass\n')
    summary = {'missing_lines': 0, 'missing_branches': 0, 'excluded_lines': 0}
    if fault in ('lines', 'branches', 'excluded'):
        summary[{'lines': 'missing_lines', 'branches': 'missing_branches', 'excluded': 'excluded_lines'}[fault]] = 1
    data = {'meta': {'branch_coverage': fault != 'no_branches'}, 'files': {'module.py': {'summary': summary}}, 'totals': summary}
    if fault in ('files', 'empty'):
        data['files'] = {}
    if fault == 'empty':
        (tmp_path / 'module.py').unlink()
    report = tmp_path / 'report.json'
    report.write_text(json.dumps(data))
    if fault:
        with pytest.raises(ValueError):
            gate.validate_report(report, tmp_path)
    else:
        assert gate.validate_report(report, tmp_path) == summary


def test_gate_cli_dispatch_and_help():
    with patch.object(gate.argparse.ArgumentParser, 'parse_args', return_value=SimpleNamespace(report='synthetic.json')), patch.object(gate, 'validate_report') as validate:
        gate.main()
        validate.assert_called_once_with('synthetic.json')
    with patch.object(sys, 'argv', ['check_coverage.py', '--help']):
        with pytest.raises(SystemExit) as stopped:
            runpy.run_path(str(ROOT / 'scripts/check_coverage.py'), run_name='__main__')
        assert stopped.value.code == 0
