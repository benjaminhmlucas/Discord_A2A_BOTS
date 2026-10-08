"""Windows integration tests with real interpreters, scoped files and deterministic provider/PM2 adapters."""
import ctypes
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from ctypes import wintypes
from pathlib import Path

import pytest
from scripts.check_release import check_path

ROOT = Path(__file__).resolve().parent.parent
NODE = os.environ.get('BOTBRIDGE_TEST_NODE') or shutil.which('node')
POWERSHELL = os.environ.get('BOTBRIDGE_TEST_POWERSHELL') or shutil.which('pwsh')
pytestmark = pytest.mark.skipif(sys.platform != 'win32', reason='Native Windows integration; portable logic is tested separately')


def export_into(destination):
    for path in ROOT.rglob('*'):
        if not path.is_file():
            continue
        relative = path.relative_to(ROOT)
        if check_path(relative) or any(part in ('__pycache__', '.pytest_cache', 'coverage_html', '.git', '.venv', 'tools') for part in relative.parts):
            continue
        if path.name == '.coverage' or path.name.startswith('.coverage.') or path.name in ('coverage.json', 'SOURCE_MANIFEST.json'):
            continue
        target = destination / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(path.read_bytes())


def command(args, root, env, expected=0):
    result = subprocess.run([str(arg) for arg in args], cwd=root, env=env, capture_output=True, text=True, timeout=180)
    assert result.returncode == expected, result.stdout + result.stderr
    return result.stdout


def test_fresh_install_and_start_success_and_failure_propagation(tmp_path):
    if not NODE or not POWERSHELL:
        pytest.fail('Native setup verification requires Node and PowerShell 7')
    root = tmp_path / 'setup verification & isolated'
    root.mkdir()
    export_into(root)
    env = os.environ.copy()
    env.pop('BOTBRIDGE_CONFIG_FILE', None)
    env['PIP_DISABLE_PIP_VERSION_CHECK'] = '1'
    env['PM2_HOME'] = str(root / '.pm2')
    wheels = os.environ.get('BOTBRIDGE_TEST_WHEELS')
    if not wheels:
        wheels = str(tmp_path / 'wheels')
        command([sys.executable, '-m', 'pip', 'download', '-r', root / 'requirements.txt', '-d', wheels], root, env)
    env['PIP_NO_INDEX'] = '1'
    env['PIP_FIND_LINKS'] = wheels
    for name in ('CODEXBOT_TOKEN', 'ANTIGRAVITYBOT_TOKEN', 'CLAUDEBOT_TOKEN', 'GEMINI_API_KEY', 'CLAUDE_CODE_OAUTH_TOKEN'):
        env[name] = 'synthetic-integration-fixture-only'
    driver = root / 'tests/verify_wrappers.ps1'
    receipts = []
    def wrapper(name, label, expected=0, custom=env, extra=()):
        receipt = tmp_path / (label + '.json')
        command([POWERSHELL, '-NoProfile', '-File', driver, '-Target', root / ('scripts/' + name), '-Receipt', receipt, *extra], root, custom, expected)
        data = json.loads(receipt.read_text(encoding='utf-8-sig'))
        assert data['branches'] == 0 and all(point['hit'] for point in data['statements'])
        receipts.append(data)
    wrapper('setup.ps1', 'setup')
    python = root / '.venv/Scripts/python.exe'
    assert '3.11' in command([python, '-c', 'import sys;print(sys.version)'], root, env)
    assert 'No broken requirements' in command([python, '-m', 'pip', 'check'], root, env)
    command([python, 'initialize.py', '--owner-id', '201', '--channel-id', '301', '--codex-id', '101', '--antigravity-id', '102', '--claude-id', '103'], root, env)
    local = json.loads((root / 'local_settings.json').read_text())
    local.update(node_executable=NODE, pm2_cli='tools/pm2/fixture_pm2.cjs')
    for name in ('codex_cli', 'claude_cli'):
        path = root / local[name]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('// Existence fixture. Never executed.\n')
    pm2 = root / local['pm2_cli']
    pm2.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(root / 'tests/fixtures/fake_pm2.cjs', pm2)
    (root / 'local_settings.json').write_text(json.dumps(local))
    wrapper('start.ps1', 'start')
    records = json.loads((root / '.pm2/fixture_commands.json').read_text())
    assert [row[0] for row in records] == ['install', 'multiset', 'set', 'restart', 'start']
    assert records[-1][1] == str(root / 'ecosystem.config.js')
    assert not list((root / 'runtime_state').glob('health_*.json'))
    wrapper('pm2.ps1', 'pm2-command', extra=('-TargetArguments', 'list'))
    records = json.loads((root / '.pm2/fixture_commands.json').read_text())
    assert records[-1] == ['list']
    command([python, 'log_manager.py', '--config', 'log_management.config.json', '--once'], root, env)
    assert json.loads((root / 'log_management_state.json').read_text())['status'] == 'ok'
    failing = env.copy()
    failing['BOTBRIDGE_FAKE_PM2_FAIL'] = 'install'
    wrapper('start.ps1', 'start-failure', 1, failing)
    after = json.loads((root / '.pm2/fixture_commands.json').read_text())
    assert after[len(records):] == [['install', 'pm2-logrotate@3.0.0']]
    wrapper('setup.ps1', 'setup-failure', 7, extra=('-StubPythonLauncher', '-StubExitCode', '7'))
    assert len(receipts) == 5


def child_env():
    return {key: value for key, value in os.environ.items() if key.upper() in {
        'SYSTEMROOT', 'WINDIR', 'PATH', 'PATHEXT', 'TEMP', 'TMP', 'USERPROFILE', 'COMSPEC'}}


def test_optimized_python_retains_preflight_validation(tmp_path):
    root=tmp_path/'optimized setup'
    root.mkdir()
    export_into(root)
    env=os.environ.copy()
    env.pop('BOTBRIDGE_CONFIG_FILE',None)
    command([sys.executable,'initialize.py','--owner-id','201','--channel-id','301','--codex-id','101','--antigravity-id','102','--claude-id','103'],root,env)
    settings=json.loads((root/'local_settings.json').read_text())
    settings['node_executable']='missing-runtime.exe'
    (root/'local_settings.json').write_text(json.dumps(settings))
    result=subprocess.run([sys.executable,'-O','preflight.py'],cwd=root,env=env,capture_output=True,text=True,timeout=15)
    assert result.returncode != 0 and 'Required runtime/context file is unavailable' in result.stderr


def test_real_windows_duplicate_mutex(tmp_path):
    code = ('import sys,time;sys.path.insert(0,sys.argv[1]);from bridge_windows import protect_process;'
            'protect_process(sys.argv[2]);print("ready",flush=True);time.sleep(60)')
    args = [sys.executable, '-c', code, str(ROOT), str(tmp_path / 'unique-lock')]
    first = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=child_env())
    try:
        assert first.stdout.readline().strip() == 'ready'
        second = subprocess.run(args, capture_output=True, text=True, env=child_env(), timeout=15)
        assert second.returncode == 75
        assert not second.stdout
    finally:
        first.terminate()
        first.wait(timeout=10)


def test_real_windows_job_kills_only_spawned_descendant(tmp_path):
    code = ('import sys,subprocess,time;sys.path.insert(0,sys.argv[1]);from bridge_windows import protect_process;'
            'protect_process(sys.argv[2]);p=subprocess.Popen([sys.executable,"-c","import time;time.sleep(60)"]);'
            'print(p.pid,flush=True);time.sleep(60)')
    parent = subprocess.Popen([sys.executable, '-c', code, str(ROOT), str(tmp_path / 'unique-job')],
                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=child_env())
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.WaitForSingleObject.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = None
    try:
        pid = int(parent.stdout.readline().strip())
        handle = kernel.OpenProcess(0x00100000, False, pid)
        assert handle
        assert kernel.WaitForSingleObject(handle, 0) == 258  # Descendant alive before parent exit.
        parent.terminate()
        parent.wait(timeout=10)
        assert kernel.WaitForSingleObject(handle, 5000) == 0
    finally:
        if parent.poll() is None:
            parent.terminate()
            parent.wait(timeout=10)
        if handle:
            kernel.CloseHandle(handle)


@pytest.mark.parametrize('archives', [False, True])
def test_actual_gigabyte_log_budget_without_allocating_gigabyte_payload(tmp_path, archives):
    import msvcrt
    import log_manager
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    kernel.DeviceIoControl.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD,
                                      ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    protected = tmp_path / 'protected.txt'
    protected.write_text('synthetic protected content')
    digest = hashlib.sha256(protected.read_bytes()).hexdigest()
    count = 3 if archives else 1
    size = 370_000_000 if archives else 1_100_000_000
    for number in range(count):
        path = tmp_path / (f'fixture-{number}.log' + ('.1' if archives else ''))
        with path.open('w+b') as stream:
            returned = wintypes.DWORD()
            assert kernel.DeviceIoControl(msvcrt.get_osfhandle(stream.fileno()), 0x900C4, None, 0, None, 0, ctypes.byref(returned), None)
            stream.truncate(size)
            stream.seek(size - 2)
            stream.write(b'x\n')
    config = {'aggregate_limit_bytes': 1_000_000_000, 'cleanup_trigger_bytes': 900_000_000,
              'cleanup_target_bytes': 750_000_000, 'max_active_file_bytes': 10_485_760,
              'active_tail_bytes': 5_242_880, 'archive_max_age_days': 14, 'interval_seconds': 5,
              'scopes': [{'directory': str(tmp_path), 'include_transcripts': False}]}
    report = log_manager.enforce(config)
    assert report['before_bytes'] >= 1_100_000_000
    assert report['current_bytes'] <= 750_000_000 and report['status'] == 'ok'
    assert hashlib.sha256(protected.read_bytes()).hexdigest() == digest
