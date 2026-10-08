"""Real PM2 daemon and logrotate integration; only Discord/AI consumers are fixture processes."""
import gzip
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest
import test_native_setup as native
from test_setup_paths import manage

pytestmark = pytest.mark.skipif(sys.platform != 'win32', reason='Actual Windows PM2 deployment integration')


def test_real_pm2_start_rotation_stop_codes_save_resurrect_and_isolation(tmp_path):
    if not native.NODE or not native.POWERSHELL:
        pytest.fail('Real PM2 integration requires Node and PowerShell 7')
    root = tmp_path / 'real PM2 setup & isolated'
    root.mkdir()
    native.export_into(root)
    env = native.child_env()
    env['PATH'] = str(Path(native.NODE).parent) + os.pathsep + env.get('PATH', '')
    env['PM2_HOME'] = str(root / '.pm2')
    env['PM2_NO_INTERACTION'] = 'true'
    env['PM2_SILENT'] = 'true'
    env['NODE_OPTIONS'] = '--require=' + json.dumps(str(root / 'scripts/pm2_namespace.cjs'))
    env['PIP_DISABLE_PIP_VERSION_CHECK'] = '1'
    wheels = os.environ.get('BOTBRIDGE_TEST_WHEELS')
    if wheels:
        env.update(PIP_NO_INDEX='1', PIP_FIND_LINKS=wheels)
    for name in ('CODEXBOT_TOKEN', 'ANTIGRAVITYBOT_TOKEN', 'CLAUDEBOT_TOKEN', 'GEMINI_API_KEY', 'CLAUDE_CODE_OAUTH_TOKEN'):
        env[name] = 'synthetic-pm2-integration-only'

    def command(args, custom=env, timeout=90):
        # Real daemon descendants cannot hold an output-capture pipe open on Windows.
        with tempfile.TemporaryFile('w+', encoding='utf-8', errors='replace') as stdout, tempfile.TemporaryFile('w+', encoding='utf-8', errors='replace') as stderr:
            proc = subprocess.Popen([str(arg) for arg in args], cwd=root, env=custom,
                                    stdout=stdout, stderr=stderr)
            try:
                code = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                manage.stop_command(proc)
                stdout.seek(0)
                stderr.seek(0)
                print('Timed out command output:', stdout.read(), stderr.read(), flush=True)
                raise
            stdout.seek(0)
            stderr.seek(0)
            output, error = stdout.read(), stderr.read()
        assert code == 0, output + error
        return output

    command([native.POWERSHELL, '-NoProfile', '-File', root / 'scripts/setup.ps1'])
    python = root / '.venv/Scripts/python.exe'
    command([python, 'initialize.py', '--owner-id', '201', '--channel-id', '301', '--codex-id', '101', '--antigravity-id', '102', '--claude-id', '103'])
    prefix = root / 'tools/pm2'
    cache = os.environ.get('BOTBRIDGE_TEST_PM2_PREFIX')
    if cache:
        shutil.copytree(cache, prefix)
    else:
        npm = os.environ.get('BOTBRIDGE_TEST_NPM_CLI') or str(Path(native.NODE).parent / 'node_modules/npm/bin/npm-cli.js')
        prefix.mkdir(parents=True)
        shutil.copyfile(root / 'scripts/pm2-package.json', prefix / 'package.json')
        shutil.copyfile(root / 'scripts/pm2-package-lock.json', prefix / 'package-lock.json')
        command([native.NODE, npm, 'ci', '--prefix', prefix, '--no-audit', '--no-fund'])
    module = prefix / 'node_modules/pm2'
    assert json.loads((module / 'package.json').read_text())['version'] == '7.0.1'
    cli = module / 'bin/pm2'
    settings = json.loads((root / 'local_settings.json').read_text())
    settings['node_executable'] = native.NODE
    for name in ('codex_cli', 'claude_cli'):
        path = root / settings[name]
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text('// Provider existence fixture; not provider verification.\n')
    (root / 'local_settings.json').write_text(json.dumps(settings))
    fixture = "import sys,time\nprint('SYNTHETIC-REAL-PM2-TEST',flush=True)\nwhile True:\n print('SYNTHETIC-REAL-PM2-TEST:'+'x'*65536,flush=True)\n time.sleep(0.1)\n"
    (root / 'codexbot.py').write_text(fixture)
    (root / 'AntigravityBot/antigravitybot.py').write_text(fixture)
    (root / 'claudebot.py').write_text("import sys\nprint('SYNTHETIC-STOP-103',flush=True)\nsys.exit(103)\n")
    other = env.copy()
    other['PM2_HOME'] = str(root / 'second-daemon')
    def sockets(custom):
        result = json.loads(command([native.NODE, '-e',
            'console.log(JSON.stringify(require(process.argv[1])(process.env.PM2_HOME)))', module / 'paths.js'], custom))
        for name in ('DAEMON_RPC_PORT', 'DAEMON_PUB_PORT', 'INTERACTOR_RPC_PORT'):
            assert result[name].startswith('\\\\.\\pipe\\botbridge-')
            assert result[name] not in ('\\\\.\\pipe\\rpc.sock', '\\\\.\\pipe\\pub.sock', '\\\\.\\pipe\\interactor.sock')
        return result
    first_sockets, second_sockets = sockets(env), sockets(other)
    assert first_sockets['DAEMON_RPC_PORT'] != second_sockets['DAEMON_RPC_PORT']
    def pm2(*args, custom=env):
        return command([native.NODE, cli, *args], custom)
    def processes(custom=env):
        return json.loads(pm2('jlist', custom=custom))
    active = []
    try:
        active.append(env)
        pm2('ping')
        assert processes() == []
        active.append(other)
        pm2('ping', custom=other)
        assert processes(other) == []
        first_pid = int((root / '.pm2/pm2.pid').read_text())
        second_pid = int((root / 'second-daemon/pm2.pid').read_text())
        assert first_pid != second_pid
        # This wrapper runs six independently bounded PM2 commands plus npm.
        command([native.POWERSHELL, '-NoProfile', '-File', root / 'scripts/start.ps1'], timeout=900)
        assert not (root / '.pm2/dump.pm2').exists()
        names = {row['name'] for row in processes()}
        assert names == {'codexbot', 'antigravitybot', 'claudebot', 'botbridge-log-manager', 'botbridge-health', 'pm2-logrotate'}
        assert processes(other) == []
        pm2('multiset', 'pm2-logrotate:max_size 32K pm2-logrotate:retain 2 pm2-logrotate:compress true pm2-logrotate:workerInterval 1')
        pm2('restart', 'pm2-logrotate')
        logdir = root / '.pm2/logs'
        deadline = time.monotonic() + 25
        archives = []
        while time.monotonic() < deadline:
            archives = list(logdir.glob('codexbot-out__*.log.gz'))
            if len(archives) == 2:
                break
            time.sleep(0.5)
        assert len(archives) == 2, 'Real logrotate did not produce and retain two compressed archives'
        pm2('stop', 'codexbot')
        time.sleep(3)
        archives = list(logdir.glob('codexbot-out__*.log.gz'))
        assert 1 <= len(archives) <= 2
        for archive in archives:
            assert b'SYNTHETIC-REAL-PM2-TEST' in gzip.decompress(archive.read_bytes())
        rows = {row['name']: row for row in processes()}
        # PM2 7.0.1 unconditionally applies the delay's display label even when
        # stop_exit_codes prevents creating a restart task. Check actual behavior.
        assert rows['claudebot']['pm2_env']['status'] in ('stopped', 'waiting restart')
        assert rows['claudebot']['pid'] == 0
        assert rows['claudebot']['pm2_env']['exit_code'] == 103
        assert rows['claudebot']['pm2_env']['restart_time'] == 0
        time.sleep(6)
        stopped = {row['name']: row for row in processes()}['claudebot']
        assert stopped['pid'] == 0 and stopped['pm2_env']['restart_time'] == 0
        assert (logdir / 'claudebot-out.log').read_text().count('SYNTHETIC-STOP-103') == 1
        assert rows['pm2-logrotate']['pm2_env']['status'] == 'online'
        assert rows['botbridge-log-manager']['pm2_env']['status'] == 'online'
        assert json.loads((root / 'log_management_state.json').read_text())['status'] == 'ok'
        nested = root / '.pm2/modules/pm2-logrotate/node_modules/pm2/package.json'
        assert json.loads(nested.read_text())['version'] == '7.0.1'
        npm = str(Path(native.NODE).parent / 'node_modules/npm/bin/npm-cli.js')
        for destination in (prefix, root / '.pm2/modules/pm2-logrotate'):
            audit = json.loads(command([native.NODE, npm, 'audit', '--prefix', destination, '--json']))
            assert audit['metadata']['vulnerabilities']['total'] == 0
        # Reinstallation deletes the module prefix upstream. The override policy
        # must be applied again before npm resolves the new dependency graph.
        pm2('install', 'pm2-logrotate@3.0.0')
        command([python, root / 'scripts/fix_logrotate.py'])
        pm2('restart', 'pm2-logrotate')
        assert json.loads(nested.read_text())['version'] == '7.0.1'
        pm2('start', 'codexbot')
        pm2('save')
        assert {row['name'] for row in json.loads((root / '.pm2/dump.pm2').read_text())} == names - {'pm2-logrotate'}
        pm2('kill')
        pm2('resurrect')
        assert {row['name'] for row in processes()} == names
        assert processes(other) == []
        receipt = {'real_pm2_version': '7.0.1', 'installed_logrotate_version': '3.0.0',
                   'isolated_daemons': 2, 'distinct_rpc_sockets': True, 'real_start_save_resurrect': True,
                   'compressed_rotation_and_retention': True, 'exit_103_no_restart': True,
                   'both_npm_graphs_audit_zero': True, 'reinstall_preserves_dependency_pins': True,
                   'real_log_manager': True, 'discord_and_provider_consumers': 'synthetic fixture processes'}
    finally:
        for custom in reversed(active):
            # Addresses were verified before launch; this controls only our own daemons.
            pm2('kill', custom=custom)
        assert not (root / '.pm2/pm2.pid').exists()
        assert not (root / 'second-daemon/pm2.pid').exists()
    receipt['scoped_cleanup_verified'] = True
    destination = os.environ.get('BOTBRIDGE_TEST_PM2_RECEIPT')
    if destination:
        Path(destination).write_text(json.dumps(receipt, indent=2) + '\n')
