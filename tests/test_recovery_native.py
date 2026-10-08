"""Focused real daemon-loss recovery through Windows Task Scheduler."""
import json
import os
import shutil
import subprocess
import sys
import time
import uuid
from pathlib import Path

import pytest
import test_native_setup as native

pytestmark = pytest.mark.skipif(sys.platform != 'win32', reason='Real Windows recovery task')


def test_actual_scheduled_recovery_and_preserved_stop(tmp_path):
    root = tmp_path / 'scheduled recovery & isolated'
    root.mkdir()
    scripts = root / 'scripts'
    scripts.mkdir()
    for name in ('pm2_namespace.cjs', 'pm2-package.json', 'pm2_recovery.cjs', 'recover_pm2.cjs', 'install_recovery.ps1'):
        shutil.copyfile(native.ROOT / 'scripts' / name, scripts / name)
    prefix = root / 'tools/pm2'
    env = native.child_env()
    env.update(PM2_HOME=str(root / '.pm2'), NODE_OPTIONS='--require=' + json.dumps(str(scripts / 'pm2_namespace.cjs')))
    env['PATH'] = str(Path(native.NODE).parent) + os.pathsep + env.get('PATH', '')

    def command(args):
        with open(root / 'command.log', 'w+', encoding='utf8') as output:
            result = subprocess.run([str(v) for v in args], cwd=root, env=env, stdout=output,
                                    stderr=subprocess.STDOUT, timeout=120)
            output.seek(0)
            diagnostics = root / 'control-diagnostics.log'
            assert result.returncode == 0, output.read() + (diagnostics.read_text() if diagnostics.exists() else '')
            output.seek(0)
            return output.read()

    cached = os.environ.get('BOTBRIDGE_TEST_PM2_PREFIX')
    if cached:
        shutil.copytree(cached, prefix)
    else:
        prefix.mkdir(parents=True)
        shutil.copyfile(native.ROOT / 'scripts/pm2-package.json', prefix / 'package.json')
        shutil.copyfile(native.ROOT / 'scripts/pm2-package-lock.json', prefix / 'package-lock.json')
        command([native.NODE, Path(native.NODE).parent / 'node_modules/npm/bin/npm-cli.js', 'ci', '--prefix', prefix])
    (root / 'worker.py').write_text('import time\nwhile True: time.sleep(1)\n')
    pythonw = Path(sys.executable).with_name('pythonw.exe')
    assert pythonw.is_file()
    apps = [{'name': 'synthetic-recovery', 'script': str(pythonw), 'cwd': str(root),
             'args': 'worker.py', 'interpreter': 'none', 'windowsHide': True,
             'env': {'PM2_HOME': str(root / '.pm2')}}]
    (root / 'ecosystem.config.js').write_text('module.exports=' + json.dumps({'apps': apps}) + ';')
    # Direct API callbacks and explicit exit avoid unrelated CLI shutdown handles.
    (root / 'control.cjs').write_text(r"""
require('./scripts/pm2_namespace.cjs');
const pm2=require('./tools/pm2/node_modules/pm2');
const action=process.argv[2];
const trace=stage=>require('node:fs').appendFileSync('control-diagnostics.log',new Date().toISOString()+' '+stage+' '+action+'\n');
trace('connecting');
const timer=setTimeout(()=>{trace('timed out');process.exit(2);},30000);
pm2.connect(error=>{
 trace('connected');
 if(error)process.exit(1);
 const done=(error,value)=>{trace('finished');clearTimeout(timer);pm2.disconnect();if(error)process.exit(1);console.log(JSON.stringify(value));process.exit(0);};
 if(action==='start')pm2.start('./ecosystem.config.js',done);
 else if(action==='stop')pm2.stop('synthetic-recovery',done);
 else if(action==='save')pm2.dump(done);
 else if(action==='list')pm2.list(done);
 else pm2.killDaemon(done);
});
""")
    task_name = 'BotBridge-Recovery-Test-' + uuid.uuid4().hex
    registered = False
    try:
        command([native.NODE, root / 'control.cjs', 'start'])
        command([native.NODE, root / 'control.cjs', 'stop'])
        command([native.NODE, scripts / 'recover_pm2.cjs'])
        report = json.loads((root / '.pm2/recovery_state.json').read_text())
        assert report['status'] == 'degraded' and report['recovered'] is False
        assert report['services'][0]['pid'] == 0
        command([native.NODE, root / 'control.cjs', 'start'])
        command([native.NODE, root / 'control.cjs', 'save'])
        command([native.NODE, root / 'control.cjs', 'kill'])
        assert not (root / '.pm2/pm2.pid').exists()
        command([native.POWERSHELL, '-NoProfile', '-File', scripts / 'install_recovery.ps1',
                 '-NodePath', native.NODE, '-TaskName', task_name])
        registered = True
        command([native.POWERSHELL, '-NoProfile', '-Command', f'Start-ScheduledTask -TaskName {task_name}'])
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            report = json.loads((root / '.pm2/recovery_state.json').read_text())
            if report.get('recovered'):
                break
            time.sleep(.5)
        assert report['status'] == 'ok' and report['recovered'] and not report['daemon_was_alive']
        time.sleep(2)
        state = command([native.POWERSHELL, '-NoProfile', '-Command',
                         f'Get-ScheduledTask -TaskName {task_name} | Select-Object -ExpandProperty State'])
        assert state.strip() == 'Ready'
        rows = json.loads(command([native.NODE, root / 'control.cjs', 'list']))
        assert len(rows) == 1 and rows[0]['pid'] and rows[0]['pm2_env']['status'] == 'online'
        receipt = {'actual_scheduled_dead_daemon_recovery': True, 'preserves_deliberate_stop': True,
                   'daemon_survives_task_completion': True}
    finally:
        if registered:
            command([native.POWERSHELL, '-NoProfile', '-Command',
                     f'Stop-ScheduledTask -TaskName {task_name}; Unregister-ScheduledTask -TaskName {task_name} -Confirm:$false'])
        command([native.NODE, root / 'control.cjs', 'kill'])
        assert not (root / '.pm2/pm2.pid').exists()
    receipt['scoped_cleanup_verified'] = True
    destination = os.environ.get('BOTBRIDGE_TEST_RECOVERY_RECEIPT')
    if destination:
        Path(destination).write_text(json.dumps(receipt, indent=2))
