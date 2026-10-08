"""Independent local health monitor, supervised separately from Discord consumers."""
import json
import os
import shutil
import time
from pathlib import Path

from botbridge_logging import append_line
from bridge_runtime import load_config
from bridge_windows import protect_process

ROOT = Path(__file__).resolve().parent


def inspect(root=ROOT):
    root = Path(root)
    config = load_config(root)
    failures = []
    bots = []
    for identity in config['enabled_bots']:
        try:
            data = json.loads((root / 'runtime_state' / f'health_{identity}.json').read_text())
            stale = time.time() - data['timestamp'] > 40
            if stale or not data['ready']:
                failures.append(f'bot {identity} disconnected or heartbeat stale')
            bots.append({'bot_id': identity, 'ready': data['ready'], 'stale': stale,
                         'last_success': data.get('last_success'), 'last_error': data.get('last_error'),
                         'queued': data.get('queued'), 'active_message_id': data.get('active_message_id')})
            if data.get('last_error'):
                failures.append(f'bot {identity} last request failed: {data["last_error"]}')
        except (OSError, ValueError, KeyError):
            failures.append(f'bot {identity} health unavailable')
    try:
        path = root / 'log_management_state.json'
        data = json.loads(path.read_text())
        if (time.time() - path.stat().st_mtime > 20 or data['errors']
                or data.get('status') != 'ok' or not data.get('inventory_complete', True)):
            failures.append('log manager unhealthy/stale')
    except (OSError, ValueError, KeyError):
        failures.append('log manager health unavailable')
    try:
        module = Path(os.environ.get('PM2_HOME', ROOT / '.pm2')) / 'modules/pm2-logrotate/node_modules/pm2-logrotate/app.js'
        source = module.read_text(encoding='utf-8')
        if "str === true || str === 'true'" not in source or "str === false || str === 'false'" not in source:
            failures.append('logrotate Boolean fix missing; verify module after reinstall')
    except OSError:
        failures.append('logrotate module unavailable')
    drives = {}
    roots = {root.resolve().anchor, Path(os.environ.get('PM2_HOME', root / '.pm2')).resolve().anchor}
    for drive in sorted(roots):
        free = shutil.disk_usage(drive).free
        drives[drive] = free
        if free < 2_000_000_000:
            failures.append(f'{drive} free space below 2 GB')
    return {'timestamp': time.time(), 'status': 'degraded' if failures else 'ok',
            'failures': failures, 'bots': bots, 'disk_free_bytes': drives}


def main():
    protect_process(ROOT / 'health_monitor.lock')
    (ROOT / 'runtime_state').mkdir(exist_ok=True)
    previous = None
    while True:
        try:
            report = inspect()
        except Exception as exc:
            report = {'timestamp': time.time(), 'status': 'degraded', 'failures': [type(exc).__name__]}
        path = ROOT / 'runtime_state' / 'setup_health.json'
        tmp = path.with_suffix('.tmp')
        tmp.write_text(json.dumps(report, indent=2), encoding='utf-8')
        tmp.replace(path)
        signature = (report['status'], tuple(report['failures']))
        if signature != previous:
            line = f'Health {report["status"]}: {"; ".join(report["failures"]) or "all checks passed"}'
            print(line, flush=True)
            append_line(ROOT / 'bridge_health.log', line)
            previous = signature
        time.sleep(10)


if __name__ == '__main__':
    main()
