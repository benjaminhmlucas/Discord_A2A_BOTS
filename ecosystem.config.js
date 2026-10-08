// PM2 reads ignored local settings only after initialize.py has run.
const path = require('path');
const root = __dirname;
const python = path.join(root, '.venv', 'Scripts', 'pythonw.exe');
const defaults = {
  cwd: root, script: python, interpreter: 'none', autorestart: true, windowsHide: true, watch: false,
  restart_delay: 5000, max_restarts: 10, min_uptime: '30s',
  stop_exit_codes: [75, 78, 103],
  env: { PYTHONUNBUFFERED: '1', PM2_HOME: path.join(root, '.pm2') }
};
module.exports = { apps: [
  { ...defaults, name: 'codexbot', args: 'codexbot.py' },
  { ...defaults, name: 'antigravitybot', args: 'AntigravityBot/antigravitybot.py' },
  { ...defaults, name: 'claudebot', args: 'claudebot.py' },
  { ...defaults, name: 'botbridge-log-manager', args: 'log_manager.py --config log_management.config.json',
    stop_exit_codes: [2, 103], max_memory_restart: '128M' },
  { ...defaults, name: 'botbridge-health', args: 'bridge_health.py', max_memory_restart: '128M' }
] };
