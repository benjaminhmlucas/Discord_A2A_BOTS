const test = require('node:test');
const assert = require('node:assert/strict');
const path = require('node:path');
const root = path.resolve(__dirname, '..');
const config = require('../ecosystem.config.js');

test('installed logrotate and its audited lock share the pinned PM2 override policy', () => {
  const pm2 = require('../dependencies/pm2/package.json');
  const rotate = require('../dependencies/logrotate/package.json');
  const lock = require('../dependencies/logrotate/package-lock.json');
  assert.deepEqual(rotate.overrides, pm2.overrides);
  assert.deepEqual(rotate.dependencies, {'pm2-logrotate': '3.0.0'});
  assert.equal(lock.packages['node_modules/pm2'].version, '7.0.1');
});

test('ecosystem uses only this checkout and bounded restart policies', () => {
  assert.deepEqual(config.apps.map(a => a.name), [
    'codexbot', 'antigravitybot', 'claudebot', 'botbridge-log-manager', 'botbridge-health'
  ]);
  for (const app of config.apps) {
    assert.equal(app.cwd, root);
    assert.equal(app.script, path.join(root, '.venv', 'Scripts', 'pythonw.exe'));
    assert.equal(app.windowsHide, true);
    assert.equal(app.watch, false);
    assert.equal(app.env.PM2_HOME, path.join(root, '.pm2'));
    assert.equal(app.interpreter, 'none');
    assert.equal(app.restart_delay, 5000);
    assert.equal(app.max_restarts, 10);
    assert.equal(app.min_uptime, '30s');
    assert.ok(app.stop_exit_codes.includes(103));
  }
  assert.deepEqual(config.apps[3].stop_exit_codes, [2, 103]);
});
