// External supervisor: restore missing services, never restart stopped/fatal services.
const fs = require('node:fs');
const path = require('node:path');

function call(operation, timeout = 20000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error('PM2 recovery command timed out')), timeout);
    operation((error, value) => {
      clearTimeout(timer);
      if (error) reject(error);
      else resolve(value);
    });
  });
}

function validateDump(root, apps) {
  const dump = JSON.parse(fs.readFileSync(path.join(root, '.pm2', 'dump.pm2'), 'utf8'));
  if (!Array.isArray(dump) || dump.length !== apps.length)
    throw new Error('Save the current roster before enabling recovery');
  for (const app of apps) {
    const rows = dump.filter(row => row.name === app.name);
    if (rows.length !== 1) throw new Error('Saved roster does not match ecosystem');
    const row = rows[0];
    if (path.resolve(row.pm_exec_path) !== path.resolve(app.script) ||
        path.resolve(row.pm_cwd) !== path.resolve(app.cwd) ||
        path.resolve(row.PM2_HOME) !== path.join(root, '.pm2') ||
        row.windowsHide !== true)
      throw new Error('Saved process paths or hidden-window policy do not match ecosystem');
    // PM2 serializes a string of arguments as an array. These ecosystem arguments
    // deliberately contain no shell quoting; compare tokens and preserve their order.
    const args = value => Array.isArray(value) ? value : String(value).split(/\s+/);
    if (JSON.stringify(args(row.args)) !== JSON.stringify(args(app.args)) ||
        row.exec_interpreter !== app.interpreter)
      throw new Error('Saved process arguments or interpreter do not match ecosystem');
    for (const key of ['autorestart', 'watch', 'restart_delay', 'max_restarts', 'stop_exit_codes']) {
      if (app[key] !== undefined && JSON.stringify(row[key]) !== JSON.stringify(app[key]))
        throw new Error('Saved restart policy does not match ecosystem');
    }
  }
}

async function recover(root, apps, pm2) {
  if (fs.existsSync(path.join(root, '.pm2', 'recovery.disabled')))
    return {status: 'paused', recovered: false};
  const alive = await call(done => pm2.Client.pingDaemon(value => done(null, value)));
  // Validate before connect(), which can start a new daemon as a side effect.
  if (!alive) validateDump(root, apps);
  await call(done => pm2.connect(done));
  try {
    let rows = await call(done => pm2.list(done));
    const missing = apps.some(app => !rows.some(row => row.name === app.name));
    if (missing) {
      validateDump(root, apps);
      await call(done => pm2.resurrect(done));
      rows = await call(done => pm2.list(done));
    }
    const healthy = apps.every(app => rows.some(row => row.name === app.name && row.pm2_env.status === 'online'));
    return {status: healthy ? 'ok' : 'degraded', recovered: missing,
      daemon_was_alive: alive,
      services: rows.map(row => ({name: row.name, pid: row.pid, status: row.pm2_env.status}))};
  } finally {
    pm2.disconnect();
  }
}

function record(root, report) {
  const home = path.join(root, '.pm2');
  fs.mkdirSync(home, {recursive: true});
  report.timestamp = Date.now() / 1000;
  const destination = path.join(home, 'recovery_state.json');
  const temporary = destination + '.tmp';
  fs.writeFileSync(temporary, JSON.stringify(report, null, 2));
  fs.renameSync(temporary, destination);
  // Bounded local journal, independent of the possibly dead aggregate manager.
  const log = path.join(home, 'recovery.log');
  if (fs.existsSync(log) && fs.statSync(log).size > 64000)
    fs.renameSync(log, log + '.1');
  fs.appendFileSync(log, JSON.stringify(report) + '\n');
}

async function main(root, pm2, apps) {
  let report;
  try {
    report = await recover(root, apps, pm2);
  } catch (error) {
    report = {status: 'error', recovered: false, error: error.message};
  }
  record(root, report);
  // A missing daemon can be restored; a stopped/fatal service needs operator repair.
  // Surface degradation to Task Scheduler without restarting an intentionally stopped bot.
  return ['error', 'degraded'].includes(report.status) ? 1 : 0;
}

module.exports = {call, validateDump, recover, record, main};
