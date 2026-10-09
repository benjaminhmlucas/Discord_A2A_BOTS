const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const vm = require('node:vm');
const recovery = require('../scripts/pm2_recovery.cjs');

function fixture() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'recovery-contract-'));
  fs.mkdirSync(path.join(root, '.pm2'));
  const apps = [{name: 'synthetic', script: path.join(root, 'pythonw.exe'), cwd: root,
    args: 'worker.py --safe', interpreter: 'none'}];
  const dump = [{name: 'synthetic', pm_exec_path: apps[0].script, pm_cwd: root,
    PM2_HOME: path.join(root, '.pm2'), windowsHide: true, args: ['worker.py', '--safe'], exec_interpreter: 'none'}];
  const save = () => fs.writeFileSync(path.join(root, '.pm2/dump.pm2'), JSON.stringify(dump));
  save();
  let rows = [{name: 'synthetic', pid: 42, pm2_env: {status: 'online'}}];
  const counts = {restore: 0, disconnect: 0, connect: 0};
  const pm2 = {Client: {pingDaemon: cb => cb(true), executeRemote: (method, options, cb) => {
    assert.equal(method, 'getMonitorData'); assert.deepEqual(options, {botbridge_metadata_only: true}); pm2.list(cb);
  }},
    connect: cb => {counts.connect++; cb(null);},
    list: cb => cb(null, rows),
    resurrect: cb => {counts.restore++; rows = [{name: 'synthetic', pid: 43, pm2_env: {status: 'online'}}]; cb(null);},
    disconnect: () => counts.disconnect++};
  return {root, apps, dump, save, pm2, counts, setRows: value => {rows = value;},
    cleanup: () => fs.rmSync(root, {recursive: true, force: true})};
}

test('bounded callback success, error, timeout and synchronous exception', async () => {
  assert.equal(await recovery.call(cb => cb(null, 7)), 7);
  await assert.rejects(recovery.call(cb => cb(new Error('failure'))), /failure/);
  await assert.rejects(recovery.call(() => {}, 5), /timed out/);
  await assert.rejects(recovery.call(() => {throw new Error('sync');}, 5), /sync/);
});

test('pause, live no-op, dead-daemon restore, missing-service restore and fatal-stop preservation', async () => {
  const f = fixture();
  try {
    fs.writeFileSync(path.join(f.root, '.pm2/recovery.disabled'), 'maintenance');
    assert.equal((await recovery.recover(f.root, f.apps, f.pm2)).status, 'paused');
    assert.equal(f.counts.connect, 0);
    fs.unlinkSync(path.join(f.root, '.pm2/recovery.disabled'));
    assert.deepEqual((await recovery.recover(f.root, f.apps, f.pm2)).services,
      [{name: 'synthetic', pid: 42, status: 'online'}]);
    assert.equal(f.counts.restore, 0);
    f.pm2.Client.pingDaemon = cb => cb(false);
    f.setRows([]);
    const restored = await recovery.recover(f.root, f.apps, f.pm2);
    assert.equal(restored.status, 'ok');
    assert.equal(restored.recovered, true);
    assert.equal(restored.daemon_was_alive, false);
    f.pm2.Client.pingDaemon = cb => cb(true);
    f.setRows([]);
    assert.equal((await recovery.recover(f.root, f.apps, f.pm2)).recovered, true);
    f.setRows([{name: 'synthetic', pid: 0, pm2_env: {status: 'waiting restart'}}]);
    assert.equal((await recovery.recover(f.root, f.apps, f.pm2)).status, 'degraded');
    assert.equal(f.counts.restore, 2);
    assert.equal(f.counts.disconnect, 4);
  } finally {f.cleanup();}
});

for (const fault of ['array', 'length', 'name', 'duplicate', 'script', 'cwd', 'home', 'hide', 'args', 'interpreter']) {
  test('reject unsafe or obsolete dump: ' + fault, () => {
    const f = fixture();
    try {
      if (fault === 'array') fs.writeFileSync(path.join(f.root, '.pm2/dump.pm2'), '{}');
      else {
        if (fault === 'length') f.dump.push({...f.dump[0]});
        if (fault === 'name') f.dump[0].name = 'unexpected';
        if (fault === 'duplicate') {f.apps.push({...f.apps[0], name: 'other'}); f.dump.push({...f.dump[0]});}
        if (fault === 'script') f.dump[0].pm_exec_path += '.other';
        if (fault === 'cwd') f.dump[0].pm_cwd += '-other';
        if (fault === 'home') f.dump[0].PM2_HOME += '-other';
        if (fault === 'hide') f.dump[0].windowsHide = false;
        if (fault === 'args') f.dump[0].args = 'other.py --safe';
        if (fault === 'interpreter') f.dump[0].exec_interpreter = 'node';
        f.save();
      }
      assert.throws(() => recovery.validateDump(f.root, f.apps), /roster|paths|arguments/);
    } finally {f.cleanup();}
  });
}

test('callback/list/restore failures recorded and clients disconnected', async () => {
  const f = fixture();
  try {
    assert.equal(await recovery.main(f.root, f.pm2, f.apps), 0);
    f.pm2.list = cb => cb(new Error('list failure'));
    assert.equal(await recovery.main(f.root, f.pm2, f.apps), 1);
    assert.equal(f.counts.disconnect, 2);
    assert.equal(JSON.parse(fs.readFileSync(path.join(f.root, '.pm2/recovery_state.json'))).error, 'list failure');
    f.pm2.list = cb => cb(null, []);
    f.pm2.resurrect = cb => cb(new Error('restore failure'));
    assert.equal(await recovery.main(f.root, f.pm2, f.apps), 1);
    assert.equal(f.counts.disconnect, 3);
    fs.writeFileSync(path.join(f.root, '.pm2/recovery.log'), 'X'.repeat(65000));
    recovery.record(f.root, {status: 'ok'});
    assert.equal(fs.statSync(path.join(f.root, '.pm2/recovery.log.1')).size, 65000);
    fs.writeFileSync(path.join(f.root, '.pm2/recovery.log'), 'Y'.repeat(65001));
    recovery.record(f.root, {status: 'ok'});
    assert.equal(fs.statSync(path.join(f.root, '.pm2/recovery.log.1')).size, 65001);
    assert.ok(fs.statSync(path.join(f.root, '.pm2/recovery.log')).size < 1000);
  } finally {f.cleanup();}
});

test('journal keeps its open file identity during a concurrent pathname replacement', () => {
  const f = fixture();
  const stat = fs.fstatSync;
  const log = path.join(f.root, '.pm2/recovery.log');
  const held = log + '.held';
  fs.writeFileSync(log, 'old entry\n');
  try {
    fs.fstatSync = descriptor => {
      const result = stat(descriptor);
      fs.renameSync(log, held);
      fs.writeFileSync(log, 'SYNTHETIC-UNRELATED');
      return result;
    };
    recovery.record(f.root, {status:'ok'});
    assert.equal(fs.readFileSync(log, 'utf8'), 'SYNTHETIC-UNRELATED');
    assert.match(fs.readFileSync(held, 'utf8'), /"status":"ok"/);
  } finally {
    fs.fstatSync = stat;
    f.cleanup();
  }
});

test('state replacement retries sharing conflicts and preserves the old snapshot on exhaustion', () => {
  const f = fixture();
  const rename = fs.renameSync;
  const destination = path.join(f.root, '.pm2/recovery_state.json');
  try {
    for (const code of ['EPERM', 'EACCES', 'EBUSY']) {
      let attempts = 0;
      fs.renameSync = (...args) => {
        if (++attempts < 3) throw Object.assign(new Error('sharing conflict'), {code});
        return rename(...args);
      };
      recovery.record(f.root, {status: 'ok'});
      assert.equal(attempts, 3);
      assert.equal(JSON.parse(fs.readFileSync(destination)).status, 'ok');
    }
    for (const code of ['EPERM', 'ENOENT']) {
      let attempts = 0;
      fs.renameSync = () => { attempts++; throw Object.assign(new Error('cannot replace'), {code}); };
      assert.throws(() => recovery.record(f.root, {status:'new'}), /cannot replace/);
      assert.equal(attempts, code === 'EPERM' ? 3 : 1);
      assert.equal(JSON.parse(fs.readFileSync(destination)).status, 'ok');
    }
  } finally {
    fs.renameSync = rename;
    f.cleanup();
  }
});

test('rejects stale restart policy and validates PM2 string arguments', () => {
  const f = fixture();
  try {
    f.dump[0].args = 'worker.py --safe';
    recovery.validateDump(f.root, f.apps);
    for (const [key, value] of Object.entries({autorestart: true, watch: false,
      restart_delay: 5000, max_restarts: 10, stop_exit_codes: [75, 78, 103]})) {
      f.apps[0][key] = value;
      assert.throws(() => recovery.validateDump(f.root, f.apps), /restart policy/);
      f.dump[0][key] = value;
      f.save();
      recovery.validateDump(f.root, f.apps);
    }
  } finally {f.cleanup();}
});

test('CLI sets scoped home and loader and exits on result, rejection and hard deadline', async () => {
  const entry = path.resolve(__dirname, '../scripts/recover_pm2.cjs');
  const code = fs.readFileSync(entry, 'utf8');
  for (const failure of [false, true]) {
    const exits = [], env = {PATH: 'synthetic-path'};
    let timeout;
    const root = path.resolve(path.dirname(entry), '..');
    const context = {__dirname: path.dirname(entry),
      process: {env, execPath: 'node.exe', exit: value => exits.push(value)},
      require: name => {
        if (name === 'node:path') return path;
        if (name === './pm2_recovery.cjs') return {main: (received, pm2, apps) => {
          assert.equal(received, root); assert.equal(pm2, 'synthetic-pm2'); assert.deepEqual(apps, ['app']);
          return failure ? Promise.reject(new Error('disk failure')) : Promise.resolve(0);
        }};
        if (name.endsWith('ecosystem.config.js')) return {apps: ['app']};
        if (name.endsWith(path.join('node_modules', 'pm2'))) return 'synthetic-pm2';
        assert.equal(name, './pm2_namespace.cjs');
      },
      setTimeout: (fn, ms) => {assert.equal(ms, 45000); timeout = fn; return 17;},
      clearTimeout: id => assert.equal(id, 17)};
    new vm.Script(code, {filename: entry}).runInNewContext(context);
    await new Promise(resolve => setImmediate(resolve));
    assert.deepEqual(exits, [failure ? 1 : 0]);
    assert.equal(env.PM2_HOME, path.join(root, '.pm2'));
    assert.ok(env.NODE_OPTIONS.includes('pm2_namespace.cjs'));
    timeout();
    assert.equal(exits.at(-1), 2);
  }
});
