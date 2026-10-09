const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
require('../scripts/pm2_namespace.cjs');

test('managed PM2 client opts into metadata RPC without changing normal monitoring or other calls', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'metadata-client-'));
  const prior = process.env.BOTBRIDGE_PM2_METADATA_ONLY;
  try {
    for (const directory of ['pm2/lib', 'unrelated/lib', 'pm2/Other']) {
      fs.mkdirSync(path.join(root, directory), {recursive:true});
      fs.writeFileSync(path.resolve(root, directory, '../package.json'), JSON.stringify({name:'pm2',version:'7.0.1'}));
      const entry = path.join(root, directory, 'Client.js');
      fs.writeFileSync(entry, 'module.exports = class Client { executeRemote(method, env, cb) { cb(null, {method, env, owner:this}); } };');
      const Client = require(entry);
      const method = Client.prototype.executeRemote;
      assert.equal(require(entry).prototype.executeRemote, method); // Cached load never wraps again.
      const client = new Client();
      for (const flag of ['0', '1']) for (const rpc of ['getMonitorData', 'restartProcessId']) {
        process.env.BOTBRIDGE_PM2_METADATA_ONLY = flag;
        const env = {id:42};
        client.executeRemote(rpc, env, (error, value) => {
          assert.equal(error, null);
          assert.equal(value.owner, client);
          assert.deepEqual(value.env, directory === 'pm2/lib' && flag === '1' && rpc === 'getMonitorData'
            ? {id:42, botbridge_metadata_only:true} : env);
          assert.deepEqual(env, {id:42});
        });
      }
    }
  } finally {
    if (prior === undefined) delete process.env.BOTBRIDGE_PM2_METADATA_ONLY;
    else process.env.BOTBRIDGE_PM2_METADATA_ONLY = prior;
    fs.rmSync(root, {recursive:true,force:true});
  }
});

test('recovery metadata RPC skips WMI while normal metrics and unrelated modules are preserved', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'metadata-rpc-'));
  try {
    for (const directory of ['pm2/lib/God', 'unrelated/lib/God', 'pm2/lib/Other']) {
      fs.mkdirSync(path.join(root, directory), {recursive: true});
      const packageRoot = path.resolve(root, directory, '../..');
      fs.writeFileSync(path.join(packageRoot, 'package.json'), JSON.stringify({name: 'pm2', version: '7.0.1'}));
      const entry = path.join(root, directory, 'ActionMethods.js');
      fs.writeFileSync(entry, 'module.exports = God => {God.getMonitorData = (env, cb) => {God.metricCalls++; cb(null, "metrics");};};');
      const rows = [{name: 'synthetic', pid: 42, pm2_env: {status: 'online'}}];
      const God = {metricCalls: 0, getFormatedProcesses: () => rows};
      require(entry)(God);
      God.getMonitorData({botbridge_metadata_only: true}, (error, value) => {
        assert.equal(error, null);
        assert.equal(value, directory === 'pm2/lib/God' ? rows : 'metrics');
      });
      const expected = directory === 'pm2/lib/God' ? 0 : 1;
      assert.equal(God.metricCalls, expected);
      for (const env of [{}, null, {botbridge_metadata_only: 'true'}])
        God.getMonitorData(env, (error, value) => {assert.equal(error, null); assert.equal(value, 'metrics');});
      assert.equal(God.metricCalls, expected + 3);
    }
  } finally {fs.rmSync(root, {recursive: true, force: true});}
});

test('PM2 paths are distinct per home, including nested PM2 module copies', () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'namespace-check-'));
  try {
    const modules = ['pm2', 'nested/node_modules/pm2', 'unrelated'];
    for (const name of modules) {
      const directory = path.join(root, name);
      fs.mkdirSync(directory, { recursive: true });
      fs.writeFileSync(path.join(directory, 'package.json'), JSON.stringify({name:'pm2',version:'7.0.1'}));
      fs.writeFileSync(path.join(directory, 'paths.js'), 'module.exports = home => ({PM2_HOME:home,DAEMON_RPC_PORT:"global",DAEMON_PUB_PORT:"global",INTERACTOR_RPC_PORT:"global"});');
    }
    const first = require(path.join(root, 'pm2/paths.js'))(root);
    const same = require(path.join(root, 'nested/node_modules/pm2/paths.js'))(root);
    const other = require(path.join(root, 'pm2/paths.js'))(path.join(root, 'other'));
    assert.deepEqual(first, same);
    assert.notEqual(first.DAEMON_RPC_PORT, other.DAEMON_RPC_PORT);
    assert.match(first.DAEMON_RPC_PORT, /^\\\\\.\\pipe\\botbridge-[a-f0-9]{24}-rpc\.sock$/);
    assert.notEqual(first.DAEMON_RPC_PORT, first.DAEMON_PUB_PORT);
    assert.notEqual(first.DAEMON_PUB_PORT, first.INTERACTOR_RPC_PORT);
    assert.equal(require(path.join(root, 'unrelated/paths.js'))(root).DAEMON_RPC_PORT, 'global');
    assert.equal(require('node:fs'), fs);
  } finally {
    assert.equal(path.dirname(root), path.resolve(os.tmpdir()));
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test('only PM2 module npm installation bypasses the shell', () => {
  const Module = require('node:module');
  const child = require('child_process');
  const original = child.spawn;
  const calls = [];
  const root = fs.mkdtempSync(path.join(os.tmpdir(),'npm-adapter-'));
  const packageRoot = path.join(root,'pm2');
  fs.mkdirSync(packageRoot);
  fs.writeFileSync(path.join(packageRoot,'package.json'),JSON.stringify({name:'pm2',version:'7.0.1'}));
  child.spawn = (...args) => { calls.push(args); return 'synthetic-spawn'; };
  try {
    const parent = { filename: path.join(packageRoot, 'lib/API/Modules/NPM.js') };
    const scoped = Module._load('child_process', parent, false);
    assert.equal(scoped.spawn('npm.cmd', ['install', '--prefix', 'synthetic space & path'], { shell: true }), 'synthetic-spawn');
    assert.equal(calls[0][0], process.execPath);
    assert.equal(path.basename(calls[0][1][0]), 'npm-cli.js');
    assert.equal(calls[0][1].at(-1), 'synthetic space & path');
    assert.equal(calls[0][2].shell, false);
    scoped.spawn('bun', ['install'], { shell: false });
    assert.equal(calls[1][0], 'bun');
    assert.equal(Module._load('child_process', null, false), child);
    const savedHome = process.env.PM2_HOME;
    process.env.PM2_HOME = root;
    const destination = path.join(root, 'modules', 'pm2-logrotate');
    fs.mkdirSync(destination, {recursive:true});
    try {
      for (const args of [ ['install','pm2-logrotate@3.0.0'],
        ['install','pm2-logrotate@3.0.0','--prefix'],
        ['install','pm2-logrotate@3.0.0','--prefix',root] ])
        assert.throws(()=>scoped.spawn('npm.cmd',args,{}), /unexpected logrotate/);
      for (const flag of ['--prefix','--cwd']) {
        scoped.spawn(flag === '--cwd' ? 'bun' : 'npm.cmd',
          ['install','pm2-logrotate@3.0.0',flag,destination],{shell:true});
        const policy=JSON.parse(fs.readFileSync(path.join(destination,'package.json')));
        assert.equal(policy.dependencies['pm2-logrotate'],'3.0.0');
        assert.equal(policy.overrides.pm2,'7.0.1');
        assert.deepEqual(JSON.parse(fs.readFileSync(path.join(destination,'package-lock.json'))), require('../dependencies/logrotate/package-lock.json'));
        assert.equal(calls.at(-1)[1][1],'ci');
        assert.ok(calls.at(-1)[1].includes('--ignore-scripts'));
        assert.equal(calls.at(-1)[0],process.execPath);
        assert.equal(calls.at(-1)[2].shell,false);
      }
      delete process.env.PM2_HOME;
      assert.throws(()=>scoped.spawn('npm.cmd',['install','pm2-logrotate@3.0.0'],{}),/scoped PM2_HOME/);
    } finally {
      if (savedHome === undefined) delete process.env.PM2_HOME;
      else process.env.PM2_HOME=savedHome;
    }
  } finally {
    child.spawn = original;
    assert.equal(path.dirname(root),path.resolve(os.tmpdir()));
    fs.rmSync(root,{recursive:true,force:true});
  }
});

test('incompatible PM2 packages and paths fail before using any sockets', () => {
  const root=fs.mkdtempSync(path.join(os.tmpdir(),'namespace-contract-'));
  const packageRoot=path.join(root,'pm2');
  fs.mkdirSync(packageRoot);
  const metadata=path.join(packageRoot,'package.json');
  const entry=path.join(packageRoot,'paths.js');
  function set(value,source='module.exports = () => null;') {
    fs.writeFileSync(metadata,JSON.stringify(value));
    fs.writeFileSync(entry,source);
    delete require.cache[entry];
  }
  try {
    for(const value of [{name:'other',version:'7.0.1'},{name:'pm2',version:'99.0.0'}]) {
      set(value);
      assert.throws(()=>require(entry),/Unsupported PM2 package/);
    }
    const valid={name:'pm2',version:'7.0.1'};
    set(valid,'module.exports = {};');
    assert.throws(()=>require(entry),/Unsupported PM2 paths module/);
    for(const value of [null,{PM2_HOME:7},{PM2_HOME:''},{PM2_HOME:root},
      {PM2_HOME:root,DAEMON_RPC_PORT:'r',DAEMON_PUB_PORT:'p'}]) {
      set(valid,'module.exports = () => ('+JSON.stringify(value)+');');
      assert.throws(()=>require(entry)(),/Unsupported PM2 socket configuration/);
    }
  } finally {
    assert.equal(path.dirname(root),path.resolve(os.tmpdir()));
    fs.rmSync(root,{recursive:true,force:true});
  }
});
