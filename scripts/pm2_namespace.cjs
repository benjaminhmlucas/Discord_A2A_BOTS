// Scope every PM2 copy (including module dependencies) to this PM2_HOME on Windows.
// PM2 7.0.1 otherwise replaces home-relative sockets with fixed global named pipes.
const Module = require('node:module');
const path = require('node:path');
const crypto = require('node:crypto');
const fs = require('node:fs');
function validate(root) {
  const metadata = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
  if (metadata.name !== 'pm2' || metadata.version !== '7.0.1')
    throw new Error('Unsupported PM2 package; this namespace adapter requires pm2@7.0.1');
}
const load = Module._load;
Module._load = function (request, parent, isMain) {
  const value = load.apply(this, arguments);
  if (request === 'child_process' && parent && parent.filename.endsWith(path.join('pm2', 'lib', 'API', 'Modules', 'NPM.js'))) {
    validate(path.resolve(path.dirname(parent.filename), '../../..'));
    // PM2's npm.cmd shell invocation loses quoting for spaces and ampersands.
    return { ...value, spawn(command, args, options) {
      const npm = path.join(path.dirname(process.execPath), 'node_modules', 'npm', 'bin', 'npm-cli.js');
      if (args.includes('pm2-logrotate@3.0.0')) {
        if (!process.env.PM2_HOME) throw new Error('A scoped PM2_HOME is required');
        let index = args.indexOf('--prefix');
        if (index < 0) index = args.indexOf('--cwd');
        const prefix = args[index + 1];
        const expected = path.resolve(process.env.PM2_HOME, 'modules', 'pm2-logrotate');
        if (index < 0 || typeof prefix !== 'string' || path.resolve(prefix) !== expected)
          throw new Error('Refusing an unexpected logrotate installation directory');
        const policy = require('./pm2-package.json');
        fs.writeFileSync(path.join(expected, 'package.json'), JSON.stringify({
          private: true, dependencies: { 'pm2-logrotate': '3.0.0' }, overrides: policy.overrides
        }));
        return value.spawn(process.execPath,
          [npm, 'install', 'pm2-logrotate@3.0.0', '--prefix', expected, '--loglevel=error'],
          { ...options, shell: false });
      }
      if (command !== 'npm.cmd') return value.spawn(command, args, options);
      return value.spawn(process.execPath, [npm, ...args], { ...options, shell: false });
    } };
  }
  const file = Module._resolveFilename(request, parent, isMain);
  if (path.basename(file) !== 'paths.js' || path.basename(path.dirname(file)) !== 'pm2') return value;
  validate(path.dirname(file));
  if (typeof value !== 'function') throw new Error('Unsupported PM2 paths module');
  return function (...args) {
    const config = value(...args);
    if (!config || typeof config.PM2_HOME !== 'string' || !config.PM2_HOME ||
        ['DAEMON_RPC_PORT', 'DAEMON_PUB_PORT', 'INTERACTOR_RPC_PORT'].some(key => typeof config[key] !== 'string'))
      throw new Error('Unsupported PM2 socket configuration');
    const key = crypto.createHash('sha256').update(path.resolve(config.PM2_HOME).toLowerCase()).digest('hex').slice(0, 24);
    const prefix = '\\\\.\\pipe\\botbridge-' + key + '-';
    config.DAEMON_RPC_PORT = prefix + 'rpc.sock';
    config.DAEMON_PUB_PORT = prefix + 'pub.sock';
    config.INTERACTOR_RPC_PORT = prefix + 'interactor.sock';
    return config;
  };
};
