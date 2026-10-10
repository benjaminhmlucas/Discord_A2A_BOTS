// Provider-local preload: hide Node CLI helpers unless the operator requests consoles.
const child = require('node:child_process');
const { syncBuiltinESMExports } = require('node:module');
const { promisify } = require('node:util');
const policy = options => {
  if (options != null && (typeof options !== 'object' || Array.isArray(options)))
    throw new TypeError('Child process options must be an object');
  return { ...options, windowsHide: process.env.BOTBRIDGE_SHOW_CONSOLE !== '1' };
};
for (const name of ['spawn', 'spawnSync', 'fork']) {
  const original = child[name];
  child[name] = function (command, args, options) {
    if (args == null || Array.isArray(args)) return original.call(this, command, args ?? [], policy(options));
    return original.call(this, command, policy(args));
  };
}
for (const name of ['exec', 'execSync']) {
  const original = child[name];
  child[name] = function (command, options, callback) {
    if (typeof options === 'function' && name === 'exec') return original.call(this, command, policy(), options);
    return original.call(this, command, policy(options), callback);
  };
}
for (const name of ['execFile', 'execFileSync']) {
  const original = child[name];
  child[name] = function (file, args, options, callback) {
    if (typeof args === 'function' && name === 'execFile') return original.call(this, file, [], policy(), args);
    if (args == null || Array.isArray(args)) {
      if (typeof options === 'function' && name === 'execFile') return original.call(this, file, args ?? [], policy(), options);
      return original.call(this, file, args ?? [], policy(options), callback);
    }
    return original.call(this, file, [], policy(args), options);
  };
}
// Preserve Node's promise result shape and .child handle without bypassing this policy.
for (const name of ['exec', 'execFile']) {
  child[name][promisify.custom] = function (...args) {
    let resolve, reject;
    const promise = new Promise((success, failure) => { resolve = success; reject = failure; });
    promise.child = child[name](...args, (error, stdout, stderr) => {
      if (error) {
        error.stdout = stdout;
        error.stderr = stderr;
        reject(error);
      } else resolve({ stdout, stderr });
    });
    return promise;
  };
}
// Codex uses named ESM imports from node:child_process.
syncBuiltinESMExports();
