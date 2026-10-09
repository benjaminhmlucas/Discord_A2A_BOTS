// Provider-local preload: hide native helpers launched by the Node CLI wrappers.
const child = require('node:child_process');
const { syncBuiltinESMExports } = require('node:module');
for (const name of ['spawn', 'spawnSync']) {
  const original = child[name];
  child[name] = function (command, args, options) {
    if (Array.isArray(args)) return original.call(this, command, args, { ...options, windowsHide: true });
    return original.call(this, command, { ...args, windowsHide: true });
  };
}
// Codex uses named ESM imports from node:child_process.
syncBuiltinESMExports();
