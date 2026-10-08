// Task Scheduler launches this outside editor/terminal process lifetimes.
const path = require('node:path');
const root = path.resolve(__dirname, '..');
process.env.PM2_HOME = path.join(root, '.pm2');
process.env.NODE_OPTIONS = '--require=' + JSON.stringify(path.join(__dirname, 'pm2_namespace.cjs'));
process.env.PATH = path.dirname(process.execPath) + path.delimiter + process.env.PATH;
require('./pm2_namespace.cjs');
const pm2 = require(path.join(root, 'tools/pm2/node_modules/pm2'));
const apps = require(path.join(root, 'ecosystem.config.js')).apps;
const deadline = setTimeout(() => process.exit(2), 45000);
require('./pm2_recovery.cjs').main(root, pm2, apps).then(code => {
  clearTimeout(deadline);
  process.exit(code);
}).catch(() => process.exit(1));
