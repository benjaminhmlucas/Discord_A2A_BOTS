// Deterministic setup adapter: records commands, never connects to Discord or starts bots.
const fs = require('node:fs');
const path = require('node:path');
const home = process.env.PM2_HOME;
const args = process.argv.slice(2);
fs.mkdirSync(home, { recursive: true });
const log = path.join(home, 'fixture_commands.json');
const records = fs.existsSync(log) ? JSON.parse(fs.readFileSync(log)) : [];
records.push(args);
fs.writeFileSync(log, JSON.stringify(records));
if (args[0] === 'install') {
  const directory = path.join(home, 'modules', 'pm2-logrotate', 'node_modules', 'pm2-logrotate');
  fs.mkdirSync(directory, { recursive: true });
  fs.writeFileSync(path.join(directory, 'package.json'), JSON.stringify({ version: '3.0.0' }));
  fs.writeFileSync(path.join(directory, 'app.js'), "const parseBool = (str, defaultVal = false) => {\n  return str.toLowerCase() === 'true';\n};\n");
}
if (process.env.BOTBRIDGE_FAKE_PM2_FAIL === args[0]) process.exit(7);
