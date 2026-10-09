# BotBridge

A Windows Discord bridge for Codex, Gemini and Claude Code, with bounded discussions, authenticated handoffs, private owner work responses, PM2 supervision, health monitoring and log retention.

This repository template contains source code and fictional configuration examples. It contains no operational credentials, real Discord IDs, personal usernames, machine-specific paths, conversations, shared memory, process dumps or historical backups. Examples are intentionally unconfigured: IDs are zero and credentials are blank. Tests use small, synthetic IDs.

## Beta status and license

This project is released under the [MIT license](LICENSE), which permits free use, modification and redistribution. Model-provider access depends on your accounts and may require subscriptions or API charges.

This is a Windows deployment beta. PM2 CLI startup, stop and shutdown commands can stall in some Windows process-supervision environments. Management commands have bounded waits, and the independent scheduled recovery path has actual daemon-loss tests. Check command exit codes and fresh health timestamps. Use the documented maintenance flag before intentionally stopping the daemon. The log budget is periodic retention, not a hard filesystem quota. Review [security boundaries](SECURITY.md) before deployment.

CI uses explicit Ubuntu 24.04 and Windows Server 2022 images to keep its operating-system targets stable. The initial Windows Server 2025 hosted runs failed real PM2 startup/stop checks and an npm installation deadline; compatibility with that image remains unresolved. Passing the pinned matrix does not establish support for every Windows version.

## Repository structure

```text
.github/workflows/ci.yml      Offline regression checks on Linux and Windows
.env.example                 Credential variable names, with blank values
.gitignore                   Excludes local configuration and private runtime data
bridge_config.example.json   Unconfigured identities and conservative chat settings
local_settings.example.json Relative CLI and privacy-directory paths
public_context.example.md   Fictional, explicitly public context
initialize.py                Creates ignored local settings from your own IDs
ecosystem.config.js          Windows PM2 process definitions
codexbot.py / claudebot.py    Identity launchers
AntigravityBot/              Gemini-backed identity launcher
bridge_*.py                  Routing, providers, privacy, state and health checks
botbridge_*.py               Shared identity configuration and bounded logging
log_manager.py              Combined log retention manager
preflight.py                 Local readiness check, without Discord posts
scripts/                     Setup, startup and publication checks
tests/fixtures/              Fictional context and synthetic identities
tests/                       Offline routing, privacy and setup tests
docs/                        Architecture, configuration and publication notes
SECURITY.md                  Threat boundaries and vulnerability reporting
CONTRIBUTING.md              Development and review instructions
requirements.txt             Tested Python dependency versions
requirements-dev.txt         Pinned test and coverage tools
```

## Setup on your own Windows machine

Use a new checkout, separate from any existing live installation. Python 3.11, Node.js and npm must be installed. Bots require their own Discord application identities and tokens. In the Discord Developer Portal, enable Message Content Intent for each bot, invite it to your server, and grant View Channel, Send Messages and Read Message History in the intended channel. Avoid giving bots Administrator permission.

1. Run `scripts/setup.ps1` to create a Python venv and install requirements. It does not start bots.
2. Create local settings using your own IDs. The following prompts deliberately contain no example user values:

```powershell
$ownerId = Read-Host 'Your Discord user ID'
$channelId = Read-Host 'Your bridge channel ID'
$codexId = Read-Host 'Your CodexBot application/user ID'
$antigravityId = Read-Host 'Your AntigravityBot application/user ID'
$claudeId = Read-Host 'Your ClaudeBot application/user ID'
& .\.venv\Scripts\python.exe initialize.py --owner-id $ownerId --channel-id $channelId --codex-id $codexId --antigravity-id $antigravityId --claude-id $claudeId
```

3. Supply the credential variables listed in `.env.example` through the process environment or Windows User environment. The application does not automatically read `.env` files. Never put values into source files, GitHub issues or Actions workflow YAML. Public repository tests need no credentials.
4. Install the tested provider CLIs into ignored project-local directories and authenticate with your own accounts:

```powershell
npm install --prefix tools/codex-cli @openai/codex@0.159.3
npm install --prefix tools/claude-cli @anthropic-ai/claude-code@2.1.112
node tools/codex-cli/node_modules/@openai/codex/bin/codex.js login
node tools/claude-cli/node_modules/@anthropic-ai/claude-code/cli.js auth login
```

ClaudeBot uses `CLAUDE_CODE_OAUTH_TOKEN`; a CLI login alone does not populate that variable. Obtain a subscription token through Claude Code's `setup-token` command and supply it privately. Gemini uses `GEMINI_API_KEY`. Provider availability, account limits and model access depend on your accounts. Set your Codex model and reasoning effort in the ignored local configuration if needed.

5. Edit ignored `public_context.md` with only information you want sent to the providers and potentially repeated in the channel. Review `local_settings.json`, including CLI paths and the local privacy-marker directory. Only the configured owner can request replies initially; add trusted numeric user IDs explicitly to `allowed_user_ids` if desired.
6. Install checkout-local PM2 from the shipped manifest and integrity lock:

```powershell
New-Item -ItemType Directory -Force tools/pm2 | Out-Null
Copy-Item dependencies/pm2/package.json tools/pm2/package.json
Copy-Item dependencies/pm2/package-lock.json tools/pm2/package-lock.json
npm ci --prefix tools/pm2
npm audit --prefix tools/pm2
```

Run `scripts/start.ps1`. Startup invokes Node directly with the configured local PM2 entry, uses a dedicated `.pm2` directory inside this checkout, installs log rotation with the same dependency overrides, verifies its Boolean parser fix, and starts the configured processes. It does not register a login startup task or save the process list automatically. The pinned Chokidar 4 watcher supports literal paths; glob-based PM2 watch configuration is unsupported. Bot services use `watch: false`.

7. Inspect `.pm2/logs/` and `runtime_state/setup_health.json`. After all enabled identities are connected and healthy, save the list in the same PowerShell session:

```powershell
& .\scripts\pm2.ps1 list
& .\scripts\pm2.ps1 save
```

Use `scripts/pm2.ps1` for every PM2 command in this installation. It sets both the checkout's `PM2_HOME` and its scoped Node preloader. PM2 7.0.1 otherwise uses fixed Windows named pipes despite different home folders; bare PM2 commands could reach another daemon. The preloader also preserves installer paths containing spaces and shell metacharacters. It applies to nested PM2 copies used by logrotate. Do not persist its `NODE_OPTIONS` value in the global user environment.

The preloader rejects other PM2 versions and installs logrotate from its committed integrity lock using npm ci with lifecycle scripts disabled. This also pins logrotate's transitive PM2 dependency, which otherwise requests `latest`. Review and retest the namespace adapter before updating PM2. Recheck both dependency trees after installation with `npm audit --prefix tools/pm2` and `npm audit --prefix .pm2/modules/pm2-logrotate`. Audits identify known advisories and do not establish absence of vulnerabilities.

PM2 7.0.1 can display `waiting restart` for a configured stop exit code when a restart delay is present. Verify PID zero and an unchanged restart count rather than treating that label alone as a restart loop. The real lifecycle test checks exit 103 across the restart delay.

The ecosystem contains all three launchers; a disabled identity exits with code 75 and is excluded from discussions and health checks. To change participation, edit `enabled_bots` to a subset of your configured numeric bot IDs and restart the affected processes. Keep all three identity mappings configured.

Supervised Windows services use the venv's `pythonw.exe` to run without console windows. PM2 still captures stdout and stderr in its log files. Use `python.exe` for setup, diagnostics, and tests that need console output; do not replace all Python invocations with `pythonw.exe`.

8. Register independent Windows recovery after saving and verifying the roster:

```powershell
& .\scripts\install_recovery.ps1 -NodePath (Get-Command node).Source
```

Use the tested Node runtime. The hidden `BotBridge-Recovery` task runs at login and every two minutes while your account is logged in. It restores a dead daemon or missing saved services using this checkout's scoped PM2, and preserves deliberately stopped processes and fatal stop codes. It runs outside your editor and terminal process lifetimes. Its state is `.pm2/recovery_state.json`; its own journal rotates around 64 KB with one backup. Inspect the report timestamp: an old `status: ok` file does not establish current health.

For maintenance, create `.pm2/recovery.disabled` before stopping/deleting services or killing PM2. Update the ecosystem and saved roster together before removing that file. The supervisor rejects mismatched saved paths/rosters. A stopped process already in PM2 is not restarted by recovery. Multiple installations must use distinct `-TaskName` values. To remove the task, use `Unregister-ScheduledTask -TaskName BotBridge-Recovery -Confirm:$false`. Recovery is not available while logged out or while the machine is off.

## Verify messaging

In your configured channel, mention one enabled bot and send:

```text
/discuss 6 Test reliable messaging. Each reply must name the bot in one short sentence. On the final turn, include TEST COMPLETE.
```

With the default three-bot order, each bot should reply twice, then the bridge reports completion. A missing participant stops the discussion with a notice.

Discussion replies include a validated control decision. A participant can stop immediately when the user's stop condition is met, or report consensus when all participants have explicitly agreed. The bridge closes the discussion and issues no next-bot mention or token. Missing or malformed decisions also stop the chain. The requested count is an upper bound, capped at 15 turns.

Public chat providers cannot browse GitHub or retrieve links. Supply the relevant code or diff in the conversation for review; a repository URL alone is not a pull request or an inspected source. Saying "stop if you cannot access it" now ends the discussion after that explanation.

## Development checks

```powershell
& .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt
& .\.venv\Scripts\python.exe scripts/check_release.py
& .\.venv\Scripts\python.exe -m coverage run -m pytest tests -q
& .\.venv\Scripts\python.exe -m coverage json
& .\.venv\Scripts\python.exe -m coverage report
& .\.venv\Scripts\python.exe scripts/check_coverage.py coverage.json
node --test --experimental-test-coverage --test-coverage-lines=100 --test-coverage-branches=100 --test-coverage-functions=100 --test-coverage-include=ecosystem.config.js --test-coverage-include=scripts/pm2_namespace.cjs --test-coverage-include=scripts/pm2_recovery.cjs --test-coverage-include=scripts/recover_pm2.cjs tests/test_ecosystem.cjs tests/test_pm2_namespace.cjs tests/test_pm2_recovery.cjs
```

Both unit tests and setup integration tests are required. Coverage must be exactly 100% of statements and branch outcomes in every shipped Python module, with no coverage exclusions. JavaScript production configuration must also pass 100% line, branch and function coverage. See [testing procedures](docs/TESTING.md) for the native Windows installation, PowerShell, process-protection and 1 GB log-budget checks.

Default tests use fake Discord destinations and AI consumers, alongside real Windows PM2 daemons, npm/module installation, log rotation and process supervision. They do not contact Discord or consume AI credits. Windows native tests require PowerShell 7, Node 24.15.0, npm and the Python 3.11 launcher; they install dependencies into a temporary checkout. Explicit private opt-in tests additionally verify real authenticated providers. The GitHub Actions workflow runs the default checks on pushes and pull requests. Check the Actions results for the exact commit before deploying it.

## CI and merge policy

Enable a main-branch ruleset requiring an independently approved pull request,
fresh approval after code changes, resolved review conversations and all required
checks on an up-to-date branch. Block force pushes and deletion with no bypass
list. Verify these repository settings; workflow files alone do not enforce them. CI pins action
commits and runs formatting/lint, strict boundary type checks, Bandit, Python/npm
audits, CodeQL, both supported OS suites and exact coverage gates. Dependabot proposes
weekly dependency/action updates. See [the security review policy](docs/security-review.md)
and [contribution checks](CONTRIBUTING.md).

Persistent request limits default to six human requests per minute across bots,
30 provider calls per bot per minute and 200 per bot per rolling day. Configure
`user_requests_per_minute`, `bot_requests_per_minute`, and `bot_requests_per_day`
in ignored local configuration, then restart. These are request counts, not billing
caps. Work prompts contain only the authenticated owner's explicit text.

## Publication

Upload the files in this clean template, not a running installation. Follow [the publication notes](docs/PUBLISHING.md) before the first push. The release checker checks the current file tree and common credential patterns; it does not scan Git history or prove the absence of every secret. Preserve the MIT copyright and license notice when redistributing the project.

Local `/work` is disabled by default. The security boundaries and remaining limitations are described in [SECURITY.md](SECURITY.md).
