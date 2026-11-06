# Local control window (optional)

`control_gui.py` is an optional browser dashboard for setup and day-to-day operation.
It runs only when you start it, and the bots never depend on it. Everything it does
is also available through the README's command-line path, and both paths read and
write the same ignored local files.

## Start and stop

Create the checkout venv first (the dashboard itself needs the pinned `aiohttp`):

```powershell
py -3.11 scripts/manage.py setup
& .\.venv\Scripts\python.exe control_gui.py
```

The window opens in your default browser. Use `--no-browser` to print the address
instead, and `--root <folder>` to manage another installation folder. Stop it with
Ctrl+C. Closing it disconnects every MCP session it still owns, including one whose
connect failed part way; bots, PM2 services and configured connections keep running.
After a saved configuration change, the window switches to the new configuration only
once no connection action is in progress and every connection the old one owns has
been cleaned up. If that cleanup fails, the old configuration stays in use and the next
action retries it.

## Security boundary

- The server binds to `127.0.0.1` on a random port and checks the exact `Host`
  header, which blocks DNS rebinding and other machines.
- Every API call needs a per-session secret. It is generated in memory, carried
  once in the URL fragment, removed from the address bar and kept only in page
  memory. Reloading the page ends the session; restart the window to get a new one.
- State-changing calls also require the window's own `Origin` and a JSON content
  type, so other web pages cannot drive it. Responses are `no-store`, framed by
  nobody, and limited by a strict content security policy. No browser storage is used.
- Error messages are fixed sentences. Text that could echo request data, paths or
  credentials is replaced by a generic message.
- Saved credentials are never returned. Credential screens show only set, not set,
  unavailable, and when the value was last verified.
- Logs, redaction previews and exports pass through the same redaction as the
  runtime, including known values from the process and Windows User environment.
  Log views read 64 KiB more than they show, starting at a complete line, and redact
  all of it before cutting the displayed 32 KiB, so a value crossing the cut is never
  shown in part.

## Screens

| Screen | What it does | Shared code it uses |
|---|---|---|
| Setup | First-run checklist: venv, pinned Python dependencies, Discord identities, Node, checkout-local PM2, provider CLIs, required credentials for enabled bots, and preflight. Each failing step shows its fix: a command, a screen, or an Install/Run button. | `initialize.py`, `preflight.py`, README install commands |
| Discord | Owner, channel and bot IDs, with invite links that request View Channel, Send Messages and Read Message History, never Administrator. | `validate_runtime_config` |
| Credentials | Masked entry for the five runtime credentials into this installation's OS credential store, removal, and Verify for Discord tokens and the Gemini key. Shows whether the value in use comes from the OS store or the environment fallback. | `bridge_runtime_credentials`, deployment `CredentialStore` |
| Providers | Model and reasoning effort, installed versus pinned CLI version, Install pinned CLI, Check sign-in, and the Claude `setup-token` command. | provider settings, CLI status commands |
| Connections | MCP profiles: Add, Edit, Remove, Test, Discover tools, Connect/Disconnect, Sign in/Log out for OAuth, and native credential references. The tool and web policy editor and the issue #25 notice follow. | `Registry`, `ConnectionManager`, `Authentication` |
| Memory, Access, Privacy, Limits | Memory policy, roster and allowed users (owner work requires a risk confirmation), public context, local paths and redaction preview, and queue/deadline/turn limits. | runtime, capability and memory validators |
| Services | PM2 status for the five services, Start/Stop/Restart, Start all, a troubleshooting-console choice for starts, health and heartbeat ages, recovery state, maintenance mode, recovery task check/install/remove, and recent redacted logs. | `scripts/manage.py`, `scripts/recover_pm2.cjs --status`, `bridge_health.inspect`, `scripts/install_recovery.ps1` |
| Diagnostics | Preflight, provider sign-in checks, credential verification, and an opt-in test message. | as above |
| Backup | Export and import of non-secret settings. | `ControlConfig.export` / `restore` |

### Validation

Every save goes through the runtime's own validators (`validate_runtime_config`,
`Capabilities` and memory policy) before any file changes. Saves compare the
revision of all three configuration files, so a concurrent edit by another window or
editor is refused with "Configuration changed; reload before saving". The control
window cannot enable anything the runtime would reject.

### MCP connections

Connection actions call the same shared manager and authentication API as
`mcp_connections.py` and the runtime. There is no second transport, permission engine
or secret store.

- Discovery lists tool names only, marked authorized or not authorized. Discovering,
  connecting or signing in never adds or enables a tool. Authorizations stay in the
  tool policy, with per-tool user and bot scopes, fixed arguments and read-only
  status unchanged.
- Status reports the connection outcome (`not_tested`, `connected`, `completed`,
  `disconnected`, `failed`, `exited`, `rejected`) and authentication (`none`,
  `configured`, `required`, `expired`, `unavailable`).
- Connect opens a test session owned by the control window. It does not change the
  bots' connections. For the stateless `2026-07-28` protocol, connect resolves the
  credentials without a request; `2025-11-25` sends `initialize`.
- Sign in opens your browser only when you click it. OAuth tokens go to the native
  credential store, exactly as with `mcp_connections.py signin`.

### Services

Service actions run `scripts/manage.py` with this checkout's `PM2_HOME` and scoped
preloader, the same path as `scripts/pm2.ps1`. Status comes from the recovery entry's
read-only `--status` mode: it pings the daemon first and never starts one, and it
returns names, PIDs, status, restart counts and uptime only, never PM2's stored
process environment. Without the checkout venv, every service action is refused.

The troubleshooting-console choice applies to the start command it accompanies. As
with the CLI, already running services change only when their ecosystem
configuration is next loaded; reload the normal configuration before saving the
production roster.

Maintenance mode creates or removes `.pm2/recovery.disabled`, the recovery
supervisor's documented pause file. Recovery task actions run on Windows only and
need a distinct task name per installation.

### Diagnostics without credits

Verify calls Discord's `GET /users/@me` and checks that the token belongs to the
configured bot ID, or reads Gemini model metadata. Neither generates text. Codex and
Claude sign-in checks run each CLI's own status command and report only its exit
status. The test message is a single fixed REST post to the configured channel after
an explicit confirmation; it opens no gateway connection, so it cannot duplicate a
running bot.

### Backup

Export downloads `bridge_config.json`, `local_settings.json` and `public_context.md`
as one JSON file. Credentials are never included: they stay in the OS store or the
environment, and `runtime_credentials` lists names only. Import validates the
complete export with the runtime policy and refuses known credential values, then
replaces all three files together. If a write fails, the files already replaced are
restored. Before the first replacement, the previous files are recorded in
`.botbridge-memory/control-import.json`. If the process exits part way through, the
next configuration read (the control window or a bot starting up) restores all three
previous files and removes the record. A file edited by hand since the interruption
is reported as a conflict and left as it is; resolve it, then delete the record.

## Runtime credential selection

`local_settings.json` accepts an optional `runtime_credentials` list. It is a
backwards-compatible extension: when it is absent, providers read the established
process or Windows User environment variables exactly as before. Saving a credential
in the control window adds its name, and providers then read that name only from the
installation's OS credential store, failing closed if the entry is missing. Removing
a stored credential keeps the name, so the bot does not silently fall back to an
environment value.

## Not yet included

- Pulling a new release, running migrations such as the PM2 saved-roster refresh, and
  rollback are not available in the window yet. Use Git and the README procedure.
- Memory policy and per-tool authorizations are edited as validated JSON rather than
  typed forms.
- The Windows executable-extension policy control waits for the shared backend from
  issue #25. The window shows a notice and offers no separate override.
- Interactive provider sign-in (`codex login`, `claude setup-token`) runs in a
  terminal; the window shows the exact command and stores the resulting token through
  the masked Credentials screen.
