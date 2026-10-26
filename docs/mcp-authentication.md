# MCP authentication and credential storage (issue #27)

Authentication describes **how a connection proves who it is**. It never grants a
tool, user or bot permission: aliases, allowlists, the read-only gate and private
destination guards decide what may run, exactly as in
[MCP connections](mcp-connections.md). Bots run without a GUI or browser; only the
explicit operator `signin` command can open one.

## Credential references

Profiles store references, never secret values:

```json
{"source": "native", "name": "docs-token"}
{"source": "environment", "name": "BOTBRIDGE_MCP_DOCS"}
```

- `native` names are lowercase (`[a-z][a-z0-9_.-]`, at most 64 characters) and are
  stored in the operating system's credential store.
- `environment` names must start with `BOTBRIDGE_MCP_`. They are explicit,
  read-only and externally managed (for headless deployments, containers or hosts
  without a usable store). The bridge never writes them.

Each native stored value is bound to the installation folder, the configured operator
(`owner_id`), the connection alias and the **complete** profile. Changing the
endpoint, protocol, scopes or any other profile field, or using the same reference
under another alias, finds no credential: set it (or sign in) again. A token can
therefore not follow a profile edit or another alias. Environment references are
externally managed: profiles using the same environment name intentionally read
the same value, so operators must use distinct variables for isolation. Values are at most
2560 UTF-8 bytes (the Windows credential limit, applied everywhere) and may not be
empty or contain NUL.

### Clean up before editing or removing a profile

Before changing an alias or any profile field, use the original configuration to
run `logout` for OAuth, or `credential-delete` for each native bearer/header/stdio
reference. Confirm cleanup succeeds before applying the edited/exported config.
These explicit operations remove the old native entries; OAuth logout also attempts
provider revocation. Offline profile exports do not silently delete credentials or
revoke access. Environment variables remain externally managed.

If a profile was already edited, use a retained copy of its original configuration
from the same installation folder to run those cleanup commands, then configure
the new profile. Without the original binding, revoke access at the provider and
remove only the identified old native entries using the OS credential manager.
Editing a profile alone does not remove old secrets or revoke a provider grant.

### Native stores

| OS | Store | Notes |
| --- | --- | --- |
| Windows | Credential Manager (generic credentials, current user) | Targets start `BotBridge.MCP/`. |
| macOS | Default keychain (normally the login keychain), generic passwords | User interaction is disabled; a locked keychain fails instead of prompting. Unlock it outside the bridge. |
| Linux | Secret Service `default` collection over an encrypted D-Bus session | Requires a running, unlocked Secret Service (for example GNOME Keyring or KeePassXC). Each operation runs in a helper process killed after 3 seconds, so a hung D-Bus peer cannot block the bot. Locked collections and prompts fail closed. |

Linux installs `SecretStorage`, `jeepney` and `cryptography` from
`requirements.txt` (Linux-only markers). There is **no** plaintext-file fallback:
an unavailable store reports `unavailable` and the request fails. Use environment
references explicitly if a host has no store.

Native credential helpers import only lightweight shared errors and native-store
code, not the HTTP client stack. Reads remain fresh for each request's redaction
snapshot rather than caching credential values across requests.

## Modes

```json
{"type": "none"}
{"type": "bearer", "credential": {"source": "native", "name": "docs-token"}}
{"type": "headers", "credentials": {"X-API-Key": {"source": "native", "name": "docs-key"}}}
```

Custom headers are limited to `X-*` names (not `X-Forwarded-*`, `X-Real-*`,
`X-HTTP-Method-*`) and `Api-Key`, at most eight, case-insensitively unique. Header
values must be printable ASCII without spaces. Host, Authorization, Cookie and MCP
protocol headers cannot be set this way.

Stdio profiles use `credentials` instead: `{"ENV_NAME": reference}`. The child
receives only those resolved values plus the minimal base environment.

### OAuth

```json
{
  "type": "oauth",
  "credential": {"source": "native", "name": "docs-oauth"},
  "issuer": "https://auth.example.com",
  "client_id": "pre-registered-public-client",
  "scopes": ["docs:read"],
  "allowed_origins": ["https://auth.example.com"],
  "internal_origins": [],
  "callback_port": 0
}
```

Supported: MCP-compatible discovery (RFC 9728 protected-resource metadata from the
`WWW-Authenticate` challenge or well-known locations, then RFC 8414 / OpenID
configuration for the configured issuer), authorization code with PKCE S256, a
single-use loopback callback on `127.0.0.1`, the `resource` parameter, refresh and
RFC 7009 revocation. The issuer must be listed by the resource. Protected-resource
metadata stays on the MCP resource's origin; authorization-server metadata and
authorization/token/revocation endpoints must be on an `allowed_origins` origin. Only
`internal_origins` may be private addresses. Resource `internal_origins` do not
permit internal authorization servers. Tokens must be bearer tokens with
`expires_in`; the granted scope must equal the configured scopes. A server asking
for a scope outside the configured list requires operator approval (a profile edit).
The client binds authorization/token requests and stored grants to the intended
resource; the resource server validates the audience of opaque access tokens.

The authorization URL also receives a DNS admission check before it is printed or
opened. The system browser controls subsequent DNS resolution and redirects; the
bridge cannot pin that browser's connection against DNS rebinding. Configure only
trusted authorization origins and review the address shown during sign-in.

`callback_port` 0 picks a free port; set a fixed port if the authorization server
requires an exact registered redirect URI (`http://127.0.0.1:PORT/oauth/callback`).
The callback accepts one request with the matching state and issuer, rejects
cross-origin/rebound requests and closes after three minutes.

Access and refresh tokens are stored as separate native entries. Only non-secret
metadata (generation, expiry, lease) is kept in
`runtime_state/mcp_auth.sqlite3`. All bot processes in one installation share a
grant: an expired token is refreshed by exactly one process under a short lease
while others wait and reuse the result. Rotation is committed atomically against
the grant generation, so a logout or newer sign-in always wins over a late refresh,
and cancelling a request cannot lose a rotated refresh token. An HTTP 401 from the
MCP server forces a refresh on the next request; a refused refresh token marks the
grant `expired` until the operator signs in again.

If a native token write fails during explicit sign-in, partial entries are deleted when possible and an
inactive grant record is committed. No token from that failed save can be dispatched;
if native cleanup also failed, `logout` can find that record and retry cleanup.
Revoke access at the provider if remote revocation was not completed.

Automatic refresh differs: a native write failure rolls back metadata and preserves
the token entries, including any rotated refresh token already stored. The next
request retries without requiring sign-in. If the refresh-token write failed before
storing a rotated token, the provider may refuse the old token on retry; the normal
rejected-grant path then marks the grant expired without deleting it.

Unsupported, with clear errors: dynamic client registration and confidential clients
(`client_id` must be a pre-registered public client), PKCE `plain`, implicit or
device flows, tokens without `expires_in`, tokens over 2560 bytes, environment
references for OAuth, browser cookies or desktop/app connector sessions.

## Operator commands

Use this installation's Python interpreter from the installation folder:

```powershell
.venv\Scripts\python.exe mcp_connections.py --config bridge_config.json status
.venv\Scripts\python.exe mcp_connections.py --config bridge_config.json credential-set docs-server docs-token
.venv\Scripts\python.exe mcp_connections.py --config bridge_config.json credential-delete docs-server docs-token
.venv\Scripts\python.exe mcp_connections.py --config bridge_config.json signin oauth-server
.venv\Scripts\python.exe mcp_connections.py --config bridge_config.json signin oauth-server --no-browser
.venv\Scripts\python.exe mcp_connections.py --config bridge_config.json logout oauth-server
```

`credential-set` reads the value from a hidden prompt (or one line of stdin with
`--stdin`), never from arguments, and validates the reference before prompting.
Rotation is `credential-set` again; deletion is `credential-delete`. OAuth values
cannot be set manually. `signin` prints the authorization URL and opens the default
browser unless `--no-browser` is given. `logout` deletes the local grant first, then
asks the provider to revoke it: `revoked`, `local_only` (provider has no revocation
endpoint or refused; revoke it at the provider) or `not_signed_in`.

Output is masked: `authentication` is `none`, `configured`, `required`, `expired`
or `unavailable`, with per-reference `set`/`not_set`/`unavailable`. Errors from the
authentication API are static guidance; tokens never appear in CLI output, logs,
exports, public Discord replies or saved configuration, and a server that reflects a
token back has it redacted before the provider sees the result. Discord users see
only the generic capability failure notice; health files record only the error class.

Available configured native and environment values are read before argument and
provider-context filtering, including ordinary chat. Native reads run off the event
loop with at most four profile readers at once; this does not refresh grants or
start servers. An unavailable unused store does not disable chat; a selected
connection still requires its credential before dispatch. Values that cannot be
read cannot be included in the redaction snapshot.

### Troubleshooting

| Status or error | Meaning and action |
| --- | --- |
| `required` | Nothing stored for this exact profile: run `credential-set` or `signin`. Also expected after any profile edit. |
| `expired` | OAuth refresh was refused or no refresh token was issued: `signin` again. |
| `unavailable` | The native store is locked, missing or unsupported: unlock/start it, or use environment references. |
| `MCP server rejected the credential` | HTTP 401: rotate the bearer/header value; OAuth retries with a refresh next time. |
| `OAuth scope requires operator approval` | The server challenged for a scope you did not configure. |
| `OAuth destination denied` | An endpoint is outside `allowed_origins` or private without `internal_origins`. |
| `MCP authorization refresh busy` | Another process held the refresh lease for its whole lifetime; retry. |
| `MCP grant disabled; native cleanup failed` | Local dispatch is disabled. Retry logout to remove remaining native entries, and revoke access at the provider if remote revocation was not completed. |

## Shared API

`bridge_authentication.Authentication` is the single API for the runtime, the CLI
and the future GUI (#24): `headers`, `environment`, `set_credential`,
`delete_credential`, `signin` (the caller supplies the browser opener), `logout`,
`rejected` and masked `status`. `ConnectionManager` resolves credentials through it
for each request; nothing else reads credential stores.

## Verification and acceptance

| AC | Implementation and evidence |
| --- | --- |
| 1: modes through the manager | `test_oauth_grants.py` runs a real loopback MCP resource and authorization server through `ConnectionManager` and `Bridge.handle`: bearer, custom header and OAuth (no-auth is covered by `test_capabilities.py`/`test_connections.py`), and a real stdio child receives only its approved references (`test_connections.py`). |
| 2: OAuth validation | `test_oauth_discovery.py`, `test_oauth_flow.py` and `test_oauth_browser_boundary.py` exercise issuer/resource/scope/state/PKCE/callback/replay and IPv4/IPv6 admission. |
| 3: refresh, revocation, concurrency, logout | `test_oauth_grants.py` and `test_auth_races_regression.py`: rotation, 401 recovery, concurrent refresh, cancellation, native cleanup failure, logout/late-refresh and stale-401/new-sign-in races. |
| 4: no secret disclosure | Canary checks cover CLI, statuses, SQLite, configuration exports, tool arguments, original/public provider context and public replies. `test_credential_dispatch_guard.py` covers a transient native snapshot read failure before actual credential resolution. |
| 5: native stores | Real Windows Credential Manager in the normal Windows job; real macOS Keychain and Linux Secret Service in the isolated `credentials-macos`/`credentials-linux` jobs with disposable stores. Every adapter also runs on every host through its OS API boundary (`test_credential_adapters.py`). Unavailable stores never fall back. |
| 6: one API, no GUI needed | CLI and runtime use `Authentication`; the same API is available to the future GUI. Credentials never change tool/user/bot policy. `test_cli_secret_input.py` verifies hidden input fails before echoed fallback. |
| 7: real boundaries | Core authentication, storage, leases and HTTP admission run unchanged against controlled peers. OS/DNS/browser/input faults and CLI error-reporting injection are identified in tests. Exact 100% statement/branch coverage remains required. |
| 8: documentation | This guide plus [MCP connections](mcp-connections.md) and [security review](security-review.md). |
