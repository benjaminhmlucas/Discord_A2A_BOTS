# MCP connections (issue #26)

Connections describe **how to reach a server**; tool aliases describe **what a
particular Discord user and bot may call**. Connecting, testing, discovery and
sign-in never grant tool permissions. Native provider MCP settings and desktop-app
sessions are not inherited. Capabilities remain off by default.

## Configuration first

Inside the ignored `bridge_config.json`, `capabilities.connections` has this form:

```json
{
  "version": 1,
  "servers": {
    "docs-server": {
      "transport": "http",
      "endpoint": "https://mcp.example.com/mcp",
      "protocol": "2025-11-25",
      "authentication": {
        "type": "bearer",
        "credential": {"source": "native", "name": "docs-token"}
      }
    }
  }
}
```

`authentication` is required: `{"type": "none"}`, a bearer reference, restricted
custom headers or OAuth. Profiles hold credential **references**, never values; see
[MCP authentication](mcp-authentication.md) for every mode, the native credential
stores and the sign-in/rotation commands. Endpoint query parameters named like
credentials (token, key, secret, signature, session, auth...) are rejected.
Remote HTTP uses the existing HTTPS/address/DNS/redirect policy and explicit
`internal_origins` exceptions. HTTP supports the configured 2025-11-25 or
2026-07-28 protocol without silent downgrade.

Local connections instead contain these exact fields:

```json
{
  "transport": "stdio",
  "command": "/absolute/path/to/mcp-server",
  "arguments": [],
  "cwd": "/absolute/path/to/working-directory",
  "environment": {"LANG": "en_US.UTF-8"},
  "credentials": {"SERVICE_TOKEN": {"source": "native", "name": "service-token"}}
}
```

`credentials` maps a child environment variable to a native or environment
reference; only those resolved values reach the child.

Use native absolute Windows paths on Windows (escaped backslashes in JSON).
The command must be an executable, not a `.cmd`, `.bat`, `.ps1` or `.sh` launcher;
paths ending in a dot or space are rejected to avoid Windows normalization ambiguity.
Run an explicitly selected interpreter with the script as an argument if needed.
This is an operator-selected program, not a sandbox: installing a malicious local
server gives it the operating-system access of the bot account. Read-only tool
policy cannot constrain what that program does internally.

The bridge does not use a shell or search PATH for the server command. Child
environment starts with only OS/locale temporary-directory settings, adds the
explicit profile values and credential references, and sets its own Node hiding
preload, UTF-8 mode and troubleshooting switch. Plaintext credential-looking
environment names are refused; use references for all secrets, regardless of name.
Commands/arguments and ordinary environment values must not contain credentials.
Case-insensitive duplicate environment keys are rejected for portable behavior.
Configure required helper executables explicitly, for example Comfy's
`GIT_PYTHON_GIT_EXECUTABLE`; desktop PATH/configuration is not inherited.

Stdio uses initialize/initialized with version 2025-11-25. Server versions outside
the supported protocol fail clearly. Requests/notifications are newline-delimited
UTF-8 JSON-RPC; server requests for sampling, roots or elicitation are denied.
Legacy HTTP+SSE, subscriptions, arbitrary extension behavior and non-text tool
results are not supported. This is defined compatibility, not every MCP server.

## Tool permission and nested arguments

Registered aliases may reference a connection instead of repeating HTTP details:

```json
{
  "connection": "docs-server",
  "name": "search_docs",
  "read_only": true,
  "user_ids": [123456789],
  "bot_ids": [987654321],
  "input_schema": {
    "type": "object",
    "properties": {"query": {"type": "string"}},
    "required": ["query"],
    "additionalProperties": false
  },
  "fixed_arguments": {"collection": "public"}
}
```

Place that object under `capabilities.tools.docs`. IDs must also belong to the
global allowlist/enabled roster. The human command is still
`<@BOT_ID> /mcp docs {"query":"topic"}`. The local input schema describes dynamic
arguments; fixed top-level arguments must be disjoint. The merged arguments must
also satisfy the server's declared input schema before `tools/call`.
Search aliases use the exact query-only object schema shown above. Every tool must
reference a connection and declare `input_schema`; inline endpoints and scalar
`parameters` are rejected. This replaces the unreleased inline format. There is no
migration command or second argument-validation path.

Supported schema keywords are `type`, `properties`, `required`, boolean
`additionalProperties`, `items`, `enum`, `anyOf`, `minLength`, `maxLength`,
`minItems`, `maxItems`, `minimum` and `maximum`. Types are object, array, string,
integer, number, boolean and null, without coercion. `title`, `description`,
`default` and `$schema` are bounded metadata; defaults are not inserted. This is
an explicit subset, not a full JSON Schema implementation. References, patterns,
formats, header-mirroring and unknown keywords are refused; nothing fetches remote
schemas or executes schema text.

Both local argument policy and remote schema checks are required. All arguments, including
nested raw strings and keys, pass current privacy/credential filtering before
serialization or dispatch. Server descriptions/results cannot choose commands,
endpoints, credentials or permissions. Existing read-only annotation vetoes remain;
missing hints retain the operator's assertion rather than proving a tool is safe.
Mutating tools remain rejected and are separately tracked under #28.

## Shared API and CLI

`Registry` validates and exports independent copies. `changed()` produces a new
validated registry; it does not change a running connection. `ConnectionManager`
provides `status`, `connect`, `disconnect`, request-scoped `session`, `discover` and
`call`. The runtime authorizes the explicit alias before calling this trusted
transport API. A future #24 UI must use the same validators and manager, not
implement another transport or permission engine.
Raw discovery definitions returned by the trusted API remain untrusted data;
callers must filter credentials before displaying them. The CLI propagates selected
credential/session values to its redactor and sanitizes names before serialization.

Use this checkout's Python interpreter; Windows examples:

```powershell
.venv\Scripts\python.exe mcp_connections.py --config bridge_config.json status
.venv\Scripts\python.exe mcp_connections.py --config bridge_config.json test docs-server
.venv\Scripts\python.exe mcp_connections.py --config bridge_config.json discover docs-server
.venv\Scripts\python.exe mcp_connections.py --config bridge_config.json add local-server --profile local-profile.json --output proposed-config.json
.venv\Scripts\python.exe mcp_connections.py --config bridge_config.json edit local-server --profile revised-profile.json --output proposed-config-2.json
.venv\Scripts\python.exe mcp_connections.py --config bridge_config.json remove local-server --output proposed-config-3.json
```

`status` reports this manager instance plus masked authentication state; a fresh
CLI invocation has no connected sessions and does not probe existing bot processes.
Credential and sign-in commands are documented in
[MCP authentication](mcp-authentication.md). `test` performs initialization
and discovery, not a tool call. `discover` adds tool names only, not descriptions or
schemas. Diagnostic sessions disconnect before returning; output reports
`connected: false` and the completed/failed/rejected outcome. Future long-lived
callers can explicitly connect/disconnect through the shared API. Only the explicit
`signin` command can open a browser.

Edits validate the complete resulting bridge configuration and write only a **new**
export, refusing to overwrite existing files. Omitted optional runtime defaults stay
omitted in exports. A configuration without `capabilities` can add its first profile;
capabilities remain disabled. Review the export before the normal stopped-service
update/restart procedure; no hot reload or live service action occurs.
Removing a referenced connection is rejected until its aliases are changed/removed.

## Bounds and lifecycle

There are at most 32 profiles, 32 launch arguments and 32 entries in each environment
map, 1024 characters per
executable/working-directory path and 2048 characters per launch argument/value.
Each profile is at most 16 KiB. Argument graphs are at most six levels, 32 object
members/array items per container, 256 privacy leaves and 64 KiB encoded JSON; scalar
text is at most 4096 characters. All aliases use the same 64 KiB argument bound for
privacy traversal and remote schema validation. Schema text is at most 16 KiB, with
at most eight `anyOf` choices and 16 enum values. Malformed Unicode fails closed.
Local aliases forbid unknown dynamic top-level
arguments; nested additional-field behavior follows the explicit schema.

Each operation has a 15-second deadline and up to two seconds for cleanup. Manager
sessions serialize per profile and allow at most four simultaneous operations per
manager, within existing per-bot queue/quota limits. Stdio frames and accumulated
notifications per RPC are capped at 512 KiB; stderr is drained privately and capped
at 64 KiB per session. Discovery is at most three pages and 256 unique names.
HTTP retains its 64 KiB response cap. Tool text still goes through the existing
privacy/result-length limits before a provider sees it.

Each runtime operation starts a fresh stdio server, so startup/initialization cost
is paid per call. This deliberately bounds session state and child lifetime; the
shared API also supports explicit connect/disconnect for a trusted long-lived caller.
Sessions own their child processes and clean up on failure, timeout, cancellation
and completion. The Windows host uses a private kill-on-close job; POSIX uses an
owned process group. Stdio cancellation signals the active request best-effort,
then terminates the owned tree. A failed cleanup retains ownership; the next connection attempt retries cleanup
before any replacement starts. Repeated cleanup failure stays visible and never
starts a second server. HTTP cancellation cannot prove remote work stopped.
Windows host/server launches are hidden by default and honor
`BOTBRIDGE_SHOW_CONSOLE=1`. The Node preload hides supported Node child launches;
an arbitrary server can use native launch APIs of its own, so visible descendants
must be checked during acceptance. Full native installation portability remains #25.

## Verification and acceptance

`test_connections.py` runs actual subprocesses and HTTP servers through the real
manager and Discord consumer. `test_connection_config.py` exercises the actual
registry/CLI, validation and exclusive exports. `test_mcp_schema.py`
covers schema/argument admission. `test_mcp_host.py` executes the real host and
merges child coverage, checking inherited pipes and exit codes without assigning
the test runner to a process job. OS fault adapters may be substituted in focused
platform-edge tests; authorization, state, transport and schema logic are not mocked.

For a selected server, record executable/server versions, explicit helper paths,
protocol, approved tool/arguments, sanitized outcome and cleanup. Start with
metadata-only Comfy `server_info`; a stopped ComfyUI backend is a reported state,
not permission to start it or generate images. Test each independent profile.
Record controlled consumer fixtures separately from actual Discord delivery and
provider inference. No live capability enablement, image generation, model/node
installation or service changes follow from passing fixture tests.

### Ticket acceptance map

| AC | Implementation and evidence |
| --- | --- |
| 1: one configuration format | Every tool uses a connection and input_schema; former inline/parameters formats and the migrate command are rejected. Registry/profile and actual HTTP/stdio tests cover valid configuration and bounded failures. |
| 2: independent stdio and HTTP consumers | Real subprocess lifecycle/profile tests and connection-backed HTTP initialization through `Bridge.handle`; separately recorded metadata-only calls to both selected Comfy profiles. |
| 3: shared policy and management | CLI/registry/runtime tests cover the same validators, exclusive exports, scopes, discovery without calls, busy status and owned sessions. |
| 4: nested schema and injection bounds | `test_mcp_schema.py` plus actual consumer, annotation-veto and untrusted-definition/result regressions. |
| 5: failure, cancellation and cleanup | Independent stdio/socket peers exercise malformed frames, stderr/output limits, failed launch, cancellation/backpressure, reconnect and actual child cleanup. OS failure/driver tests inject only the OS boundary and retain the real manager/transport. |
| 6: privacy and credentials | Real bearer/session discovery reflection and stdio credential-echo tests verify filtering before provider input, public output and audit; private nested arguments are denied before dispatch. |
| 7: selected real-server acceptance | Record protocol/server versions, exact approved metadata tool, reported backend state and cleanup for each profile; distinguish synthetic Discord/provider transports from live delivery. |
| 8: review and validation | The unchanged exact coverage gates require every shipped Python statement/branch and applicable JavaScript line/branch/function. PR evidence records the tested head, CI, audits and independent agent review; human approval remains separate. |
