# Scoped MCP and web access (issue #17)

Capabilities are disabled in fresh installations and when existing configuration
omits the `capabilities` key. Native Codex, Claude and Gemini providers keep their
existing text-only restrictions. The bridge executes one explicit read-only operation
and supplies its result as untrusted data to the selected provider. Models, channel
history, attachments, display names, bot handoffs and remote tool descriptions cannot
select operations or grant permissions. Ordinary text replies continue to work when
a capability server fails.

## Commands

Use a numeric bot mention in the configured channel, followed by one command:

```text
<@BOT_ID> /web https://example.com/page
<@BOT_ID> /search search terms
<@BOT_ID> /mcp docs {"query":"search terms"}
```

`/web` fetches one page with GET. It does not execute scripts, load linked resources,
use browser sessions or log into sites. `/search` calls the configured MCP search alias
with a `query` string. `/mcp` selects a configured alias, never an arbitrary endpoint or
tool name. Tool parameters are required scalar strings, integers or booleans; nested
objects and arrays are unsupported. Fixed arguments cannot be overridden. A command
inside `/discuss`, `/work`, a quote or a tool result does not invoke this dispatcher.
Discussion continuations cannot invoke capabilities.

## Operator configuration

Add a reviewed `capabilities` object to the ignored `bridge_config.json`. This example
remains disabled; replace the URL, actual tool name and numeric identities with values
verified for your read-only server before considering enablement:

```json
{
  "enabled": false,
  "web": false,
  "internal_origins": [],
  "tools": {
    "docs": {
      "endpoint": "https://mcp.example.com/mcp",
      "protocol": "2025-11-25",
      "name": "search_docs",
      "read_only": true,
      "user_ids": [123456789],
      "bot_ids": [987654321],
      "parameters": {"query": "string"},
      "fixed_arguments": {"collection": "public"},
      "credential_env": "BOTBRIDGE_MCP_DOCS"
    }
  },
  "search": "docs"
}
```

User and bot IDs must also appear in the bridge's global allowlist and enabled roster.
Every tool needs its own explicit user/bot scope. At most 32 aliases and 16 dynamic
plus 16 fixed scalar arguments per tool are allowed; dynamic values are at most 2048
characters. Search aliases must have exactly one dynamic parameter, `query: string`.
`credential_env: null` selects an unauthenticated server. Credential names must start
with `BOTBRIDGE_MCP_` and use uppercase ASCII; existing Discord/provider credentials
cannot be selected. Set the value in the bot process environment without committing it
or posting it in Discord, then restart through the normal deployment process.

All configured tools must be read-only. Mutating tools fail configuration validation,
including when requested by the owner. This ticket provides no new file writes,
memory access, shell execution or external write approvals. Existing owner-only private
`/work` remains a separate explicitly enabled capability; expanded memory is issue #18.
`read_only: true` is an operator assertion, not a sandbox for a malicious MCP server.
Review the server implementation, credential scopes and fixed collection/resource
arguments before granting it access. Remote `readOnlyHint` annotations confer no authority.

Public destinations require HTTPS and globally routable unicast addresses. DNS answers
are checked and the connector uses those same addresses, with no DNS cache, proxy or
cookies. A mixed public/private DNS answer fails closed. Each web redirect is rechecked;
MCP redirects are refused so bearer credentials cannot follow them. An internal server
needs a separate explicit entry in `internal_origins`, such as
`https://mcp.internal.example:8443`, with no path, query, credentials or wildcard.
That exact scheme/host/port grants an exception to public-address and HTTPS requirements
for both MCP and `/web`; it does not grant other internal destinations. Plain HTTP in
this list deliberately permits cleartext traffic and must be confined to a trusted
local test service. Keep credentials on HTTPS in deployments.

## Supported protocol and provider behavior

Each tool specifies exactly one supported protocol; negotiation cannot downgrade to
another revision. **MCP 2026-07-28 Streamable HTTP** uses stateless POST JSON-RPC,
protocol/method/name headers and client `_meta`. **MCP 2025-11-25 Streamable HTTP**
uses initialize/initialized and an optional server session ID, followed by best-effort
bounded DELETE cleanup. Session IDs are treated as sensitive and redacted alongside
bearer credentials. Both accept bounded JSON or request-scoped SSE responses and
support paginated `tools/list` and text `tools/call`
results. It does not import server instructions, roots, sampling, elicitation, provider
configuration, hooks or plugins. Server-initiated requests, input requests, non-text
results and schemas requiring `x-mcp-header` mirroring fail closed. There are no
subscriptions, reconnections or persisted sessions. Other protocol revisions, legacy
HTTP+SSE transports, stdio and OAuth discovery are unsupported; use a compatible server
rather than relaxing the checks. See the [stateless transport specification](https://modelcontextprotocol.io/specification/2026-07-28/basic/transports/streamable-http)
and [2025 Streamable HTTP specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/transports).

| Provider identity | Dispatch | Native tools/inherited MCP |
| --- | --- | --- |
| CodexBot | Bridge HTTP -> sanitized result -> existing Codex text call | Disabled in public mode |
| ClaudeBot | Bridge HTTP -> sanitized result -> existing Claude text call | Disabled in public mode |
| AntigravityBot | Bridge HTTP -> sanitized result -> existing Gemini text call | No native tools configured |

The optional dispatcher launches no subprocesses. Existing hidden Windows defaults
and `BOTBRIDGE_SHOW_CONSOLE=1` troubleshooting behavior are unchanged. Codex's own
[MCP configuration](https://learn.chatgpt.com/docs/extend/mcp?surface=cli) is intentionally
not used as a bridge capability registry.

## Limits, privacy and acceptance evidence

Each admitted command shares the existing persistent human/bot admission limits,
daily allowance, queue capacity and per-bot execution lock. Daily capacity is charged
when a capability attempt starts, before any network activity; its subsequent provider
reply uses that same reservation. Capability failure/cancellation after that point stays
charged. Cancellation or expiry while still queued gives the daily reservation back.
Each operation has a 15-second total network deadline, a 64 KiB body limit per response,
three web redirects or three MCP discovery pages, and at most one MCP tool call.
Legacy initialization/notification and session termination add protocol-only requests;
termination gets at most two additional seconds and does not mask a call failure. Bodies
with compression are refused. Tool text supplied to providers is capped at 16000
characters. Network I/O is asynchronous; privacy scans run off the event loop.

Actual argument values are privacy-checked before JSON escaping or network dispatch.
Tool output is checked against current private-memory rules and known scoped
credentials before being supplied to a provider; public replies are checked again.
Credentials go only in the selected server's Authorization header. Audit entries record
the configured alias (or generic command), authorization decision and outcome; they
contain no queries, URLs, arguments, result bodies or exception messages. Literal
redaction is not semantic DLP against a server that encodes or paraphrases a secret;
do not register untrusted servers or give them credentials beyond their scope.

`tests/test_capability_http.py` uses real local sockets for redirects, private DNS
destinations, pinned connection addresses, oversized bodies, compression, encoding,
timeouts and cancellation. Only OS DNS resolution is substituted for deterministic
DNS tests. `tests/test_capabilities.py` runs the actual HTTP/MCP client and Discord
consumer against a local server, covering both protocols, sessions/cleanup, JSON/SSE, malformed protocol replies,
registry/identity scopes, injection in descriptions/results, private arguments with
quotes/backslashes, synthetic credential redaction, all three identities, persistent
quota charging, replay and queued expiry. External model inference is a controlled
test sink, not a replacement for the authorization or transport being tested.

These isolated checks do not establish acceptance of an operator's particular server,
credential scope or live Discord delivery. Keep the feature disabled until required CI,
security review and an isolated acceptance run for each configured tool/server pass.
Record the exact configuration revision, server protocol, tool arguments/scopes and
redacted outcome before a separately authorized deployment. No live acceptance or
deployment is claimed by the automated fixture tests.
