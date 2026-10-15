# Scoped memory and confirmed notes (issue #18)

Memory access is off by default. It does not inherit model tools or arbitrary file
access. Operators configure up to 32 named Markdown files under one absolute local
root; that root must equal the installation's privacy source. Each file is at most
64 KiB, and each displayed excerpt or submitted note is at most 12000 characters.
Files must already exist. Paths, links, junctions, hard links, invalid UTF-8, unreadable
sources and malformed PRIVATE markers fail closed. Filesystem work runs in worker
threads; the existing bounded queue, per-bot lock and persistent admission/daily
capability budgets also apply. Memory commands produce direct bridge replies and
never invoke a model or MCP server.

Ben selected **dedicated notes first**. Shared task/protocol records are read-only.
Writes beneath a shared root containing AGENTS.md, LIVE_STATE.md and SESSION_LOG.md
are refused. Canonical shared filenames cannot be configured as writable aliases.
This version does not write shared-agent identity/checkpoint records or alter
STATIC_PROCEDURES.md. Shared task-board updates require a separate policy.

## Commands and delivery

In the configured public channel:

- `<@BOT_ID> /memory read facts`: retrieve an approved public excerpt.
- `<@BOT_ID> /memory private notes`: verified owner only; results go to the owner's DM.

In the owner's direct DM with that bot (no mention needed):

- `/memory private notes`: view the note and its SHA-256 revision.
- `/memory propose notes REVISION {"text":"new note text"}`: private preview, no file change.
- `/memory commit CONFIRMATION`: confirm the exact proposed change within 120 seconds.
- `/memory status`: inspect a pending recovery receipt.
- `/memory recover RECEIPT`: explicitly recover that recorded transaction.

Write text and confirmations are refused in public channels. Bot authors, webhooks,
quoted commands, forged owner IDs, guild channels and group DMs cannot authorize private
access. Discord does not name the recipient of an incoming DM, so a DM command is
accepted from the configured owner in a private, non-guild channel. Before any private
memory read or write, the runtime asks Discord for the owner's DM, requires that it is
the owner's private channel and, for a DM command, the same channel the command came
from, and sends an acceptance message there. A failed destination prevents dispatch
with no public fallback. A mention inside note text does not select another bot. Confirmation tokens
are bound to the owner and selected bot, single-use, bounded to 16 pending proposals,
and discarded on expiry or restart. Nothing in memory text can dispatch another action.

## Configuration

An example disabled policy for `bridge_config.json`:

```json
{
  "enabled": false,
  "root": "C:/BotBridgeNotes",
  "user_ids": [123456789],
  "bot_ids": [987654321],
  "credential_env": ["BOTBRIDGE_MCP_DOCS"],
  "files": {
    "facts": {"path": "facts.md", "public": true, "private": false, "write": null},
    "notes": {"path": "notes.md", "public": false, "private": true, "write": "replace"},
    "log": {"path": "notes/log.md", "public": false, "private": true, "write": "append"}
  }
}
```

Place this object under the top-level `memory` key. User/bot scopes must be subsets
of the global allowed users and enabled roster. Private operations additionally
require the configured owner. `public`/`private` select delivery permissions;
PRIVATE markers supply the existing literal DLP policy. Public excerpts are filtered
against current privacy sources, all configured aliases and retained private-marked
backups; credential-shaped values and configured environment credentials are masked.
Masking runs on the whole note before the 12000-character excerpt limit, so the cut
cannot expose part of a value. Public excerpts are posted as plain text under a
`Memory ALIAS (approved public excerpt):` heading; no model reads them.
Owner-private reads can show PRIVATE-marked text but still mask known credentials.
Literal filtering does not identify every paraphrase or encoding of a secret.
Curate public files and review every server-side credential scope before enablement.

Precreate the root, approved files and nested directories with restrictive owner-only
filesystem permissions. Windows control files inherit those ACLs; POSIX atomic and
audit files use mode 0600, and the control directory uses 0700 to protect its SQLite
lock file as well. Use a local disk, not UNC/network
storage. Do not let untrusted accounts write this root. Keep the existing privacy
source set to the same root. Paths and exact public/private/write policy need
operator review and isolated acceptance before activation. Set `enabled: false`
and restart through the normal deployment workflow to disable the feature.

## Conflicts and recovery

Notes use atomic replacement and file flushes, with bounded Windows sharing retries.
Directory handles prevent Windows directory replacement during operations; POSIX
reads/replacements use pinned directory descriptors. A root-scoped SQLite transaction
serializes bridge writers. The expected revision is checked before durable preparation
and immediately before replacement. External editors do not participate in this lock.
The revision check and replacement are separate filesystem operations: an external
edit after the final check can race either a commit or recovery. Pause bridge writes
before editing these files elsewhere, then read the newest revision before proposing
another write. This is revision conflict detection, not a filesystem compare-and-swap.

The private `.botbridge-memory` directory retains preimages, immutable receipts,
a pending record and an append-only metadata journal. Receipts and the pending record
hold only the alias, path, write mode and before/after hashes. Audit records contain
alias, receipt, hashes, timestamp and outcome (`prepared`, `committed`, `abandoned`,
`recovered-applied` or `recovered-unapplied`), never note contents or credentials.
Preimage backups retain PRIVATE markers so replacing a note does not erase the deny
set for its old private values. At 64 receipts/backups or approximately 1 MiB of audit
metadata, new writes stop until the operator archives records while preserving the
journal; reads continue. Nothing silently prunes these append-only records.

If the final revision check finds an external edit, nothing is written: the commit is
journaled as `abandoned`, its pending record is closed and the owner sees a revision
conflict. Any other failure after preparation (a crash, a write error, or a failed
final audit entry) leaves a pending record, even if the note was already replaced;
later commits are refused until it is resolved. After any refused commit, check
`/memory status`. The owner inspects `status` and
explicitly selects `recover RECEIPT`. Recovery rolls forward: if the note already has
the confirmed revision it is kept (`recovered-applied`); if the note still has the
prior revision, the change was not applied and only the record is closed
(`recovered-unapplied`). Recovery never rewrites the note and refuses any other
revision; an operator must then inspect the note, receipt and preimage and resolve the
pending record locally. The same external-editor coordination requirement applies.
Atomic write/recovery work finishes before cancellation releases the request's lock;
a Discord timeout can occur after the file changed. Inspect the private revision
and receipt before retrying; a used confirmation cannot be replayed.

A command the policy does not allow (wrong channel, non-owner, unknown alias or
malformed arguments) gets the generic reply `Bridge: capability request denied; check
configuration and command arguments.` An allowed command that then fails replies with
a fixed reason, for example `Memory revision conflict`,
`Memory confirmation unavailable`, `Memory file unavailable` (missing or access-denied
file) or `Memory busy; try again shortly` (another bridge writer holds the root lock).
These reasons never include note text, paths or credentials.

## AC evidence and deployment

`tests/test_memory.py`, `tests/test_memory_edges.py` and `tests/test_memory_io.py`
exercise actual configuration/authorization, bounded files, private routing, exact
previews, confirmations, replay/expiry, concurrent real writers, hard links, redaction,
roll-forward recovery after real process crashes and cancellation through production
code. Owner-DM authorization is also checked against messages built by discord.py's own
gateway parser, so the test DM shape matches the library. Discord transport and provider
replies are test adapters; the authorization, filesystem, SQLite and memory dispatcher
are not mocked. OS fault-injection tests
cover failure paths separately from real native behavior. Both platform CI suites
and exact coverage/security gates must pass before review readiness.

No live shared-memory, provider-account or Discord acceptance is claimed by fixtures.
Keep access off until the reviewed aliases, ACLs, privacy source and delivery policy
pass an isolated acceptance run. Live enablement/deployment remains a separate action.
