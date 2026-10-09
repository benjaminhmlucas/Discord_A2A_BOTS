# Security controls and review policy

Configure the default branch to require a pull request, one independent approval of the latest
push, dismissal of stale approvals, resolved conversations, an up-to-date branch,
and passing required checks. There is no bypass list. Deletion and force pushes are
blocked. Linear history requires squash or rebase merging. An author cannot approve
their own PR; a solo maintainer needs another trusted reviewer with write access.
Do not grant repository access to an unknown account just to satisfy this rule.

Required checks are the Ubuntu 24.04 and Windows 2022 test jobs, Quality and
dependency audits, and both CodeQL language jobs. Repository settings enforce these
requirements; committing workflow YAML alone does not enable branch protection.
Review and verify the active GitHub ruleset after changing job names or permissions.

CI uses SHA-pinned actions, read-only checkout credentials and no application
secrets. Only the CodeQL job has permission to publish security findings. PR code
never runs in a `pull_request_target` context. Tests use hosted runners and synthetic
identities, never a production bot home. Dependencies and actions receive weekly
Dependabot PRs; updates must pass the same checks and approval requirements.

Ruff checks and formats shipped Python and tests. Mypy strictly checks the provider
contract and atomic health I/O boundary; the remaining dynamically configured
Discord code is not yet fully typed. Bandit blocks all medium/high findings without
rule or vulnerability exclusions. Its remaining low-severity findings identify
subprocess imports and calls: commands use argument arrays, never user text as shell
syntax; tree termination addresses owned PIDs. Review these findings when process
code changes. Dependency audits cover the installed Python development/runtime
environment and both locked PM2/logrotate graphs, failing on any known advisory.

PM2's namespace adapter patches the internal `God.getMonitorData` method for
metadata-only recovery queries. Every PM2 upgrade must revalidate that internal
contract using actual daemon-loss and lifecycle tests, including normal monitoring.
The managed CLI recognizes leading global flags and their values before selecting
the command; an option value named `stop` cannot change a `list` command. Unknown
options preserve normal behavior and arguments are forwarded unchanged.
Management operations explicitly set `BOTBRIDGE_PM2_METADATA_ONLY=1` so process-name
lookup and operation summaries use metadata instead of blocking Windows WMI metrics.
This requires the pinned Client.executeRemote adapter too. Direct PM2 monitoring
without this opt-in retains normal CPU/memory collection.
The adapter intentionally requires PM2 7.0.1. A dependency update that
changes this version must update and retest the adapter and both npm manifests
together. The production logrotate installer copies the committed manifest and integrity
lock and runs npm ci with lifecycle scripts disabled; CI audits that same graph.
The unit suite asserts lock equality and the shared override policy. Auditing known advisories and
exact coverage do not establish absence of unknown vulnerabilities.

Privacy scanning propagates unreadable directory/file errors, rejects links and
Windows reparse points, and reads every Markdown file on each refresh. Each filter
batch uses a complete immutable snapshot; a failed scan cannot fall back to stale
rules or publish partially loaded rules. The privacy directory remains trusted, operator-managed storage. This
literal filter is not semantic DLP and cannot prevent a model paraphrasing private
information. Keep private information out of public context.

Runtime scans run in worker threads. The request and public context share one complete
input snapshot; public replies receive a fresh scan so rules or ACL changes during
provider execution still apply. Concurrent batches never use partially loaded rules.
Quota reservations precede acknowledgements and private-DM setup. Admission attempts
count against the per-minute limits, even when they later time out in the queue.
Daily capacity is reserved atomically while waiting, and spent only when the provider
starts. Queue timeouts, cancellation or other failures before that point release the
daily reservation without refunding the admission rate. Once the provider starts,
failures and timeouts remain charged because provider work may already have occurred.
Unused reservations expire after the configured total deadline plus 25 seconds of
cleanup grace, so a crash cannot strand daily capacity for a full day. Expired
reservations cannot start a provider or claim capacity already reassigned elsewhere.

Tool-enabled `/work` requires the numeric owner, CodexBot, explicit enablement and
successful private-DM setup. Only the owner's request text is included; channel
history, display names, attachments and public-context files are excluded. Work
results remain private. Local work still has the owner's configured tool access;
it is not an isolation boundary for a compromised owner account.

Request counts persist in SQLite, using atomic transactions. Defaults allow six
human admission attempts per minute across identities, 30 admissions per bot per minute
and 200 per bot in a rolling day. Discussion continuations count toward bot limits.
When upgrading an existing database, historical admission records are conservatively
imported once as spent daily usage; they age out normally rather than resetting limits.
Failed provider attempts consume their reservation. Limits apply before invoking
providers, and do not measure tokens or currency; configure provider-side spend
limits where supported. Changing limits requires restarting the consumer.

Recovery validates saved roster, executable, working directory, home, hidden-window
policy, ordered arguments and interpreter before resurrection. It preserves stopped
or fatal services. Degradation returns exit code 1 and writes a bounded journal;
operators must inspect fresh recovery/health state and repair the cause. It does not
restart stopped services merely to make monitoring green.

Recovery's metadata-only process-list RPC avoids Windows CPU/memory query delays.
The adapter enables it only for an explicit boolean flag in pinned PM2 7.0.1;
normal monitoring continues to collect metrics. The actual scheduled-task test
verifies cold recovery, deliberately stopped service preservation and cleanup.
