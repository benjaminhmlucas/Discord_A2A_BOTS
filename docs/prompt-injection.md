# Prompt-injection trust boundaries

Issue [#16](https://github.com/benjaminhmlucas/Discord_A2A_BOTS/issues/16) establishes
the policy required before [MCP/web tools](https://github.com/benjaminhmlucas/Discord_A2A_BOTS/issues/17)
and [expanded memory access](https://github.com/benjaminhmlucas/Discord_A2A_BOTS/issues/18)
are enabled. This change does not enable either feature.

## Authorization sources

Discord transport metadata identifies the channel, numeric sender and bot/webhook
status. `bridge_authorization.eligible_sender` enforces the configured channel,
enabled bot roster and human allowlist. Content, display names and quoted IDs cannot
replace these fields. Bot continuations additionally require the real SQLite
handoff transaction and its single-use token.

`authorize_work` grants the existing work mode only to an eligible human owner
issuing an explicit `/work` command to CodexBot, with `allow_work` exactly `true`.
Private-DM setup and an actual send must succeed before the work provider runs.
SQLite records prevent a Discord message being executed or answered again,
including after a restart, within their retention window (24 hours, at most
20,000 records). Deduplication runs before any refusal is sent.
There is no approval-token API: quoted or repeated approval text grants nothing.

Public calls remain text-only: Codex disables tools, browsing and inherited
configuration; Claude disables tools, MCP, hooks and inherited settings; Gemini
does not dispatch local tools. Provider text is never interpreted as a tool call
or authorization decision. Discussion JSON may choose a bounded stop/continue
decision, but it cannot choose tools, sender identity or routing permissions.

PR titles, bodies, comments, diffs and documents, and future web/MCP/tool results,
are data. The same rule applies when their text is pasted into public Discord
requests. Public input/output pass through the real privacy filter, which reads
operator-managed private-marker files and fails closed when those rules cannot
be loaded. A synthetic private value is redacted even if a provider emits it.

## PR and CI checks

`scripts/check_ci_policy.py` parses workflow files as YAML data. It never executes
their `run` commands or candidate Python/JavaScript code. It rejects unexpected
workflows/triggers/jobs, untrusted runners, excessive permissions, production job
environments, actions not pinned to the reviewed commits, persistent checkout
credentials, direct PR/secrets expressions, duplicate YAML keys, aliases, explicit
YAML tags and malformed configuration. Only the CodeQL analysis job may publish
security events.
Main runs must not cancel each other: job keys are an allowlist, so job-level
`concurrency`, `if`, `continue-on-error`, `env`, `uses` and similar settings are
rejected. The checker runs inside the existing required Quality and dependency audits
job, so the five required check names and independent approval rules are unchanged.

Expressions are permitted by structural location, not a global keyword list.
Only the action families, exact commits and input fields used by these two
workflows are allowed; an action update, including a Dependabot PR, must update
`ACTION_PINS` in the checker in the same reviewed change.
Step keys are also an allowlist, so `shell`, `working-directory`,
`continue-on-error` and differently cased keys are rejected; `run` and `env`
cannot consume display or PR expressions.
The policy job and its single checker step must run unconditionally and block on
failure; the checker cannot be retargeted through step environment or defaults. The
two-OS test matrix must actually use `matrix.os` as its runner. Linked/reparse-point
workflow ancestors and leaves are rejected before parsing. These are checks of the
policy-inspected fields, not a complete replacement for GitHub's workflow schema.

To inspect a candidate checkout, run the checker from a trusted installation with
development dependencies installed:

```text
python /trusted/checkout/scripts/check_ci_policy.py /candidate/checkout
```

Review candidate checker/workflow changes against that trusted version. A PR can
edit its own tests and checker; its green CI alone cannot certify those edits.
Independent review and branch protection remain necessary. Hosted CI executes
candidate tests on isolated GitHub runners with synthetic identities, without
production bot credentials or local private memory. The policy checker does not
prevent arbitrary behavior by candidate code within that runner's existing rights.

## Acceptance Criteria and evidence

| AC | Code and verification |
| --- | --- |
| Untrusted data cannot grant denied public capabilities or expose a literal synthetic private value | `bridge_authorization.py`, real `Bridge` dispatch/privacy, `test_untrusted_artifacts_cannot_change_actual_public_dispatch` |
| PR metadata/diffs, forged identity/approval, tool results and cross-user access are covered | `tests/fixtures/prompt_injection.json`, `test_prompt_injection.py`, `test_ci_injection.py` |
| Enforcement does not depend on recognizing malicious wording | Numeric metadata checks and exact work enablement; arbitrary provider text remains text |
| PR workflow privilege and credential isolation is checked | `check_ci_policy.py`, real mutated YAML files and real checker CLI invocations in `test_ci_injection.py` |
| Denials fail closed and legitimate operations still work | Public attack/benign requests, authorized private work, private delivery denial and durable replay tests |
| Tests/coverage/security checks pass on the implementation head | Exact Python statement/branch gate and Node line/branch/function gate in required hosted CI; results belong in the implementation PR |
| Deterministic guarantees and limitations are documented | This document and `SECURITY.md` |
| Independent review and protected merges remain required | Existing repository rules; no rule or required-check-name changes |

The added integration tests execute real bridge authorization, SQLite state and
privacy filtering against actual temporary files. Discord networking and model
output are substitutes at external I/O boundaries; these tests do not verify
Discord delivery or a proprietary provider's native sandbox. The checker tests
execute actual validation against hostile workflow files, including real CLI
startup and rejection without running the candidate command. No authorization,
SQLite, privacy or workflow-checker function is mocked in these new tests.

## Limits

There is no universal deterministic detector for malicious natural-language
instructions. These checks enforce specific capabilities and data flows; they
do not guarantee truthful model answers or detect semantic leaks, encodings or
paraphrases of private information. Keep secrets out of supplied public context.

Existing owner-only `/work` intentionally gives Codex its configured workspace
tools. It is not a per-command approval system, and this ticket does not prevent
untrusted documents from influencing actions already permitted inside that mode.
Keep it disabled unless the owner accepts those capabilities; a compromised owner
account is outside this boundary. The native tool-window limitation remains
documented in the README. Future tools and memory access need their own
authorization policy and acceptance checks before enablement.
