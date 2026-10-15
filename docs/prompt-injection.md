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
YAML tags, non-ASCII text and malformed configuration. Only the CodeQL analysis job may publish
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
failure; within the inspected workflow fields, the checker cannot be retargeted
through step environment or defaults (earlier candidate steps can still alter it;
see below). The two-OS test matrix must actually use `matrix.os` as its runner.
Linked/reparse-point workflow ancestors and leaves are rejected before parsing. These are checks of the
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

| AC (issue #16 wording) | Code and verification |
| --- | --- |
| Public dispatch and data-only workflow checks demonstrate that untrusted content cannot grant a denied capability, invoke a privileged work provider, access private context or publish a literal synthetic private value | `bridge_authorization.py`, real `Bridge` dispatch/privacy and `check_ci_policy.py`; `test_untrusted_artifacts_cannot_change_actual_public_dispatch` asserts no work-mode provider call, no private value in the prompt or output and unchanged private files |
| Tests cover PR metadata/diffs/docs, forged owner identity/approval, tool/web results, cross-user access and durable replay attempts | `tests/fixtures/prompt_injection.json` (PR, document, Discord quote, web, MCP and tool sources), `test_prompt_injection.py` (forged/lookalike identity, cross-user `/work`, restart and refusal replay, bot handoffs), `test_ci_injection.py` |
| Tests exercise authorization/tool boundaries rather than depending on a model recognizing particular malicious wording | Numeric transport metadata and exact work enablement decide capabilities; the test provider returns hostile text that is never interpreted |
| The workflow checker rejects excessive privileges, production job contexts, unsafe checkout credentials and untrusted expressions; hosted PR tests use synthetic configuration without production secrets | `check_ci_policy.py` with real mutated YAML and real checker CLI runs in `test_ci_injection.py`, each asserting its exact rejection code; workflows use only `contents: read` (CodeQL adds `security-events: write`) and no secrets |
| Negative cases fail closed while benign public requests and explicitly authorized private work retain expected behavior | Public attack/benign requests, authorized private work, private-delivery denial and replay tests in `test_prompt_injection.py`; a valid workflow passes the real checker CLI |
| Required tests, exact 100% Python statement/branch and Node line/branch/function coverage, audits and CodeQL pass on the implementation head, with evidence in the linked PR | Required hosted CI: exact Python statement/branch gate, Node line/branch/function gate, audits and CodeQL; per-head results are in the PR description |
| Documentation and PR description map the ACs to code/tests and distinguish deterministic boundary enforcement from best-effort detection, candidate-controlled CI and existing owner-work risks | This document (including Limits), `SECURITY.md` and the PR description |
| Adversarial agent review has no outstanding actionable findings; existing independent GitHub approval and protected merge requirements remain enforced | Review outcome is recorded in the PR; repository rules and the five required check names are unchanged |

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
documented in the README. Tools and memory access each have their own authorization
policy ([scoped capabilities](scoped-capabilities.md), [scoped memory](scoped-memory.md))
and need acceptance checks before enablement.
