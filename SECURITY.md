# Security

## Boundaries

- Credentials come from the launching process environment or Windows User environment. Names in `.env.example` are documentation, not values.
- Only the configured channel is accepted. Human requests require a numeric trusted-user allowlist; initialization allows only the owner.
- `/work` is disabled by default. When deliberately enabled, only the configured numeric owner can authorize it, only CodexBot runs it, and delivery must work privately before the provider runs. Display names, quoted text and other bots do not authorize local work.
- Public provider calls disable local tools. Codex uses a read-only sandbox with tools and inherited configuration disabled; Claude disables tools, inherited settings, MCP, skills, Chrome and session persistence. Gemini receives curated input without local execution capability.
- Bot-to-bot handoffs require a live SQLite transaction, expected sender and recipient, one-use token, matching channel, bounded turn count and expiry. Merely copying visible marker syntax does not authorize a handoff.
- Input and public output redact literal private-marker values and some credential formats. Private markers use `<!--PRIVATE:START-->` and `<!--PRIVATE:END-->` in local Markdown files.
- Request queues, deadlines, provider retries and reply sizes are bounded. PM2 log rotation and aggregate cleanup manage log growth.

## Limits

This is a source template, not a complete security audit or guarantee. Literal redaction does not reliably detect paraphrases or all secrets. Avoid placing sensitive information in public context, Discord history, attachments or prompts. Prompt wording alone is not an authorization boundary.

The local-work feature gives the provider access to its configured memory workspace. Keep it disabled unless you deliberately accept that capability and trust the owner account. A compromised owner account may issue authenticated requests.

Trusted users can consume provider quotas. Persistent per-user and per-bot rolling request limits bound provider attempts, including discussion turns, but do not measure tokens or currency. Keep the allowlist small, configure provider-side spend limits and restrict the bridge channel. A public repository does not need a public Discord invite.

Unreadable privacy folders or files stop submission; links and reparse points are rejected. Tool-enabled work excludes channel history, display names, attachments and curated public context. Unauthorized humans are ignored before command-denial replies. See [security controls and review policy](docs/security-review.md) for CI gates, request-limit defaults and recovery behavior.

The 1 GB budget is retention enforced by periodic cleanup, not a filesystem quota. Temporary overshoot is possible; disk monitoring and bounded writers remain necessary. The log manager only scans configured top-level log scopes and never recursively searches unrelated files.

Protect your machine, authentication stores, local configuration, process dumps and runtime files with appropriate local account permissions. Do not commit or attach them to issues. Review third-party dependency upgrades and CLI behavior before deploying them.

## Reporting

Use GitHub private vulnerability reporting if enabled for the repository. Enable it in repository settings before inviting security reports. Do not post exploitable details, credentials or private transcripts publicly. If a credential is exposed, revoke or rotate it first; removing the current file alone does not remove copies or Git history.
