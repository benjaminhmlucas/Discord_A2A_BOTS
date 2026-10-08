# Architecture

Each identity launcher selects its configured bot ID and calls the shared Discord consumer. Tokens are loaded only at runtime and the connected identity is checked against the configured ID.

The consumer checks the channel and numeric authorization, captures the original request and earlier history, redacts marked private values, and waits for a bounded queue slot. It calls the selected provider under a deadline, filters public output, and sends replies with restricted Discord mentions.

For a discussion, SQLite stores content-free transaction metadata. The next connected participant gets a fresh one-use handoff token. Duplicate or forged handoffs cannot advance the same transaction. Completion, expiry and failure close the chain.

Codex and Claude run isolated CLI subprocesses; Gemini uses bounded HTTP requests. Windows process protection prevents duplicate identities in the same checkout and terminates inherited descendants when a bot process exits.

PM2 supervises the bots, aggregate log manager and independent health monitor. Direct logs rotate before their byte limit. PM2 output rotates through pm2-logrotate; aggregate cleanup covers only configured top-level log scopes. Health includes connected identities, heartbeat freshness, provider failures, log-manager freshness, the Boolean parser fix and disk headroom.

This template deliberately excludes legacy listeners, unrelated integrations, nightly posting tasks, live diagnostics, personal memory, historical logs and repair backups.
