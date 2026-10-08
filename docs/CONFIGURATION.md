# Configuration

Run `initialize.py` with your own IDs. It refuses to overwrite existing local settings, stores no credentials and starts no processes.

| File | Purpose | Commit? |
|---|---|---|
| `bridge_config.example.json` | Zero IDs and empty roster; reference defaults | Yes |
| `bridge_config.json` | Your channel, owner, bot identities and trusted-user allowlist | No |
| `local_settings.example.json` | Relative Node/CLI/privacy-directory examples | Yes |
| `local_settings.json` | Machine-specific runtime paths | No |
| `public_context.example.md` | Fictional example context | Yes |
| `public_context.md` | Locally approved public provider context | No |
| `.env.example` | Credential variable names with blank values | Yes |
| `.env` and authentication stores | Actual credentials | No |
| `log_management.config.json` | Resolved local log scopes and retention thresholds | No |
| `.pm2/`, `runtime_state/`, `private_memory/` | Process state, transactions, local context and logs | No |

`bot_ids` maps `codex`, `antigravity` and `claude` to distinct Discord application/user IDs. `enabled_bots` defines participation order as a subset of those IDs. Restart bots after changing identities or roster. Initialization enables all three; tokens must belong to the corresponding identities.

`allowed_user_ids` accepts trusted numeric Discord users. An empty list is invalid. `owner_id` identifies the single local-work owner, while `allow_work` defaults to false. The owner must also be allowlisted for requests.

`BOTBRIDGE_CONFIG_FILE` is a configuration-path override used by offline tests. Do not set it in production unless deliberately selecting another local configuration. It does not override the separate local settings file.

The default model entry for Codex is blank so the CLI uses its default. Configure a model available to your account if needed. The Gemini model and provider CLI versions are documented starting points; changing them requires verification with your account.

The local privacy-marker directory is not automatically added to public context. Keep it outside Git. Marked values are literal redaction rules, not a general classification system.
