"""Shared identities and Discord chunking; routing lives in bridge_runtime.py.
Known identities are not the enabled roster; bridge_config.json owns that.
"""
from bridge_settings import read_identity_config, local_path

_identity = read_identity_config()
BOT_BRIDGE_CHANNEL_ID = _identity['channel_id']
CODEX_APP_ID = _identity['bot_ids']['codex']
ANTIGRAVITY_APP_ID = _identity['bot_ids']['antigravity']
CLAUDE_BOT_APP_ID = _identity['bot_ids']['claude']
ALL_BOT_IDS = (CODEX_APP_ID, ANTIGRAVITY_APP_ID, CLAUDE_BOT_APP_ID)
OWNER_DISCORD_USER_ID = _identity['owner_id']
MEMORY_DIR = str(local_path('memory_dir'))


def chunk_message(text, limit=1900):
    if len(text) <= limit:
        return [text]
    chunks = []
    remaining = text
    while remaining:
        if len(remaining) <= limit:
            chunks.append(remaining.strip())
            break
        cut = remaining.rfind('\n', 0, limit)
        if cut < 200:
            cut = limit
        chunks.append(remaining[:cut].strip())
        remaining = remaining[cut:].strip()
    return [c for c in chunks if c]
