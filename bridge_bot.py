"""Identity-specific launchers delegate to this one tested consumer."""
from datetime import datetime
from pathlib import Path

import discord

from botbridge_logging import append_line
from bridge_providers import Gemini, claude, codex, secret
from bridge_runtime import Bridge, ROOT, dispatch, load_config
from bridge_windows import protect_process
from botbridge_common import CODEX_APP_ID, ANTIGRAVITY_APP_ID, CLAUDE_BOT_APP_ID

TOKENS = {CODEX_APP_ID: 'CODEXBOT_TOKEN', ANTIGRAVITY_APP_ID: 'ANTIGRAVITYBOT_TOKEN',
          CLAUDE_BOT_APP_ID: 'CLAUDEBOT_TOKEN'}
LOGS = {CODEX_APP_ID: 'codex_bridge_debug.log',
        ANTIGRAVITY_APP_ID: 'AntigravityBot/antigravitybot_debug.log',
        CLAUDE_BOT_APP_ID: 'bridge_debug.log'}


def main(bot_id):
    config = load_config()
    if bot_id not in config['enabled_bots']:
        raise SystemExit(75)
    protect_process(ROOT / f'bot_{bot_id}.lock')
    token = secret(TOKENS[bot_id])
    intents = discord.Intents.default()
    intents.message_content = True
    client = discord.Client(intents=intents, allowed_mentions=discord.AllowedMentions.none())

    def log(text):
        line = f'[{datetime.now():%Y-%m-%d %H:%M:%S}] {text}'
        print(line, flush=True)
        append_line(Path(ROOT) / LOGS[bot_id], line)

    provider = codex if bot_id == CODEX_APP_ID else (
        Gemini(config['gemini_model']) if bot_id == ANTIGRAVITY_APP_ID else claude)
    bridge = Bridge(client, bot_id, provider, log)

    @client.event
    async def on_ready():
        await bridge.ready()

    @client.event
    async def on_message(message):
        await dispatch(bridge, message)

    @client.event
    async def on_error(event, *args, **kwargs):
        log(f'Discord event error: {event}')

    try:
        client.run(token)
    except discord.LoginFailure:
        log('FATAL: Discord credential rejected; restart is disabled until repaired.')
        raise SystemExit(78)
    finally:
        bridge.health['ready'] = False
        bridge.health['timestamp'] = 0
        path = ROOT / 'runtime_state' / f'health_{bot_id}.json'
        import json
        path.write_text(json.dumps(bridge.health), encoding='utf-8')
