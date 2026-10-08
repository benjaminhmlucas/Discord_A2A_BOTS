"""Read-only preflight. Does not start bots, post messages, or print secrets."""
import importlib
import json
import sys
from pathlib import Path


from bridge_privacy import Privacy
from bridge_providers import NODE, CODEX, CLAUDE, MEMORY, secret
from bridge_runtime import ROOT, load_config
from botbridge_common import CODEX_APP_ID, ANTIGRAVITY_APP_ID, CLAUDE_BOT_APP_ID


def require_file(path):
    if not Path(path).is_file():
        raise RuntimeError('Required runtime/context file is unavailable')


def main():
    config = load_config()
    Privacy(MEMORY).refresh()
    require_file(NODE)
    if CODEX_APP_ID in config['enabled_bots']:
        require_file(CODEX)
    for name in ('discord', 'aiohttp', 'bridge_windows'):
        importlib.import_module(name)
    credentials = {
        CODEX_APP_ID: ('CODEXBOT_TOKEN',),
        ANTIGRAVITY_APP_ID: ('ANTIGRAVITYBOT_TOKEN', 'GEMINI_API_KEY'),
        CLAUDE_BOT_APP_ID: ('CLAUDEBOT_TOKEN', 'CLAUDE_CODE_OAUTH_TOKEN'),
    }
    for bot in config['enabled_bots']:
        for name in credentials[bot]:
            secret(name)
    if CLAUDE_BOT_APP_ID in config['enabled_bots']:
        require_file(CLAUDE)
    require_file(ROOT / config['public_context_file'])
    print(json.dumps({'preflight': 'passed', 'python': sys.version.split()[0],
                      'enabled_bots': config['enabled_bots']}))


if __name__ == '__main__':
    main()
