"""Create local settings with user-supplied IDs, without starting bots or storing secrets."""
import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def initialize(owner_id, channel_id, codex_id, antigravity_id, claude_id, root=ROOT):
    root = Path(root).resolve()
    values = (owner_id, channel_id, codex_id, antigravity_id, claude_id)
    if any(type(i) is not int or i <= 0 for i in values) or len(set(values)) != 5:
        raise ValueError('Supply five distinct positive numeric Discord IDs')
    names = ('bridge_config.json', 'local_settings.json', 'log_management.config.json', 'public_context.md')
    if any((root / name).exists() for name in names):
        raise FileExistsError('Local settings already exist; edit them directly instead of overwriting')
    config = json.loads((root / 'bridge_config.example.json').read_text(encoding='utf-8'))
    config.update(owner_id=owner_id, channel_id=channel_id, bot_ids={
        'codex': codex_id, 'antigravity': antigravity_id, 'claude': claude_id},
        enabled_bots=[codex_id, antigravity_id, claude_id], allowed_user_ids=[owner_id], allow_work=False)
    paths = [root / '.pm2', root / '.pm2/logs', root, root / 'AntigravityBot']
    for path in (*paths, root / 'runtime_state', root / 'chat_runtime', root / 'private_memory'):
        path.mkdir(parents=True, exist_ok=True)
    log_config = {
        'aggregate_limit_bytes': 1_000_000_000, 'cleanup_trigger_bytes': 900_000_000,
        'cleanup_target_bytes': 750_000_000, 'max_active_file_bytes': 10_485_760,
        'active_tail_bytes': 5_242_880, 'archive_max_age_days': 14, 'interval_seconds': 5,
        'state_file': str(root / 'log_management_state.json'),
        'scopes': [{'directory': str(path), 'include_transcripts': path == root} for path in paths],
    }
    (root / 'bridge_config.json').write_text(json.dumps(config, indent=2) + '\n', encoding='utf-8')
    (root / 'local_settings.json').write_text((root / 'local_settings.example.json').read_text(encoding='utf-8'), encoding='utf-8')
    (root / 'log_management.config.json').write_text(json.dumps(log_config, indent=2) + '\n', encoding='utf-8')
    (root / 'public_context.md').write_text((root / 'public_context.example.md').read_text(encoding='utf-8'), encoding='utf-8')
    (root / 'private_memory/MEMORY.md').write_text('# Local privacy markers\n\nNo private values configured.\n', encoding='utf-8')
    if json.loads((root / 'bridge_config.json').read_text()) != config:
        raise RuntimeError('Written configuration failed verification')
    return config


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ('owner-id', 'channel-id', 'codex-id', 'antigravity-id', 'claude-id'):
        parser.add_argument('--' + key, type=int, required=True)
    args = parser.parse_args()
    initialize(**vars(args))
    print('Local configuration created. Work is disabled; only the owner is allowed to request replies. No bot started.')


if __name__ == '__main__':
    main()
