"""Local configuration, kept outside Git. Examples contain no real identities."""
import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def config_path(root=ROOT):
    root = Path(root)
    override = os.environ.get('BOTBRIDGE_CONFIG_FILE') if root.resolve() == ROOT else None
    return Path(override) if override else root / 'bridge_config.json'


def read_identity_config():
    path = config_path()
    if not path.is_file():
        raise RuntimeError('Run initialize.py to create ignored local configuration before launching bots')
    config = json.loads(path.read_text(encoding='utf-8'))
    ids = [config['bot_ids'][key] for key in ('codex', 'antigravity', 'claude')]
    if len(set(ids)) != 3 or any(type(i) is not int or i <= 0 for i in ids):
        raise ValueError('Configure three distinct numeric bot IDs')
    return config


def local_settings():
    path = ROOT / 'local_settings.json'
    if not path.is_file():
        path = ROOT / 'local_settings.example.json'
    return json.loads(path.read_text(encoding='utf-8'))


def local_path(key):
    path = Path(local_settings()[key]).expanduser()
    return path if path.is_absolute() else ROOT / path
