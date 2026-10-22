"""Local configuration, kept outside Git. Examples contain no real identities."""

import json
import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def config_path(root=ROOT):
    root = Path(root)
    override = os.environ.get("BOTBRIDGE_CONFIG_FILE") if root.resolve() == ROOT else None
    return Path(override) if override else root / "bridge_config.json"


def read_identity_config():
    path = config_path()
    if not path.is_file():
        raise RuntimeError(
            "Run initialize.py to create ignored local configuration before launching bots"
        )
    config = json.loads(path.read_text(encoding="utf-8"))
    identity_ids(config)
    return config


def local_settings():
    path = ROOT / "local_settings.json"
    if not path.is_file():
        path = ROOT / "local_settings.example.json"
    return json.loads(path.read_text(encoding="utf-8"))


def local_path(key):
    path = Path(local_settings()[key]).expanduser()
    return path if path.is_absolute() else ROOT / path


def identity_ids(config):
    ids = [config["bot_ids"][key] for key in ("codex", "antigravity", "claude")]
    if len(set(ids)) != 3 or any(type(i) is not int or i <= 0 for i in ids):
        raise ValueError("Configure three distinct numeric bot IDs")
    return ids


def validate_runtime_config(config, launch_ids=None):
    """One side-effect-free runtime/CLI validator; capabilities validate separately."""
    config = dict(config)
    ids = identity_ids(config)
    identities = set(ids) if launch_ids is None else set(launch_ids)
    for key, default in {
        "user_requests_per_minute": 6,
        "bot_requests_per_minute": 30,
        "bot_requests_per_day": 200,
    }.items():
        config.setdefault(key, default)
        if type(config[key]) is not int or not 1 <= config[key] <= 10000:
            raise ValueError(f"Invalid request limit: {key}")
    if type(config.get("allow_work", False)) is not bool:
        raise ValueError("allow_work must be a Boolean")
    if set(ids) != identities:
        raise ValueError(
            "Bot identities differ from the launch configuration; restart after changes"
        )
    if not isinstance(config["owner_id"], int) or config["owner_id"] <= 0:
        raise ValueError("Configure a numeric owner ID")
    if not isinstance(config["channel_id"], int) or config["channel_id"] <= 0:
        raise ValueError("Configure a numeric channel ID")
    if not config.get("allowed_user_ids") or any(
        not isinstance(i, int) or i <= 0 for i in config["allowed_user_ids"]
    ):
        raise ValueError("Configure a nonempty trusted-user allowlist")
    ids = config["enabled_bots"]
    if len(ids) != len(set(ids)) or not ids or any(i not in identities for i in ids):
        raise ValueError("Invalid enabled roster")
    for key in (
        "queue_capacity",
        "queue_wait_seconds",
        "request_seconds",
        "total_request_seconds",
        "send_seconds",
        "handoff_seconds",
        "history_messages",
        "history_chars",
    ):
        if not isinstance(config[key], int) or config[key] <= 0:
            raise ValueError(f"Invalid setting: {key}")
    if not 1 <= config["max_turns"] <= 15:
        raise ValueError("Invalid maximum turns")
    return config
