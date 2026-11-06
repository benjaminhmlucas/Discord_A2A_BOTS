"""Typed ordinary settings with string-transported Discord snowflakes."""

SECTIONS = {
    "Discord": ("owner_id", "channel_id", "bot_ids"),
    "Providers": ("gemini_model", "codex_model", "codex_reasoning_effort"),
    "Connections": ("capabilities",),
    "Memory": ("memory",),
    "Access": ("enabled_bots", "allowed_user_ids", "allow_work"),
    "Limits": (
        "queue_capacity",
        "queue_wait_seconds",
        "request_seconds",
        "total_request_seconds",
        "send_seconds",
        "handoff_seconds",
        "max_turns",
        "history_messages",
        "history_chars",
        "user_requests_per_minute",
        "bot_requests_per_minute",
        "bot_requests_per_day",
    ),
}
ROLES = ("codex", "antigravity", "claude")


def field(value, kind="text"):
    return {"value": value if kind == "toggle" else str(value), "kind": kind}


def form(config, section):
    if section == "Discord":
        return {
            "owner_id": field(config["owner_id"], "id"),
            "channel_id": field(config["channel_id"], "id"),
            **{role + "_id": field(config["bot_ids"][role], "id") for role in ROLES},
        }
    if section == "Access":
        return {
            **{
                role: field(config["bot_ids"][role] in config["enabled_bots"], "toggle")
                for role in ROLES
            },
            "allowed_user_ids": field(", ".join(str(i) for i in config["allowed_user_ids"])),
            "allow_work": field(config.get("allow_work", False), "toggle"),
        }
    if section not in ("Providers", "Limits"):
        raise ValueError("This section has no typed form")
    return {
        key: field(config.get(key, ""), "integer" if section == "Limits" else "text")
        for key in SECTIONS[section]
    }


def integer(value):
    if not isinstance(value, str) or not value.isascii() or not value.isdigit():
        raise ValueError("Enter a numeric value")
    return int(value)


def edits(config, section, values):
    fields = form(config, section)
    if not isinstance(values, dict) or set(values) != set(fields):
        raise ValueError("Incomplete form")
    converted = {}
    for key, definition in fields.items():
        value = values[key]
        if definition["kind"] == "toggle":
            if type(value) is not bool:
                raise ValueError("Invalid switch value")
        else:
            if not isinstance(value, str) or len(value) > 4096 or "\0" in value:
                raise ValueError("Invalid field value")
            if definition["kind"] in ("id", "integer"):
                value = integer(value.strip())
        converted[key] = value
    if section == "Discord":
        return {
            "owner_id": converted["owner_id"],
            "channel_id": converted["channel_id"],
            "bot_ids": {role: converted[role + "_id"] for role in ROLES},
        }
    if section == "Access":
        return {
            "enabled_bots": [config["bot_ids"][role] for role in ROLES if converted[role]],
            "allowed_user_ids": [
                integer(value.strip()) for value in converted["allowed_user_ids"].split(",")
            ],
            "allow_work": converted["allow_work"],
        }
    return converted
