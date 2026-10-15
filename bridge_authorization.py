"""Decide capabilities from Discord transport metadata, never model or context text."""

import re
from typing import Any


class WorkDenied(ValueError):
    """A static refusal that is safe to send without revealing request contents."""


def eligible_sender(message: Any, bot_id: int, config: dict[str, Any]) -> bool:
    # Discord supplies these fields; content/display names/quoted IDs do not.
    return (
        type(message.author.id) is int
        and type(message.author.bot) is bool
        and type(message.channel.id) is int
        and message.channel.id == config["channel_id"]
        and not message.webhook_id
        and message.author.id != bot_id
        and bot_id in config["enabled_bots"]
        and (message.author.bot or message.author.id in config["allowed_user_ids"])
    )


def authorize_work(
    text: str, message: Any, bot_id: int, codex_id: int, config: dict[str, Any]
) -> bool:
    """Called only for an eligible sender, after authenticating any bot handoff."""
    if not re.match(r"^/work(?:\s|$)", text, re.I):
        return False
    if message.author.bot or message.author.id != config["owner_id"]:
        raise WorkDenied("Bridge: only the owner can authorize /work.")
    if bot_id != codex_id:
        raise WorkDenied("Bridge: use CodexBot for /work; this bot provides chat.")
    if config.get("allow_work", False) is not True:
        raise WorkDenied("Bridge: local work is disabled in this installation.")
    return True
