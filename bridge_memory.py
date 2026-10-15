"""Explicit alias-based memory access; write proposals are data, never model actions."""

import asyncio
import json
import os
import re
import secrets
import time
from dataclasses import dataclass
from pathlib import Path, PureWindowsPath
from collections.abc import Callable
from typing import Any

from bridge_authorization import eligible_sender, owner_memory_dm
from bridge_http import CapabilityError
from bridge_privacy import private_values, redact_credentials
from bridge_memory_io import MemoryStore, digest

ALIAS = re.compile(r"[a-zA-Z][a-zA-Z0-9_-]{0,31}\Z")
RELATIVE = re.compile(r"(?:[a-zA-Z0-9_-]+/)*[a-zA-Z0-9_-]+\.md\Z")
HASH = re.compile(r"[a-f0-9]{64}\Z")
TOKEN = re.compile(r"[a-f0-9]{32}\Z")
PROTECTED = {
    "agents.md",
    "static_procedures.md",
    "memory.md",
    "live_state.md",
    "handoff.md",
    "session_log.md",
    "bot_registry.md",
}
MAX_BYTES = 65536
MAX_TEXT = 12000
TTL = 120


def require(value: object) -> None:
    if not value:
        raise ValueError("Invalid memory configuration")


@dataclass(frozen=True)
class MemoryRequest:
    name: str
    mode: str
    alias: str
    arguments: dict[str, Any]
    owner: int
    bot: int

    @property
    def private(self) -> bool:
        return self.mode != "read"


@dataclass(frozen=True)
class Proposal:
    alias: str
    expected: str
    after: bytes
    owner: int
    bot: int
    expires: float


class MemoryAccess:
    def __init__(self, config: dict[str, Any], log: Callable[[str], None]) -> None:
        self.config, self.log = config, log
        data = config.get("memory", {"enabled": False})
        require(isinstance(data, dict) and type(data.get("enabled")) is bool)
        require(set(data) <= {"enabled", "root", "files", "user_ids", "bot_ids", "credential_env"})
        self.enabled = data["enabled"]
        root = data.get("root")
        # Local disks only: reject UNC/device roots in either slash form (\\host or //host).
        require(
            root is None
            or (
                isinstance(root, str)
                and Path(root).is_absolute()
                and not PureWindowsPath(root).drive.startswith("\\\\")
            )
        )
        require(not self.enabled or root is not None)
        self.root = Path(root) if root else None
        self.files: dict[str, dict[str, Any]] = data.get("files", {})
        require(isinstance(self.files, dict) and len(self.files) <= 32)
        paths = set()
        for alias, definition in self.files.items():
            require(isinstance(alias, str) and ALIAS.fullmatch(alias))
            require(
                isinstance(definition, dict)
                and set(definition) == {"path", "public", "private", "write"}
            )
            path = definition["path"]
            require(isinstance(path, str) and RELATIVE.fullmatch(path))
            require(
                all(
                    part.split(".")[0].upper()
                    not in {
                        "CON",
                        "PRN",
                        "AUX",
                        "NUL",
                        *(f"COM{i}" for i in range(1, 10)),
                        *(f"LPT{i}" for i in range(1, 10)),
                    }
                    for part in path.split("/")
                )
            )
            require(path.casefold() not in paths)
            paths.add(path.casefold())
            require(type(definition["public"]) is bool and type(definition["private"]) is bool)
            require(definition["write"] in (None, "replace", "append"))
            require(
                definition["write"] is None
                or (definition["private"] and Path(path).name.casefold() not in PROTECTED)
            )
        self.users = data.get("user_ids", [])
        self.bots = data.get("bot_ids", [])
        for values, allowed in (
            (self.users, config["allowed_user_ids"]),
            (self.bots, config["enabled_bots"]),
        ):
            require(
                isinstance(values, list) and all(type(i) is int and i in allowed for i in values)
            )
        require(not self.enabled or bool(self.bots))
        self.credential_env = data.get("credential_env", [])
        require(isinstance(self.credential_env, list) and len(self.credential_env) <= 32)
        require(
            all(
                isinstance(name, str) and re.fullmatch(r"[a-zA-Z_][a-zA-Z0-9_]{0,63}", name)
                for name in self.credential_env
            )
        )
        self.proposals: dict[str, Proposal] = {}
        self.store = MemoryStore(self.root, self.files)

    def credentials(self) -> set[str]:
        return {os.environ[name] for name in self.credential_env if os.environ.get(name)}

    def authorize(self, text: str, message: Any, bot: int) -> MemoryRequest | None:
        command = re.match(r"^/memory(?:\s|$)", text, re.I)
        if not command or message.author.bot is True:
            return None
        if not (
            self.enabled
            and type(bot) is int
            and (
                eligible_sender(message, bot, self.config)
                or owner_memory_dm(message, bot, self.config)
            )
            and message.author.bot is False
            and bot in self.bots
        ):
            raise CapabilityError("Memory access denied")
        mode, _, payload = text[command.end() :].strip().partition(" ")
        mode = mode.lower()
        alias, _, rest = payload.strip().partition(" ")
        if mode in ("commit", "recover"):
            if not TOKEN.fullmatch(alias) or rest:
                raise CapabilityError("Invalid memory confirmation")
            arguments = {"token": alias}
            alias = ""
        elif mode == "status":
            if payload:
                raise CapabilityError("Invalid memory status")
            arguments = {}
            alias = ""
        else:
            if mode not in ("read", "private", "propose") or alias not in self.files:
                raise CapabilityError("Unknown memory operation")
            definition = self.files[alias]
            if mode == "read" and (not definition["public"] or message.author.id not in self.users):
                raise CapabilityError("Public memory access denied")
            if mode != "read" and not definition["private"]:
                raise CapabilityError("Private memory access denied")
            arguments = {}
            if mode == "propose":
                expected, _, raw = rest.partition(" ")
                try:
                    values = json.loads(raw)
                except (ValueError, RecursionError):
                    raise CapabilityError("Invalid memory proposal") from None
                if not (
                    definition["write"]
                    and HASH.fullmatch(expected)
                    and isinstance(values, dict)
                    and set(values) == {"text"}
                    and isinstance(values["text"], str)
                    and len(values["text"]) <= MAX_TEXT
                ):
                    raise CapabilityError("Invalid memory proposal")
                arguments = {"expected": expected, "text": values["text"]}
            elif rest:
                raise CapabilityError("Invalid memory arguments")
        if mode != "read" and message.author.id != self.config["owner_id"]:
            raise CapabilityError("Only the owner can access private memory")
        if mode in ("propose", "commit", "status", "recover") and not owner_memory_dm(
            message, bot, self.config
        ):
            raise CapabilityError("Submit memory writes in the owner's private DM")
        return MemoryRequest("memory", mode, alias, arguments, message.author.id, bot)

    def snapshot(self) -> tuple[dict[str, bytes], tuple[str, ...]]:
        files: dict[str, bytes] = {}
        values: list[str] = []
        for alias, definition in self.files.items():
            data = self.store.read(definition["path"])
            files[alias] = data
            values.extend(private_values(data.decode("utf-8-sig")))
        for text in self.store.backup_texts():
            values.extend(private_values(text))
        return files, tuple(sorted(set(values), key=len, reverse=True))

    def public_text(self, text: str, values: tuple[str, ...], privacy: Any) -> str:
        return str(privacy._filter(text, (*privacy.refresh(), *values)))

    async def execute(
        self, request: MemoryRequest, privacy: Any, redact: Callable[[str], str]
    ) -> str:
        # This dispatcher is only called after the runtime verified private delivery.
        outcome = "failed"
        try:
            if self.root != Path(privacy.memory_dir):
                raise CapabilityError("Memory root must match the privacy source")
            self.proposals = {
                key: value
                for key, value in self.proposals.items()
                if value.expires > time.monotonic()
            }
            if request.mode in ("status", "recover"):
                if request.mode == "status":
                    result = await asyncio.to_thread(self.store.status)
                else:
                    task = asyncio.create_task(
                        asyncio.to_thread(self.store.recover, request.arguments["token"])
                    )
                    try:
                        result = await asyncio.shield(task)
                    except asyncio.CancelledError:
                        await task
                        raise
            elif request.mode == "commit":
                proposal = self.proposals.pop(request.arguments["token"], None)
                if proposal is None or (proposal.owner, proposal.bot) != (
                    request.owner,
                    request.bot,
                ):
                    raise CapabilityError("Memory confirmation unavailable")
                # Atomic file work completes even if the Discord request is cancelled.
                task = asyncio.create_task(asyncio.to_thread(self.commit, proposal))
                try:
                    result = await asyncio.shield(task)
                except asyncio.CancelledError:
                    await task
                    raise
            else:
                if request.mode == "propose":
                    await asyncio.to_thread(self.store.write_allowed)
                files, values = await asyncio.to_thread(self.snapshot)
                data = files[request.alias]
                text = data.decode("utf-8-sig")
                # Redact whole values before truncating so a cut cannot expose a prefix.
                if request.mode == "read":
                    # Mask configured credentials first: PRIVATE-value filtering could
                    # otherwise split a credential so its exact match no longer applies.
                    # A direct bridge reply, never model input: show filtered text as written.
                    text = await asyncio.to_thread(self.public_text, redact(text), values, privacy)
                    result = (
                        f"Memory {request.alias} (approved public excerpt):\n"
                        + redact(text)[:MAX_TEXT]
                    )
                elif request.mode == "private":
                    result = (
                        f"Memory {request.alias}; revision {digest(data)}\n"
                        + redact_credentials(redact(text))[:MAX_TEXT]
                    )
                else:
                    if len(self.proposals) >= 16:
                        raise CapabilityError("Memory proposal limit reached")
                    if digest(data) != request.arguments["expected"]:
                        raise CapabilityError("Memory revision conflict")
                    after = request.arguments["text"].encode("utf-8")
                    if self.files[request.alias]["write"] == "append":
                        after = data + after
                    if len(after) > MAX_BYTES:
                        raise CapabilityError("Memory file too large")
                    private_values(after.decode("utf-8-sig"))
                    token = secrets.token_hex(16)
                    self.proposals[token] = Proposal(
                        request.alias,
                        digest(data),
                        after,
                        request.owner,
                        request.bot,
                        time.monotonic() + TTL,
                    )
                    result = (
                        f"Memory proposal {request.alias}; {self.files[request.alias]['write']}; "
                        f"revision {digest(data)} -> {digest(after)}; expires in {TTL}s.\n"
                        f"Confirm this exact change with /memory commit {token}\nPreview:\n"
                        + redact_credentials(redact(request.arguments["text"]))
                    )
            outcome = "completed"
            return result
        except asyncio.CancelledError:
            outcome = "cancelled"
            raise
        finally:
            self.log(f"Memory {request.mode} authorization=allowed outcome={outcome}")

    def commit(self, proposal: Proposal) -> str:
        return self.store.commit(proposal.alias, proposal.expected, proposal.after)
