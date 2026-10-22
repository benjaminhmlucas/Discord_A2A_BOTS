"""Versioned operator-owned MCP profiles and shared bounded connection lifecycle."""

import asyncio
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator
import copy
import hashlib
import json
import os
from pathlib import Path
import re
from typing import Any

from bridge_http import CapabilityError, SafeHTTP, checked_url
from bridge_mcp import MCPClient, LEGACY_PROTOCOL, PROTOCOL
from bridge_mcp_stdio import StdioClient
from bridge_mcp_schema import JSON_ARGUMENT_BYTES

NAME = re.compile(r"[a-zA-Z][a-zA-Z0-9_.-]{0,63}\Z")
ENV_NAME = re.compile(r"BOTBRIDGE_MCP_[A-Z][A-Z0-9_]{0,49}\Z")
ENV_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
SECRET_KEY = re.compile(r"TOKEN|SECRET|PASSWORD|CREDENTIAL|AUTH|COOKIE|API_KEY", re.I)


def require(condition: object) -> None:
    if not condition:
        raise ValueError("Invalid MCP connection configuration")


def checked_profile(profile: Any, http: SafeHTTP) -> None:
    require(isinstance(profile, dict))
    if profile.get("transport") == "http":
        require(set(profile) == {"transport", "endpoint", "protocol", "credential_env"})
        checked_url(profile["endpoint"], http.internal_origins)
        require(profile["protocol"] in (PROTOCOL, LEGACY_PROTOCOL))
        ref = profile["credential_env"]
        require(ref is None or isinstance(ref, str) and ENV_NAME.fullmatch(ref))
    else:
        require(profile.get("transport") == "stdio")
        require(
            set(profile)
            == {"transport", "command", "arguments", "cwd", "environment", "credential_env"}
        )
        for key in ("command", "cwd"):
            require(
                isinstance(profile[key], str)
                and len(profile[key]) <= 1024
                and "\0" not in profile[key]
            )
            require(Path(profile[key]).is_absolute())
        require(Path(profile["command"]).suffix.lower() not in (".bat", ".cmd", ".ps1", ".sh"))
        args = profile["arguments"]
        require(isinstance(args, list) and len(args) <= 32)
        require(all(isinstance(a, str) and len(a) <= 2048 and "\0" not in a for a in args))
        for key in ("environment", "credential_env"):
            env = profile[key]
            require(isinstance(env, dict) and len(env) <= 32)
            require(all(isinstance(k, str) and ENV_KEY.fullmatch(k) for k in env))
            require(
                all(isinstance(v, str) and len(v) <= 2048 and "\0" not in v for v in env.values())
            )
        require(not set(profile["environment"]) & set(profile["credential_env"]))
        keys = [k.casefold() for group in ("environment", "credential_env") for k in profile[group]]
        require(len(keys) == len(set(keys)))
        require(not any(SECRET_KEY.search(k) for k in profile["environment"]))
        require(all(ENV_NAME.fullmatch(v) for v in profile["credential_env"].values()))
    require(len(json.dumps(profile).encode("utf-8")) <= 16384)


class Registry:
    def __init__(self, data: Any, http: SafeHTTP) -> None:
        require(isinstance(data, dict) and set(data) == {"version", "servers"})
        require(type(data["version"]) is int and data["version"] == 1)
        profiles = data["servers"]
        require(isinstance(profiles, dict) and len(profiles) <= 32)
        for name, profile in profiles.items():
            require(isinstance(name, str) and NAME.fullmatch(name))
            checked_profile(profile, http)
        self._data = copy.deepcopy(data)
        self.http = http

    def export(self) -> dict[str, Any]:
        return copy.deepcopy(self._data)

    def profile(self, name: str) -> dict[str, Any]:
        if name not in self._data["servers"]:
            raise CapabilityError("Unknown MCP connection")
        return copy.deepcopy(self._data["servers"][name])

    def changed(self, action: str, name: str, profile: Any = None) -> "Registry":
        data = self.export()
        exists = name in data["servers"]
        require(action in ("add", "edit", "remove"))
        require(not exists if action == "add" else exists)
        if action == "remove":
            del data["servers"][name]
        else:
            data["servers"][name] = profile
        return Registry(data, self.http)


def migrated(config: dict[str, Any]) -> dict[str, Any]:
    """Explicit copy-only conversion; original remains a rollback snapshot."""
    result = copy.deepcopy(config)
    data = result.setdefault("capabilities", {"enabled": False})
    registry = data.setdefault("connections", {"version": 1, "servers": {}})
    servers = registry["servers"]
    for alias, tool in data.get("tools", {}).items():
        if "connection" in tool:
            continue
        name = (
            "legacy." + alias
            if len(alias) <= 57
            else "legacy." + hashlib.sha256(alias.encode()).hexdigest()[:32]
        )
        require(name not in servers)
        servers[name] = {
            "transport": "http",
            **{k: tool[k] for k in ("endpoint", "protocol", "credential_env")},
        }
        tool["connection"] = name
        # Preserve the exact legacy scalar policy, including integer string-length limits.
        for key in ("endpoint", "protocol", "credential_env"):
            del tool[key]
    return result


class ConnectionManager:
    def __init__(self, registry: Registry) -> None:
        self.registry = registry
        self._active: dict[str, MCPClient] = {}
        self._locks: dict[str, asyncio.Lock] = {}
        self._states: dict[str, str] = {}
        self._closing: dict[str, asyncio.Task[None]] = {}
        self._slots = asyncio.Semaphore(4)

    def status(self, name: str) -> dict[str, Any]:
        profile = self.registry.profile(name)
        client = self._active.get(name)
        connected = client is not None and self._states.get(name) == "connected"
        outcome = self._states.get(name, "not_tested")
        if (
            isinstance(client, StdioClient)
            and client.process is not None
            and client.process.returncode is not None
        ):
            connected = False
            outcome = "exited"
        return {
            "id": name,
            "transport": profile["transport"],
            "connected": connected,
            "outcome": outcome,
        }

    async def connect(self, name: str, credentials: set[str]) -> MCPClient:
        profile = self.registry.profile(name)
        if name in self._active:
            raise CapabilityError("MCP connection already in use")
        client: MCPClient
        if profile["transport"] == "stdio":
            client = StdioClient(profile, credentials)
        else:
            ref = profile["credential_env"]
            credential = os.environ.get(ref) if ref else None
            if ref and not credential:
                raise CapabilityError("MCP credential unavailable")
            if credential:
                credentials.add(credential)
                if any(ord(c) < 33 or ord(c) > 126 for c in credential):
                    raise CapabilityError("Invalid MCP credential")
            client = MCPClient(
                self.registry.http,
                profile["endpoint"],
                credential,
                protocol=profile["protocol"],
                secrets=credentials,
            )
        self._active[name] = client
        self._states[name] = "connecting"
        try:
            async with asyncio.timeout(self.registry.http.seconds):
                await client.connect()
            self._states[name] = "connected"
            return client
        except BaseException:
            self._states[name] = "failed"
            await self.disconnect(name)
            raise

    async def disconnect(self, name: str) -> None:
        self.registry.profile(name)
        client = self._active.get(name)
        if client is not None:
            task = self._closing.get(name)
            if task is None:
                task = asyncio.create_task(self.close_owned(name, client))
                self._closing[name] = task
                task.add_done_callback(lambda done: self.closed(name, done))
            await asyncio.shield(task)

    def closed(self, name: str, task: asyncio.Task[None]) -> None:
        self._closing.pop(name, None)
        if not task.cancelled():
            task.exception()  # Retrieve failures even if the caller was cancelled.

    async def close_owned(self, name: str, client: MCPClient) -> None:
        try:
            async with asyncio.timeout(2):
                await client.disconnect()
            self._active.pop(name, None)
            if self._states.get(name) == "connected":
                self._states[name] = "disconnected"
        except BaseException:
            self._states[name] = "cleanup_failed"
            raise  # Keep the owner reference available for an explicit retry.

    @asynccontextmanager
    async def session(self, name: str, credentials: set[str]) -> AsyncIterator[MCPClient]:
        self.registry.profile(name)
        lock = self._locks.setdefault(name, asyncio.Lock())
        async with asyncio.timeout(self.registry.http.seconds), self._slots, lock:
            client = None
            try:
                client = await self.connect(name, credentials)
                yield client
                self._states[name] = "completed"
            except BaseException:
                if client is not None or name not in self._active:
                    self._states[name] = "failed"
                raise
            finally:
                if client is not None:
                    await self.disconnect(name)

    async def discover(
        self, name: str, credentials: set[str] | None = None
    ) -> list[dict[str, Any]]:
        async with self.session(name, set() if credentials is None else credentials) as client:
            return await client.discover()

    async def call(
        self,
        name: str,
        tool: str,
        arguments: dict[str, Any],
        credentials: set[str],
        *,
        max_argument_bytes: int = JSON_ARGUMENT_BYTES,
    ) -> str:
        # Caller must authorize this explicit tool and its arguments before entering.
        async with self.session(name, credentials) as client:
            return await client.tool_call(tool, arguments, max_argument_bytes=max_argument_bytes)
