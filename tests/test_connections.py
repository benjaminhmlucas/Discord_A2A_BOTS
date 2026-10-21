"""Real subprocess/HTTP/consumer tests; production MCP boundaries are not mocked."""

import asyncio
import copy
import json
import os
from pathlib import Path
import sys
from unittest.mock import patch
import ctypes
import time

import pytest

from bridge_capabilities import Capabilities
from bridge_connections import migrated
from bridge_http import CapabilityError
from bridge_privacy import Privacy
from test_capabilities import config_for, FixtureServer, C, A, OWNER, CANARY, TOKEN_ENV
from test_bridge import Bridge, Channel, Client, Message, Author

SERVER = Path(__file__).parent / "fixtures/mcp_stdio_server.py"
INPUT = {
    "type": "object",
    "properties": {
        "payload": {
            "type": "object",
            "properties": {"names": {"type": "array", "items": {"type": "string"}}},
            "required": ["names"],
            "additionalProperties": False,
        }
    },
    "required": ["payload"],
    "additionalProperties": False,
}


def stdio_profile(tmp_path, mode="normal", name="audit"):
    return {
        "transport": "stdio",
        "command": sys.executable,
        "arguments": [str(SERVER), mode, str(tmp_path / name)],
        "cwd": str(tmp_path),
        "environment": {"FIXTURE_SETTING": "configured"},
        "credential_env": {},
    }


def configured(tmp_path, mode="normal"):
    config = config_for()
    data = config["capabilities"]
    data["search"] = None
    data["connections"] = {
        "version": 1,
        "servers": {
            "first": stdio_profile(tmp_path, mode),
            "second": stdio_profile(tmp_path, name="other"),
        },
    }
    data["tools"] = {
        "lookup": {
            "connection": "first",
            "name": "read_example",
            "read_only": True,
            "user_ids": [OWNER],
            "bot_ids": [C, A],
            "input_schema": copy.deepcopy(INPUT),
            "fixed_arguments": {},
        }
    }
    return config


def test_real_stdio_lifecycle_and_independent_profiles(tmp_path):
    async def scenario():
        caps = Capabilities(configured(tmp_path), lambda _: None)
        manager = caps.connections
        assert manager.status("first") == {
            "id": "first",
            "transport": "stdio",
            "connected": False,
            "outcome": "not_tested",
        }
        client = await manager.connect("first", set())
        assert manager.status("first")["connected"]
        assert (await client.discover())[0]["name"] == "read_example"
        with pytest.raises(CapabilityError, match="already in use"):
            await manager.connect("first", set())
        await manager.disconnect("first")
        await manager.disconnect("first")
        assert not manager.status("first")["connected"]
        for name in ("first", "second", "first"):
            assert (await manager.discover(name))[0]["name"] == "read_example"
            assert manager.status(name)["outcome"] == "completed"
            assert not manager.status(name)["connected"]
        assert (tmp_path / "audit").exists() and (tmp_path / "other").exists()

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "mode,error",
    [
        ("exit", "response"),
        ("protocol", "mismatch"),
        ("wrong_id", "failed"),
        ("request", "server requests"),
        ("broken", "response"),
        ("encoding", "response"),
        ("large", "response"),
        ("fragment", "response"),
        ("stderr_flood", "stderr limit"),
    ],
)
def test_stdio_real_failures_are_bounded_and_cleaned(tmp_path, mode, error):
    async def scenario():
        caps = Capabilities(configured(tmp_path, mode), lambda _: None)
        with pytest.raises(CapabilityError, match=error):
            await caps.connections.discover("first")
        assert caps.connections.status("first")["outcome"] == "failed"
        assert not caps.connections.status("first")["connected"]
        assert caps.connections._active == {}

    asyncio.run(scenario())


@pytest.mark.parametrize("mode", ["normal", "notification", "stderr"])
def test_real_consumer_nested_arguments_and_no_policy_inheritance(tmp_path, mode):
    (tmp_path / "MEMORY.md").write_text("<!--PRIVATE:START-->private-canary<!--PRIVATE:END-->")
    (tmp_path / "public_context.md").write_text("public context")

    async def scenario():
        config = configured(tmp_path, mode)
        prompts, logs = [], []

        async def provider(prompt, work=False):
            prompts.append(prompt)
            return json.dumps({"decision": "stop", "reply": "public reply"})

        bridge = Bridge(Client(C), C, provider, logs.append, tmp_path, tmp_path, config=config)
        channel = Channel()
        body = '/mcp lookup {"payload":{"names":["first","second"]}}'
        await bridge.handle(Message(1, f"<@{C}> {body}", channel))
        assert len(prompts) == 1 and "first" in prompts[0] and "untrusted data" in prompts[0]
        audit = [json.loads(s) for s in (tmp_path / "audit").read_text().splitlines()]
        calls = [r for r in audit if r["method"] == "tools/call"]
        assert len(calls) == 1 and calls[0]["params"]["arguments"] == {
            "payload": {"names": ["first", "second"]}
        }
        before = len(audit)
        for identity, command in (
            (202, body),
            (OWNER, "/mcp unknown {}"),
            (OWNER, '/mcp lookup {"payload":{"names":[1]}}'),
            (OWNER, '/mcp lookup {"payload":{"names":[],"extra":1}}'),
            (OWNER, '/mcp lookup {"payload":{"names":["private-canary"]}}'),
        ):
            await bridge.handle(
                Message(2 + len(channel.sent), f"<@{C}> {command}", channel, Author(identity))
            )
        assert len((tmp_path / "audit").read_text().splitlines()) == before
        assert len(prompts) == 1

    asyncio.run(scenario())


def test_minimal_environment_and_credentials(tmp_path):
    async def scenario():
        config = configured(tmp_path)
        profile = config["capabilities"]["connections"]["servers"]["first"]
        profile["credential_env"] = {"FIXTURE_TOKEN": TOKEN_ENV}
        with patch.dict(os.environ, {TOKEN_ENV: CANARY, "UNRELATED_SECRET": "do-not-inherit"}):
            caps = Capabilities(config, lambda _: None)
            await caps.connections.discover("first")
            row = json.loads((tmp_path / "audit").read_text().splitlines()[0])
            env = row["environment"]
            assert env["FIXTURE_TOKEN"] == CANARY
            assert "UNRELATED_SECRET" not in env and TOKEN_ENV not in env
            assert env["FIXTURE_SETTING"] == "configured" and "--require=" in env["NODE_OPTIONS"]
            assert CANARY in caps.secrets and CANARY not in json.dumps(caps.registry.export())
        for value in ("",):
            with patch.dict(os.environ, {TOKEN_ENV: value}), pytest.raises(CapabilityError):
                await caps.connections.discover("first")

    asyncio.run(scenario())


def test_legacy_migration_real_http_and_configuration_rollback(tmp_path):
    (tmp_path / "MEMORY.md").write_text("public fixture memory")

    async def scenario():
        async with FixtureServer() as server:
            original = config_for(server.origin)
            snapshot = copy.deepcopy(original)
            updated = migrated(original)
            assert original == snapshot and migrated(updated) == updated
            caps = Capabilities(updated, lambda _: None)
            request = caps.authorize("/search topic", Message(1, "", Channel()), C)
            assert "public answer" in await caps.execute(request, Privacy(tmp_path))
            assert not caps.connections.status("legacy.lookup")["connected"]
            assert len(server.calls) == 2
            assert (
                migrated({"capabilities": {"enabled": False}})["capabilities"]["connections"][
                    "version"
                ]
                == 1
            )

    asyncio.run(scenario())


def alive(pid):
    if os.name == "nt":
        kernel = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel.OpenProcess.argtypes = [ctypes.c_uint32, ctypes.c_int, ctypes.c_uint32]
        kernel.OpenProcess.restype = ctypes.c_void_p
        kernel.GetExitCodeProcess.argtypes = [ctypes.c_void_p, ctypes.POINTER(ctypes.c_uint32)]
        kernel.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = kernel.OpenProcess(0x1000, False, pid)
        if not handle:
            return False
        try:
            code = ctypes.c_uint32()
            return bool(kernel.GetExitCodeProcess(handle, ctypes.byref(code))) and code.value == 259
        finally:
            kernel.CloseHandle(handle)
    try:
        os.kill(pid, 0)
        state = Path(f"/proc/{pid}/stat")
        return not state.exists() or state.read_text().split()[2] != "Z"
    except ProcessLookupError:
        return False


def test_owned_child_cleanup_timeout_cancellation_and_reconnect(tmp_path):
    async def scenario():
        config = configured(tmp_path, "spawn_child")
        caps = Capabilities(config, lambda _: None)
        await caps.connections.discover("first")
        pid = int((tmp_path / "audit.pid").read_text())
        until = time.monotonic() + 2
        while alive(pid) and time.monotonic() < until:
            await asyncio.sleep(0.02)
        assert not alive(pid)
        for mode in ("slow_initialize", "slow"):
            manager = Capabilities(configured(tmp_path, mode), lambda _: None).connections
            manager.registry.http.seconds = 0.5
            with pytest.raises(asyncio.TimeoutError):
                await manager.call("first", "read_example", {"payload": {"names": []}}, set())
            assert not manager.status("first")["connected"]
        manager = Capabilities(configured(tmp_path, "slow"), lambda _: None).connections
        task = asyncio.create_task(
            manager.call("first", "read_example", {"payload": {"names": []}}, set())
        )
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if (tmp_path / "audit").exists() and '"method": "tools/call"' in (
                tmp_path / "audit"
            ).read_text():
                break
            await asyncio.sleep(0.01)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert not manager.status("first")["connected"]
        assert (
            await Capabilities(configured(tmp_path), lambda _: None).connections.discover("first")
        )[0]["name"] == "read_example"

    asyncio.run(scenario())


def test_http_manager_credentials_discovery_and_scoped_busy_session(tmp_path):
    async def scenario():
        async with FixtureServer() as server:
            config = migrated(config_for(server.origin, TOKEN_ENV))
            caps = Capabilities(config, lambda _: None)
            manager = caps.connections
            with (
                patch.dict(os.environ, {TOKEN_ENV: ""}),
                pytest.raises(CapabilityError, match="unavailable"),
            ):
                await manager.discover("legacy.lookup")
            with (
                patch.dict(os.environ, {TOKEN_ENV: "bad\nvalue"}),
                pytest.raises(CapabilityError, match="Invalid MCP credential"),
            ):
                await manager.discover("legacy.lookup")
            with patch.dict(os.environ, {TOKEN_ENV: CANARY}):
                client = await manager.connect("legacy.lookup", set())
                with pytest.raises(CapabilityError, match="already in use"):
                    async with manager.session("legacy.lookup", set()):
                        pass
                assert manager._active["legacy.lookup"] is client
                for listing in (
                    {},
                    {"tools": [1]},
                    {"tools": [{"name": 1}]},
                    {"tools": [{"name": "a"}] * 2},
                    {"tools": [], "nextCursor": False},
                    {"tools": [], "nextCursor": "x" * 2049},
                    {"tools": [], "nextCursor": "more"},
                ):
                    server.list_result = listing
                    with pytest.raises(CapabilityError):
                        await client.discover()
                await manager.disconnect("legacy.lookup")

    asyncio.run(scenario())


def test_dead_process_status_and_request_size_guard(tmp_path):
    async def scenario():
        manager = Capabilities(configured(tmp_path, "exit_after_init"), lambda _: None).connections
        try:
            client = await manager.connect("first", set())
        except OSError:
            # Exit may race initialized-notification drain; either outcome must be closed.
            assert not manager.status("first")["connected"]
        else:
            until = time.monotonic() + 2
            while client.process.returncode is None and time.monotonic() < until:
                await asyncio.sleep(0.01)
            assert manager.status("first")["outcome"] == "exited"
            await manager.disconnect("first")
        manager = Capabilities(configured(tmp_path), lambda _: None).connections
        async with manager.session("first", set()) as client:
            with pytest.raises(CapabilityError, match="request too large"):
                await client.rpc("tools/call", {"payload": "x" * 525000}, 123)

    asyncio.run(scenario())
