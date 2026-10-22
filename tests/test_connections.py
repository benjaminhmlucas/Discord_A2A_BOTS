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
import argparse

import pytest

from bridge_capabilities import Capabilities
from bridge_connections import migrated
from bridge_http import CapabilityError
from bridge_privacy import Privacy
from test_capabilities import config_for, FixtureServer, C, A, OWNER, CANARY, TOKEN_ENV
from test_bridge import Bridge, Channel, Client, Message, Author
import mcp_connections as cli

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
                assert manager.status("legacy.lookup")["connected"] is True
                assert manager.status("legacy.lookup")["outcome"] == "connected"
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


def test_reflected_bearer_and_session_are_redacted_before_cli_json(tmp_path):
    async def scenario():
        async with FixtureServer() as server:
            server.legacy = True
            config = config_for(server.origin, TOKEN_ENV)
            config["capabilities"]["tools"]["lookup"]["protocol"] = "2025-11-25"
            source = tmp_path / "config.json"
            source.write_text(json.dumps(migrated(config)))
            server.list_result = {"tools": [{"name": CANARY + "." + server.session_id}]}
            with patch.dict(os.environ, {TOKEN_ENV: CANARY}):
                result = await cli.execute(
                    argparse.Namespace(config=str(source), action="discover", name="legacy.lookup")
                )
            encoded = json.dumps(result)
            assert CANARY not in encoded and server.session_id not in encoded
            assert result["tools"] == ["[REDACTED CREDENTIAL].[REDACTED CREDENTIAL]"]
            assert server.calls[0][1]["Authorization"] == "Bearer " + CANARY

    asyncio.run(scenario())


@pytest.mark.parametrize("character", ["x", "\U0001f600", "\x01"])
def test_legacy_fixed_argument_and_aggregate_limits_survive_migration(tmp_path, character):
    (tmp_path / "MEMORY.md").write_text("public")

    async def scenario():
        async with FixtureServer() as server:
            config = config_for(server.origin)
            tool = config["capabilities"]["tools"]["lookup"]
            # Control escapes count toward the original fixed JSON bound; keep that
            # config valid while filling the dynamic fields to their independent cap.
            tool["fixed_arguments"] = {"scope": ("x" if character == "\x01" else character) * 3000}
            tool["parameters"] = {f"q{i}": "string" for i in range(16)}
            config["capabilities"]["search"] = None
            args = {f"q{i}": character * 2048 for i in range(16)}
            for current in (config, migrated(config)):
                caps = Capabilities(current, lambda _: None)
                request = caps.authorize(
                    "/mcp lookup " + json.dumps(args), Message(1, "", Channel()), C
                )
                assert "public answer" in await caps.execute(request, Privacy(tmp_path))
            assert len([r for r, _ in server.calls if r["method"] == "tools/call"]) == 2

    asyncio.run(scenario())


def test_nested_deadlines_backpressure_cannot_lose_owned_process_tree(tmp_path):
    async def scenario():
        manager = Capabilities(configured(tmp_path, "block_stdin"), lambda _: None).connections
        manager.registry.http.seconds = 0.5
        host = None
        try:
            with pytest.raises(asyncio.TimeoutError):
                async with asyncio.timeout(0.55):
                    async with manager.session("first", set()) as client:
                        host = client.process
                        await client.discover()
                        await client.rpc("tools/call", {"payload": "x" * 400000}, 123)
            # Await the retained, shielded cleanup rather than assuming cancellation killed it.
            await manager.disconnect("first")
            pid = int((tmp_path / "audit.server.pid").read_text())
            assert host is not None and host.returncode is not None
            assert not alive(pid) and manager._active == {} and manager._closing == {}
        finally:
            # Failure on the pre-fix implementation must not leave a probe process alive.
            if host is not None and host.returncode is None:
                host.kill()
                await host.wait()

    asyncio.run(scenario())


def test_migration_keeps_exact_scalar_admission_boundaries(tmp_path):
    config = config_for()
    cases = [
        ({"query": "string"}, {"query": "x" * 2048}, {"query": "x" * 2049}),
        ({"count": "integer"}, {"count": 10**2047}, {"count": 10**2048}),
        ({"count": "integer"}, {"count": -(10**2046)}, {"count": -(10**2047)}),
    ]
    for params, allowed, denied in cases:
        config["capabilities"]["tools"]["lookup"]["parameters"] = params
        config["capabilities"]["search"] = None
        for current in (config, migrated(config)):
            caps = Capabilities(current, lambda _: None)
            assert caps.authorize(
                "/mcp lookup " + json.dumps(allowed), Message(1, "", Channel()), C
            )
            with pytest.raises(CapabilityError, match="Invalid MCP arguments"):
                caps.authorize("/mcp lookup " + json.dumps(denied), Message(2, "", Channel()), C)
    # Sixteen integer parameters remain a small valid configuration after migration.
    config["capabilities"]["tools"]["lookup"]["parameters"] = {
        f"n{i}": "integer" for i in range(16)
    }
    Capabilities(migrated(config), lambda _: None)


def test_connection_backed_http_initializes_and_calls_through_consumer(tmp_path):
    (tmp_path / "MEMORY.md").write_text("public synthetic context")
    (tmp_path / "public_context.md").write_text("public context")

    async def scenario():
        async with FixtureServer() as server:
            server.legacy = True
            original = config_for(server.origin)
            original["capabilities"]["tools"]["lookup"]["protocol"] = "2025-11-25"
            config = migrated(original)
            prompts = []

            async def provider(prompt, work=False):
                prompts.append(prompt)
                return json.dumps({"decision": "stop", "reply": "public answer"})

            bridge = Bridge(
                Client(C), C, provider, lambda _: None, tmp_path, tmp_path, config=config
            )
            channel = Channel()
            await bridge.handle(Message(1, f"<@{C}> /search topic", channel))
            assert (
                len(prompts) == 1
                and "public answer" in prompts[0]
                and "untrusted data" in prompts[0]
            )
            assert [body["method"] for body, _ in server.calls] == [
                "initialize",
                "notifications/initialized",
                "tools/list",
                "tools/call",
            ]
            assert bridge.capabilities.connections.status("legacy.lookup")["outcome"] == "completed"
            assert not bridge.capabilities.connections.status("legacy.lookup")["connected"]

    asyncio.run(scenario())


def test_failed_os_termination_retains_owner_for_real_retry(tmp_path):
    # Only the OS termination boundary is fault-injected; manager/transport run normally.
    async def scenario():
        manager = Capabilities(configured(tmp_path), lambda _: None).connections
        client = await manager.connect("first", set())
        process = client.process
        try:
            target, attribute = (process, "kill") if os.name == "nt" else (os, "killpg")
            with patch.object(
                target, attribute, side_effect=PermissionError("synthetic OS denial")
            ):
                with pytest.raises(PermissionError):
                    await manager.disconnect("first")
            assert manager._active["first"] is client and client.process is process
            assert manager.status("first")["outcome"] == "cleanup_failed"
            await manager.disconnect("first")
            assert process.returncode is not None and manager._active == {}
        finally:
            await manager.disconnect("first")

    asyncio.run(scenario())


def test_platform_termination_contract_with_native_process(tmp_path):
    import bridge_mcp_stdio as stdio

    async def scenario():
        manager = Capabilities(configured(tmp_path), lambda _: None).connections
        client = await manager.connect("first", set())
        process = client.process
        # Exercise the other OS driver's argument contract; native lifecycle is tested separately.
        if os.name == "nt":
            calls = []

            def group_kill(pid, sig):
                calls.append((pid, sig))
                process.kill()

            with (
                patch.object(stdio, "WINDOWS", False),
                patch.object(os, "killpg", group_kill, create=True),
                patch.object(stdio.signal, "SIGKILL", 9, create=True),
            ):
                await manager.disconnect("first")
            assert calls == [(process.pid, 9)]
        else:

            def job_kill():
                os.killpg(process.pid, stdio.signal.SIGKILL)

            with patch.object(stdio, "WINDOWS", True), patch.object(process, "kill", job_kill):
                await manager.disconnect("first")
        assert process.returncode is not None and not manager._active

    asyncio.run(scenario())


def test_cancelled_cleanup_task_keeps_ownership_until_retry(tmp_path):
    async def scenario():
        manager = Capabilities(configured(tmp_path), lambda _: None).connections
        client = await manager.connect("first", set())
        process = client.process
        task = asyncio.create_task(manager.disconnect("first"))
        await asyncio.sleep(0)
        manager._closing["first"].cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        assert manager._active["first"] is client
        await manager.disconnect("first")
        assert process.returncode is not None and not manager._active

    asyncio.run(scenario())


def test_already_reaped_process_needs_no_windows_kill(tmp_path):
    import bridge_mcp_stdio as stdio

    async def scenario():
        manager = Capabilities(configured(tmp_path), lambda _: None).connections
        client = await manager.connect("first", set())
        process = client.process
        if os.name == "nt":
            process.kill()
        else:
            os.killpg(process.pid, stdio.signal.SIGKILL)
        await process.wait()
        # Native process already gone; this driver branch must not kill a recycled PID.
        with patch.object(stdio, "WINDOWS", True):
            await manager.disconnect("first")
        assert not manager._active and client.process is None

    asyncio.run(scenario())


def test_stdio_credential_echo_is_absent_from_provider_public_reply_and_audit(tmp_path):
    (tmp_path / "MEMORY.md").write_text("public synthetic context")
    (tmp_path / "public_context.md").write_text("public context")

    async def scenario():
        config = configured(tmp_path, "credential_echo")
        config["capabilities"]["connections"]["servers"]["first"]["credential_env"] = {
            "FIXTURE_TOKEN": TOKEN_ENV
        }
        logs, prompts = [], []

        async def provider(prompt, work=False):
            prompts.append(prompt)
            return json.dumps({"decision": "stop", "reply": CANARY})

        with patch.dict(os.environ, {TOKEN_ENV: CANARY}):
            bridge = Bridge(Client(C), C, provider, logs.append, tmp_path, tmp_path, config=config)
            channel = Channel()
            await bridge.handle(
                Message(1, f'<@{C}> /mcp lookup {{"payload":{{"names":[]}}}}', channel)
            )
        public = "\n".join(m.content for m, _ in channel.sent)
        assert prompts and CANARY not in prompts[0] and "REDACTED CREDENTIAL" in prompts[0]
        assert CANARY not in public and "REDACTED CREDENTIAL" in public
        assert CANARY not in "\n".join(logs)

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
