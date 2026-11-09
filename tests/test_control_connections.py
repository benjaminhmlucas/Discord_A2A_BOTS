"""Local-control connection actions through the real shared manager and authentication.

Profiles are saved through the real control configuration; the stdio peer is a real
process and the OAuth peer a real loopback authorization server.
"""

import asyncio
import copy
import json
import threading
from unittest.mock import patch

import aiohttp
from aiohttp import web
import pytest

import bridge_connections
import bridge_control_connections
from bridge_auth_policy import AuthenticationError
from bridge_control_connections import ControlConnections
from bridge_credentials import PARTS, CredentialError
from bridge_errors import CapabilityError
from control_gui import STATE, create_app
from test_bridge import Author, Channel, Message
from test_connections import INPUT, stdio_profile
from test_control_config import configured
from test_oauth_grants import NATIVE, MemoryCredentials, OAuthService, browser

SECRET = "synthetic-control-connection-credential-7f3a"
TOOL = {
    "connection": "first",
    "name": "read_example",
    "read_only": True,
    "user_ids": [201],
    "bot_ids": [101, 102],
    "input_schema": INPUT,
    "fixed_arguments": {},
}


def save_capabilities(store, servers, tools=None, internal=()):
    snapshot = store.snapshot()
    config = snapshot["config"]
    config["capabilities"] = {
        "enabled": True,
        "internal_origins": list(internal),
        "connections": {"version": 1, "servers": servers},
        "tools": tools or {},
    }
    store.save("bridge_config.json", config, snapshot["revisions"]["bridge_config.json"])


def keyed_profile(tmp_path):
    profile = stdio_profile(tmp_path, name="keyed-audit")
    profile["credentials"] = {"FIXTURE_KEY": {"source": "native", "name": "fixture-key"}}
    return profile


def memory_store(manager):
    if not NATIVE:
        manager.caps.authentication.store._native = MemoryCredentials()


def test_lifecycle_discovery_credentials_and_tools_stay_unauthorized(tmp_path):
    store = configured(tmp_path)
    missing = stdio_profile(tmp_path, name="missing-audit")
    missing["cwd"] = str(tmp_path / "missing-working-directory")
    servers = {
        "first": stdio_profile(tmp_path),
        "keyed": keyed_profile(tmp_path),
        "missing": missing,
    }
    save_capabilities(store, servers, {"lookup": copy.deepcopy(TOOL)})

    async def scenario():
        manager = ControlConnections(store)
        try:
            view = await manager.overview()
            rows = {row["id"]: row for row in view["servers"]}
            assert view["enabled"] is True and view["web"] is False and view["search"] is None
            assert rows["first"]["outcome"] == "not_tested"
            assert rows["first"]["authentication"] == "none"
            assert rows["first"]["tools"] == [
                {
                    "alias": "lookup",
                    "name": "read_example",
                    "user_ids": ["201"],
                    "bot_ids": ["101", "102"],
                }
            ]
            assert rows["keyed"]["references"] == ["fixture-key"]
            assert rows["keyed"]["oauth"] is False and rows["keyed"]["tools"] == []
            memory_store(manager)
            assert (await manager.overview())["servers"][1]["authentication"] == "required"

            tested = await manager.act("test", "first", {})
            assert tested["outcome"] == "completed" and "tools" not in tested
            found = await manager.act("discover", "first", {})
            assert found["tools"] == [{"name": "read_example", "authorized": True}]

            connected = await manager.act("connect", "first", {})
            assert connected["connected"] is True and connected["outcome"] == "connected"
            with pytest.raises(CapabilityError, match="in use"):
                await manager.act("connect", "first", {})
            held = await manager.act("discover", "first", {})
            assert held["connected"] is True and held["tools"][0]["authorized"] is True
            released = await manager.act("disconnect", "first", {})
            assert released["connected"] is False and released["outcome"] == "disconnected"
            assert manager.held == {}

            with pytest.raises(OSError):
                await manager.act("test", "missing", {})
            assert (await manager.act("disconnect", "missing", {}))["outcome"] == "failed"

            with pytest.raises(CredentialError):
                await manager.act("connect", "keyed", {})
            with pytest.raises(CapabilityError, match="credential value"):
                await manager.act("credential-set", "keyed", {"reference": "fixture-key"})
            with pytest.raises(AuthenticationError, match="Unknown MCP credential"):
                await manager.act(
                    "credential-set", "keyed", {"reference": "OTHER", "value": SECRET}
                )
            saved = await manager.act(
                "credential-set", "keyed", {"reference": "fixture-key", "value": SECRET}
            )
            assert saved["authentication"] == "configured" and SECRET not in json.dumps(saved)
            # A connection that has a credential still has no authorized tools.
            discovered = await manager.act("discover", "keyed", {})
            assert discovered["tools"] == [{"name": "read_example", "authorized": False}]
            records = (tmp_path / "keyed-audit").read_text(encoding="utf-8").splitlines()
            assert json.loads(records[0])["environment"]["FIXTURE_KEY"] == SECRET
            request = Message(1, "/mcp keyed {}", Channel(301), author=Author(201))
            with pytest.raises(CapabilityError, match="Unknown MCP tool"):
                manager.caps.authorize('/mcp read_example {"payload":{"names":[]}}', request, 101)
            assert set(manager.caps.tools) == {"lookup"}
            removed = await manager.act("credential-delete", "keyed", {"reference": "fixture-key"})
            assert removed["authentication"] == "required"
            with pytest.raises(CapabilityError, match="Unknown connection action"):
                await manager.act("unknown", "first", {})
            with pytest.raises(CapabilityError, match="Unknown MCP connection"):
                await manager.act("test", "absent", {})
            assert json.loads((tmp_path / "bridge_config.json").read_text())["capabilities"][
                "tools"
            ] == {"lookup": json.loads(json.dumps(TOOL))}
        finally:
            await manager.close()

    asyncio.run(scenario())


def test_profile_changes_save_through_runtime_validation_and_release_connections(tmp_path):
    store = configured(tmp_path)
    save_capabilities(store, {"first": stdio_profile(tmp_path)}, {"lookup": copy.deepcopy(TOOL)})

    async def scenario():
        manager = ControlConnections(store)
        try:
            revision = (await manager.overview())["revision"]
            with pytest.raises(ValueError, match="Invalid MCP connection configuration"):
                await manager.act(
                    "add", "second", {"profile": {"transport": "ftp"}, "revision": revision}
                )
            with pytest.raises(ValueError, match="Invalid MCP connection configuration"):
                await manager.act(
                    "add", "first", {"profile": stdio_profile(tmp_path), "revision": revision}
                )
            with pytest.raises(CapabilityError, match="Remove the tools"):
                await manager.act("remove", "first", {"revision": revision})
            added = await manager.act(
                "add",
                "second",
                {"profile": stdio_profile(tmp_path, name="second-audit"), "revision": revision},
            )
            assert added["restart_required"] is True
            with pytest.raises(ValueError, match="changed"):
                await manager.act(
                    "edit", "second", {"profile": stdio_profile(tmp_path), "revision": revision}
                )
            view = await manager.overview()
            assert [row["id"] for row in view["servers"]] == ["first", "second"]
            await manager.act("connect", "second", {})
            edited = stdio_profile(tmp_path, name="edited-audit")
            result = await manager.act(
                "edit", "second", {"profile": edited, "revision": view["revision"]}
            )
            assert "second" not in manager.held
            view = await manager.overview()
            assert view["revision"] == result["revision"]
            assert view["servers"][1]["profile"] == edited
            await manager.act("remove", "second", {"revision": view["revision"]})
            saved = json.loads((tmp_path / "bridge_config.json").read_text())
            assert list(saved["capabilities"]["connections"]["servers"]) == ["first"]
        finally:
            await manager.close()

    asyncio.run(scenario())


def test_configuration_change_and_failed_cleanup_keep_ownership(tmp_path):
    store = configured(tmp_path)
    save_capabilities(store, {"first": stdio_profile(tmp_path)})

    async def scenario():
        manager = ControlConnections(store)
        await manager.overview()
        await manager.act("connect", "first", {})
        client = manager.held["first"]
        original = client.disconnect

        async def failing():
            raise OSError("synthetic cleanup failure")

        client.disconnect = failing
        snapshot = await asyncio.to_thread(store.snapshot)
        config = snapshot["config"]
        config["max_turns"] = 5
        revision = snapshot["revisions"]["bridge_config.json"]
        await asyncio.to_thread(store.save, "bridge_config.json", config, revision)
        with pytest.raises(CapabilityError, match="disconnect failed"):
            await manager.overview()
        assert "first" in manager.held
        client.disconnect = original
        view = await manager.overview()
        current = await asyncio.to_thread(store.snapshot)
        assert manager.held == {}
        assert view["revision"] == current["revisions"]["bridge_config.json"]

    asyncio.run(scenario())


def test_gui_oauth_signin_logout_and_static_errors(tmp_path):
    store = configured(tmp_path)

    async def scenario():
        async with OAuthService() as service:
            origin = service.origin
            profile = {
                "transport": "http",
                "endpoint": origin + "/mcp",
                "protocol": "2026-07-28",
                "authentication": {
                    "type": "oauth",
                    "credential": {"source": "native", "name": "docs-oauth"},
                    "issuer": origin,
                    "client_id": "fixture-client",
                    "scopes": ["read"],
                    "allowed_origins": [origin],
                    "internal_origins": [origin],
                    "callback_port": 0,
                },
            }
            await asyncio.to_thread(save_capabilities, store, {"docs": profile}, None, [origin])
            app = create_app(tmp_path, "", "synthetic-session")
            runner = web.AppRunner(app)
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            host = f"127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
            app[STATE]["host"] = host
            url = "http://" + host
            headers = {"Authorization": "Bearer synthetic-session", "Origin": url}
            opened = []

            def simulated_browser(address):
                # The explicit sign-in opener runs in a worker thread; follow it there.
                opened.append((address, threading.current_thread() is threading.main_thread()))
                asyncio.run(browser(address))

            try:
                async with aiohttp.ClientSession() as client:

                    async def post(data):
                        async with client.post(
                            url + "/api/connections", json=data, headers=headers
                        ) as response:
                            return response.status, await response.json()

                    async with client.get(url + "/api/connections", headers=headers) as response:
                        view = await response.json()
                    memory_store(app[STATE]["connections"])
                    assert view["servers"][0]["oauth"] is True
                    status, body = await post({"action": "discover", "name": "docs"})
                    assert status == 400 and "sign-in required" in body["error"]
                    assert service.calls == []
                    with patch.object(
                        bridge_control_connections.webbrowser, "open", simulated_browser
                    ):
                        status, body = await post({"action": "signin", "name": "docs"})
                    assert status == 200 and body["authentication"] == "configured"
                    assert len(opened) == 1 and opened[0][1] is False
                    assert service.exchanges == ["authorization_code"]
                    status, body = await post({"action": "discover", "name": "docs"})
                    assert body["tools"] == [{"name": "read_example", "authorized": False}]
                    assert "synthetic-ticket27-grant-" not in json.dumps(body)
                    # Stateless protocol: connect resolves credentials without a request.
                    status, body = await post({"action": "connect", "name": "docs"})
                    assert status == 200 and body["connected"] is True
                    status, body = await post({"action": "logout", "name": "docs"})
                    assert body["connected"] is False
                    assert body["authentication"] == "required" and body["revocation"] == "revoked"
                    for invalid in (
                        {"action": "explode", "name": "docs"},
                        {"action": "test", "name": 7},
                        {"action": "test"},
                        {"action": "test", "name": "docs", "extra": SECRET},
                    ):
                        status, body = await post(invalid)
                        assert status == 400 and SECRET not in json.dumps(body)
                    status, body = await post(
                        {
                            "action": "add",
                            "name": "leaky",
                            "profile": {**profile, "endpoint": origin + "/mcp?token=" + SECRET},
                            "revision": view["revision"],
                        }
                    )
                    assert status == 400
                    assert body["error"] == "Invalid MCP connection configuration"
                    status, body = await post(
                        {"action": "remove", "name": "docs", "revision": view["revision"]}
                    )
                    assert status == 200
                    assert (
                        "docs"
                        not in json.loads((tmp_path / "bridge_config.json").read_text())[
                            "capabilities"
                        ]["connections"]["servers"]
                    )
            finally:
                caps = app[STATE]["connections"].caps
                await runner.cleanup()
                cleanup_profile(caps, profile)

    asyncio.run(scenario())


def cleanup_profile(caps, profile):
    """Remove native OAuth parts even after the profile left the configuration."""
    if NATIVE:
        binding = caps.authentication.binding("docs", profile)
        for part in PARTS:
            caps.authentication.store.delete(profile["authentication"]["credential"], binding, part)


def test_explicit_opener_uses_the_system_browser():
    calls = []
    with patch.object(bridge_control_connections.webbrowser, "open", calls.append):
        asyncio.run(bridge_control_connections.open_browser("http://127.0.0.1:1/authorize"))
    assert calls == ["http://127.0.0.1:1/authorize"]


def test_rejected_bearer_on_stateful_connect_is_reported_without_the_value(tmp_path):
    store = configured(tmp_path)
    presented = []

    async def refuse(request):
        presented.append(request.headers.get("Authorization"))
        return web.Response(status=401, headers={"WWW-Authenticate": "Bearer"})

    async def scenario():
        app = web.Application()
        app.router.add_post("/mcp", refuse)
        runner = web.AppRunner(app, access_log=None)
        await runner.setup()
        await web.TCPSite(runner, "127.0.0.1", 0).start()
        origin = "http://127.0.0.1:" + str(runner.addresses[0][1])
        profile = {
            "transport": "http",
            "endpoint": origin + "/mcp",
            "protocol": "2025-11-25",
            "authentication": {
                "type": "bearer",
                "credential": {"source": "native", "name": "fixture-bearer"},
            },
        }
        await asyncio.to_thread(save_capabilities, store, {"bearer": profile}, None, [origin])
        manager = ControlConnections(store)
        try:
            await manager.overview()
            memory_store(manager)
            await manager.act(
                "credential-set", "bearer", {"reference": "fixture-bearer", "value": SECRET}
            )
            with pytest.raises(CapabilityError) as refused:
                await manager.act("connect", "bearer", {})
            assert SECRET not in str(refused.value) and SECRET not in repr(refused.value.args)
            assert presented == ["Bearer " + SECRET]
            assert manager.held == {}
            assert (await manager.act("disconnect", "bearer", {}))["connected"] is False
        finally:
            await manager.act("credential-delete", "bearer", {"reference": "fixture-bearer"})
            await manager.close()
            await runner.cleanup()

    asyncio.run(scenario())


class FaultyClient:
    """Stands in for the stdio client inside the real shared ConnectionManager."""

    process = None
    instances = []
    connected = None  # asyncio.Event released by the test, or None to fail at once.
    cleanup_fails = True

    def __init__(self, *args, **kwargs):
        self.calls = 0
        FaultyClient.instances.append(self)

    async def connect(self):
        if FaultyClient.connected is None:
            raise OSError("synthetic handshake failure")
        await FaultyClient.connected.wait()

    async def disconnect(self):
        self.calls += 1
        if FaultyClient.cleanup_fails:
            raise OSError("synthetic cleanup failure")


def change_turns(store, turns):
    snapshot = store.snapshot()
    config = snapshot["config"]
    config["max_turns"] = turns
    store.save("bridge_config.json", config, snapshot["revisions"]["bridge_config.json"])


def test_failed_connect_stays_owned_until_its_cleanup_succeeds(tmp_path):
    store = configured(tmp_path)
    save_capabilities(store, {"first": stdio_profile(tmp_path)})
    FaultyClient.instances, FaultyClient.connected, FaultyClient.cleanup_fails = [], None, True

    async def scenario():
        manager = ControlConnections(store)
        with patch.object(bridge_connections, "StdioClient", FaultyClient):
            with pytest.raises(OSError, match="synthetic cleanup failure"):
                await manager.act("connect", "first", {})
        owner = manager.caps.connections
        [client] = FaultyClient.instances
        # Never held by the window, but still owned by the shared manager.
        assert manager.held == {} and owner.owned() == ("first",) and client.calls == 1
        with pytest.raises(CapabilityError, match="disconnect failed"):
            await manager.close()
        assert client.calls == 2 and owner.owned() == ("first",)
        await asyncio.to_thread(change_turns, store, 5)
        with pytest.raises(CapabilityError, match="disconnect failed"):
            await manager.overview()
        # The configuration change cannot discard the owner while cleanup keeps failing.
        assert manager.caps.connections is owner and client.calls == 3
        FaultyClient.cleanup_fails = False
        view = await manager.overview()
        assert manager.caps.connections is not owner and owner.owned() == ()
        assert client.calls == 4
        current = await asyncio.to_thread(store.snapshot)
        assert view["revision"] == current["revisions"]["bridge_config.json"]
        # An explicit disconnect also reaches a connection owned only by the manager.
        with patch.object(bridge_connections, "StdioClient", FaultyClient):
            FaultyClient.cleanup_fails = True
            with pytest.raises(OSError, match="synthetic cleanup failure"):
                await manager.act("connect", "first", {})
            FaultyClient.cleanup_fails = False
            await manager.act("disconnect", "first", {})
        assert manager.caps.connections.owned() == ()

    asyncio.run(scenario())


def test_configuration_change_waits_for_an_in_flight_connect(tmp_path):
    store = configured(tmp_path)
    save_capabilities(store, {"first": stdio_profile(tmp_path)})
    FaultyClient.instances, FaultyClient.cleanup_fails = [], False

    async def scenario():
        FaultyClient.connected = asyncio.Event()
        manager = ControlConnections(store)
        with patch.object(bridge_connections, "StdioClient", FaultyClient):
            connecting = asyncio.create_task(manager.act("connect", "first", {}))
            while not FaultyClient.instances:
                await asyncio.sleep(0.01)
            owner = manager.caps.connections
            await asyncio.to_thread(change_turns, store, 5)
            viewing = asyncio.create_task(manager.overview())
            await asyncio.sleep(0.3)
            # Replacement waits: the connecting client must not land in a discarded owner.
            assert not viewing.done() and manager.caps.connections is owner
            FaultyClient.connected.set()
            assert (await connecting)["connected"] is True
            view = await viewing
        [client] = FaultyClient.instances
        assert manager.caps.connections is not owner and owner.owned() == ()
        assert client.calls == 1 and manager.held == {}
        current = await asyncio.to_thread(store.snapshot)
        assert view["revision"] == current["revisions"]["bridge_config.json"]
        await manager.close()

    asyncio.run(scenario())
