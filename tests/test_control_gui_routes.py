"""Setup, provider, service and log routes through the authenticated loopback server."""

import asyncio
import json
from unittest.mock import patch

import aiohttp
from aiohttp import web

import test_bridge  # noqa: F401  # Installs the identity fixture before health imports.
import bridge_control_setup
import control_gui
from bridge_errors import CapabilityError
from control_gui import STATE, create_app, public_message
from test_control_config import configured

SECRET = "synthetic-control-route-secret-a41f"


def test_public_messages_keep_fixed_guidance_and_hide_request_data():
    assert public_message(CapabilityError("MCP credential unavailable")) == (
        "MCP credential unavailable"
    )
    for fixed in (
        "Configuration changed; reload before saving",
        "Invalid request limit: queue_capacity",
        "Create the checkout venv before starting bots",
    ):
        assert public_message(ValueError(fixed)) == fixed
    for private in (
        f"invalid literal for int() with base 10: '{SECRET}'",
        f"Invalid value {SECRET}",
        "[Errno 2] No such file or directory: 'C:/private/path'",
        "x" * 200,
    ):
        assert public_message(ValueError(private)) == control_gui.GENERIC


def test_setup_provider_service_and_log_routes(tmp_path):
    store = configured(tmp_path)
    snapshot = store.snapshot()
    # A missing Node keeps install actions from reaching a real npm on PATH.
    local = {**snapshot["settings"], "node_executable": str(tmp_path / "missing-node.exe")}
    store.save("local_settings.json", local, snapshot["revisions"]["local_settings.json"])

    async def scenario():
        app = create_app(tmp_path, "", "synthetic-session")
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        host = f"127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
        app[STATE]["host"] = host
        url = "http://" + host
        headers = {"Authorization": "Bearer synthetic-session", "Origin": url}
        try:
            async with aiohttp.ClientSession() as client:

                async def get(path):
                    async with client.get(url + path, headers=headers) as response:
                        return response.status, await response.json()

                async def post(path, data):
                    async with client.post(url + path, json=data, headers=headers) as response:
                        return response.status, await response.json()

                for path in ("/api/checklist", "/api/providers", "/api/services", "/api/logs"):
                    async with client.get(url + path) as response:
                        assert response.status == 403
                async with client.post(
                    url + "/api/services",
                    json={"action": "stop", "name": "codexbot"},
                    headers={**headers, "Origin": "https://attacker.invalid"},
                ) as response:
                    assert response.status == 403

                with patch.object(bridge_control_setup, "legacy", lambda name: None):
                    status, body = await get("/api/checklist")
                    assert status == 200 and body["ready"] is False
                    assert {step["id"] for step in body["steps"]} >= {"venv", "pm2", "preflight"}
                    status, body = await get("/api/providers")
                    assert body["providers"]["codex"]["pinned"] == "0.159.3"
                    status, body = await post(
                        "/api/providers", {"action": "verify", "target": "GEMINI_API_KEY"}
                    )
                    assert body == {"name": "GEMINI_API_KEY", "check": "not_set"}
                status, body = await post("/api/checklist", {"action": "preflight"})
                assert body == {"preflight": "unavailable"}
                status, body = await post("/api/checklist", {"action": "install_codex"})
                assert status == 400 and body["error"].startswith("Install Node.js")
                for data in ({"action": "format_disk"}, {"action": "preflight", "x": SECRET}):
                    status, body = await post("/api/checklist", data)
                    assert status == 400 and SECRET not in json.dumps(body)
                status, body = await post("/api/providers", {"action": "login", "target": "codex"})
                assert body == {"login": "not_installed"}
                status, body = await post(
                    "/api/providers", {"action": "message", "target": "codex", "confirm": False}
                )
                assert status == 400 and body["error"].startswith("Confirm")
                status, body = await post("/api/providers", {"action": "post", "target": "codex"})
                assert status == 400 and body["error"] == "Unknown provider action"

                status, body = await get("/api/services")
                assert body["pm2"] == {"available": False}
                assert body["names"] == list(control_gui.services.SERVICES)
                assert body["health"]["recovery"]["maintenance"] is False
                status, body = await post(
                    "/api/services", {"action": "maintenance", "enabled": True}
                )
                assert body["maintenance"] is True
                status, body = await post(
                    "/api/services", {"action": "maintenance", "enabled": False}
                )
                assert body["maintenance"] is False
                status, body = await post("/api/services", {"action": "stop", "name": "codexbot"})
                assert status == 400
                assert body["error"] == "Create the checkout venv before starting bots"
                status, body = await post(
                    "/api/services", {"action": "task-status", "task": "bad name; x"}
                )
                assert status == 400
                status, body = await get("/api/logs?name=health")
                assert body == {"name": "health", "text": None}
                status, body = await get("/api/logs?name=..%2F..%2Fsecret")
                assert status == 400 and body["error"] == "Unknown log"
        finally:
            await runner.cleanup()

    asyncio.run(scenario())
    assert store.snapshot()["config"]["enabled_bots"] == [101, 102, 103]
