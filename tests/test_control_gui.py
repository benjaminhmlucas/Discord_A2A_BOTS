import asyncio
import json
import runpy
from pathlib import Path
from unittest.mock import patch

import aiohttp
from aiohttp import web
import pytest

import control_gui
from control_gui import STATE, create_app
from test_control_config import configured


def test_control_boundary_and_real_configuration_actions(tmp_path):
    configured(tmp_path)

    async def scenario():
        app = create_app(tmp_path, "", "synthetic-session")
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        host = f"127.0.0.1:{port}"
        app[STATE]["host"] = host
        url = "http://" + host
        headers = {"Authorization": "Bearer synthetic-session", "Origin": url}
        try:
            async with aiohttp.ClientSession() as client:
                async with client.get(url + "/", headers={"Host": "attacker.invalid"}) as response:
                    assert response.status == 403
                for path in ("/", "/ui/control.js", "/ui/control.css"):
                    async with client.get(url + path) as response:
                        assert response.status == 200
                        assert "synthetic-session" not in await response.text()
                        assert response.headers["Cache-Control"] == "no-store"
                        assert (
                            "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
                        )
                async with client.get(url + "/ui/unknown") as response:
                    assert response.status == 404
                async with client.get(url + "/api/config") as response:
                    assert response.status == 403
                async with client.post(
                    url + "/api/save",
                    json={},
                    headers={**headers, "Origin": "https://attacker.invalid"},
                ) as response:
                    assert response.status == 403
                async with client.post(url + "/api/save", data="{}", headers=headers) as response:
                    assert response.status == 403
                async with client.get(url + "/api/config", headers=headers) as response:
                    snapshot = await response.json()
                discord = json.loads(snapshot["sections"]["Discord"])
                discord["owner_id"] = 9007199254740993
                async with client.post(
                    url + "/api/save",
                    headers=headers,
                    json={
                        "name": "bridge_config.json",
                        "section": "Discord",
                        "revision": snapshot["revisions"]["bridge_config.json"],
                        "value": json.dumps(discord),
                    },
                ) as response:
                    assert response.status == 200
                async with client.get(url + "/api/config", headers=headers) as response:
                    snapshot = await response.json()
                assert "9007199254740993" in snapshot["sections"]["Discord"]
                assert (
                    json.loads((tmp_path / "bridge_config.json").read_text())["owner_id"]
                    == 9007199254740993
                )
                values = {
                    key: field["value"] for key, field in snapshot["forms"]["Discord"].items()
                }
                values["owner_id"] = "9007199254740995"
                async with client.post(
                    url + "/api/save",
                    headers=headers,
                    json={
                        "name": "bridge_config.json",
                        "section": "Discord",
                        "typed": True,
                        "revision": snapshot["revisions"]["bridge_config.json"],
                        "value": values,
                    },
                ) as response:
                    assert response.status == 200
                assert (
                    json.loads((tmp_path / "bridge_config.json").read_text())["owner_id"]
                    == 9007199254740995
                )
                async with client.get(url + "/api/config", headers=headers) as response:
                    snapshot = await response.json()
                for section, edits in (("Discord", {"allow_work": True}), ("Discord", [])):
                    async with client.post(
                        url + "/api/save",
                        headers=headers,
                        json={
                            "name": "bridge_config.json",
                            "section": section,
                            "revision": snapshot["revisions"]["bridge_config.json"],
                            "value": json.dumps(edits),
                        },
                    ) as response:
                        assert response.status == 400 and "allow_work" not in await response.text()
                for name, value in (
                    ("local_settings.json", snapshot["settings"]),
                    ("public_context.md", "Synthetic public text"),
                ):
                    async with client.post(
                        url + "/api/save",
                        headers=headers,
                        json={
                            "name": name,
                            "value": value,
                            "revision": snapshot["revisions"][name],
                        },
                    ) as response:
                        assert response.status == 200
                async with client.post(
                    url + "/api/redact", headers=headers, json={"text": "public"}
                ) as response:
                    assert await response.json() == {"text": "public"}
                for text in (None, "x" * 12001):
                    async with client.post(
                        url + "/api/redact", headers=headers, json={"text": text}
                    ) as response:
                        assert response.status == 400
        finally:
            await runner.cleanup()

    asyncio.run(scenario())


def test_control_first_run_and_hidden_input_errors(tmp_path):
    source = Path(__file__).resolve().parent.parent
    for name in (
        "bridge_config.example.json",
        "local_settings.example.json",
        "public_context.example.md",
    ):
        (tmp_path / name).write_bytes((source / name).read_bytes())

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
        data = {
            "owner_id": "9007199254740993",
            "channel_id": "301",
            "codex_id": "101",
            "antigravity_id": "102",
            "claude_id": "103",
        }
        try:
            async with aiohttp.ClientSession() as client:
                for invalid in (
                    {},
                    {**data, "owner_id": 201},
                    {**data, "owner_id": "SYNTHETIC-SECRET"},
                ):
                    async with client.post(
                        url + "/api/setup", json=invalid, headers=headers
                    ) as response:
                        assert response.status == 400
                        assert "SYNTHETIC-SECRET" not in await response.text()
                async with client.post(url + "/api/setup", json=data, headers=headers) as response:
                    assert await response.json() == {"initialized": True}
                assert (
                    json.loads((tmp_path / "bridge_config.json").read_text())["owner_id"]
                    == 9007199254740993
                )
        finally:
            await runner.cleanup()

    asyncio.run(scenario())


@pytest.mark.parametrize("launch", [False, True])
def test_explicit_control_launch_cleans_up(tmp_path, launch):
    async def scenario():
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        urls = []

        def opened(url, **options):
            urls.append(url)
            loop.call_soon_threadsafe(stop.set)

        with patch("control_gui.webbrowser.open", opened), patch("builtins.print", opened):
            await control_gui.serve(tmp_path, launch, stop)
        assert len(urls) == 1 and urls[0].startswith("http://127.0.0.1:")
        assert len(urls[0].split("#")[1]) >= 32
        async with aiohttp.ClientSession() as client:
            with pytest.raises(aiohttp.ClientError):
                await client.get(urls[0].split("#")[0])

    asyncio.run(scenario())


def test_control_cli_is_explicit_and_default_wait_cancels_cleanly(tmp_path):
    calls = []

    def stopped(coroutine):
        calls.append(coroutine)
        coroutine.close()

    with (
        patch("sys.argv", ["control_gui.py", "--root", str(tmp_path), "--no-browser"]),
        patch("control_gui.asyncio.run", stopped),
    ):
        runpy.run_module("control_gui", run_name="__main__")
    assert len(calls) == 1

    async def scenario():
        task = asyncio.current_task()
        loop = asyncio.get_running_loop()

        def opened(url):
            loop.call_soon_threadsafe(task.cancel)

        with patch("control_gui.webbrowser.open", opened), pytest.raises(asyncio.CancelledError):
            await control_gui.serve(tmp_path, True)

    asyncio.run(scenario())
