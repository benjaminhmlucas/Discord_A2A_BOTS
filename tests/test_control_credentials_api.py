import asyncio
import json
from unittest.mock import patch

import aiohttp
from aiohttp import web

from bridge_credentials import CredentialStore
from control_gui import STATE, create_app
from test_control_config import configured
from test_runtime_credentials import Backend, SECRET


def test_masked_credential_screen_uses_native_adapter_and_no_secret_outputs(tmp_path):
    store = configured(tmp_path)
    backend = Backend()

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
                async with client.get(url + "/api/credentials", headers=headers) as response:
                    initial = await response.json()
                assert set(initial["credentials"].values()) == {"not_set"}
                async with client.post(
                    url + "/api/credentials",
                    headers=headers,
                    json={
                        "action": "invalid",
                        "value": SECRET,
                    },
                ) as response:
                    assert response.status == 400 and SECRET not in await response.text()
                async with client.post(
                    url + "/api/credentials",
                    headers=headers,
                    json={
                        "action": "set",
                        "name": "GEMINI_API_KEY",
                        "value": SECRET,
                        "revision": initial["revision"],
                    },
                ) as response:
                    assert response.status == 200
                    assert SECRET not in await response.text()
                for path in ("config", "credentials"):
                    async with client.get(url + "/api/" + path, headers=headers) as response:
                        text = await response.text()
                        assert response.status == 200 and SECRET not in text
                        if path == "credentials":
                            status = json.loads(text)
                assert status["credentials"]["GEMINI_API_KEY"] == "set"
                async with client.post(
                    url + "/api/redact", headers=headers, json={"text": "sample " + SECRET}
                ) as response:
                    assert await response.json() == {"text": "sample [private]"}
                async with client.post(
                    url + "/api/credentials",
                    headers=headers,
                    json={
                        "action": "delete",
                        "name": "GEMINI_API_KEY",
                        "revision": status["revision"],
                    },
                ) as response:
                    assert response.status == 200
                    assert SECRET not in await response.text()
                assert not backend.values and SECRET not in str(
                    await asyncio.to_thread(store.snapshot)
                )
        finally:
            await runner.cleanup()

    with patch.object(CredentialStore, "_backend", return_value=backend):
        asyncio.run(scenario())
