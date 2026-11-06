"""Non-secret export/import through the real validator, storage guards and GUI routes."""

import asyncio
import copy
import json
from unittest.mock import patch

import aiohttp
from aiohttp import web
import pytest

import bridge_control_config
from bridge_control_config import EXPORT_FORMAT
from control_gui import STATE, create_app
from test_control_config import configured

SECRET = "synthetic-control-export-secret-c93d"
OWNER = 9007199254740993


def prepared(tmp_path):
    store = configured(tmp_path)
    snapshot = store.snapshot()
    config = snapshot["config"]
    config["owner_id"] = OWNER
    config["allowed_user_ids"] = [OWNER]
    store.save("bridge_config.json", config, snapshot["revisions"]["bridge_config.json"])
    return store


def files(store):
    return {name: (store.root / name).read_bytes() for name in bridge_control_config.FILES}


def test_export_restore_roundtrip_and_all_or_nothing_validation(tmp_path):
    store = prepared(tmp_path)
    bundle = store.export()
    assert bundle["format"] == EXPORT_FORMAT and bundle["bridge_config.json"]["owner_id"] == OWNER
    text = json.dumps(bundle)
    assert str(OWNER) in text and "runtime_credentials" not in bundle["local_settings.json"]

    changed = copy.deepcopy(bundle)
    changed["bridge_config.json"]["max_turns"] = 4
    changed["public_context.md"] = "Restored public context\n"
    revisions = store.snapshot()["revisions"]
    before = files(store)
    for invalid, message in (
        ([], "Unsupported configuration export"),
        ({**changed, "format": "other"}, "Unsupported configuration export"),
        ({**changed, "extra": 1}, "Unsupported configuration export"),
        ({**changed, "public_context.md": 7}, "Public context must be text"),
        (
            {**changed, "bridge_config.json": {**changed["bridge_config.json"], "max_turns": 99}},
            "maximum turns",
        ),
        (
            {
                **changed,
                "bridge_config.json": {**changed["bridge_config.json"], "allow_work": True},
            },
            "explicit risk confirmation",
        ),
        ({**changed, "public_context.md": "x" * 1048577}, "size limit"),
    ):
        with pytest.raises(ValueError, match=message):
            store.restore(invalid, revisions)
        assert files(store) == before
    with patch.object(bridge_control_config, "legacy", lambda name: SECRET):
        with pytest.raises(ValueError, match="credential screen"):
            store.restore({**changed, "public_context.md": "token " + SECRET}, revisions)
    assert files(store) == before
    with pytest.raises(ValueError, match="changed"):
        store.restore(changed, {**revisions, "public_context.md": "stale"})

    result = store.restore(changed, revisions)
    current = store.snapshot()
    assert result == current["revisions"]
    assert current["config"]["max_turns"] == 4 and current["config"]["owner_id"] == OWNER
    assert current["context"] == "Restored public context\n"
    work = copy.deepcopy(changed)
    work["bridge_config.json"]["allow_work"] = True
    store.restore(work, current["revisions"], confirm_work=True)
    assert store.snapshot()["config"]["allow_work"] is True


def test_partial_write_failures_restore_previous_files(tmp_path):
    store = prepared(tmp_path)
    bundle = store.export()
    bundle["bridge_config.json"]["max_turns"] = 3
    bundle["public_context.md"] = "Changed\n"
    before = files(store)
    original = store.storage.atomic

    writes = []

    def failing_second(name, data):
        # Fail the forward write of the second file whatever its bytes: the restored
        # settings can be byte-identical (LF on POSIX) or differ only in line endings.
        writes.append(name)
        if writes.count("local_settings.json") == 1 and name == "local_settings.json":
            raise OSError("synthetic disk failure")
        original(name, data)

    with patch.object(store.storage, "atomic", failing_second), pytest.raises(OSError):
        store.restore(bundle, store.snapshot()["revisions"])
    assert writes[:2] == ["bridge_config.json", "local_settings.json"]
    assert files(store) == before

    def corrupt_last(name, data):
        original(
            name, data + b" " if name == "public_context.md" and data != before[name] else data
        )

    with patch.object(store.storage, "atomic", corrupt_last), pytest.raises(RuntimeError):
        store.restore(bundle, store.snapshot()["revisions"])
    assert files(store) == before

    snapshot = store.snapshot
    calls = []

    def racing():
        calls.append(1)
        current = snapshot()
        if len(calls) == 2:  # The recheck inside the storage lock sees an external edit.
            current["revisions"]["public_context.md"] = "external"
        return current

    with patch.object(store, "snapshot", racing), pytest.raises(ValueError, match="changed"):
        store.restore(bundle, snapshot()["revisions"])
    assert files(store) == before


def test_export_and_import_routes_keep_ids_exact(tmp_path):
    store = prepared(tmp_path)

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
                async with client.get(url + "/api/export") as response:
                    assert response.status == 403
                async with client.get(url + "/api/export", headers=headers) as response:
                    assert response.headers["Content-Disposition"].startswith("attachment;")
                    assert response.headers["Cache-Control"] == "no-store"
                    text = await response.text()
                assert f'"owner_id": {OWNER}' in text
                edited = text.replace('"max_turns": 15', '"max_turns": 5')
                revisions = (await asyncio.to_thread(store.snapshot))["revisions"]
                for bundle in (7, "{not json", json.dumps({"format": "other"})):
                    async with client.post(
                        url + "/api/import",
                        json={"bundle": bundle, "revisions": revisions},
                        headers=headers,
                    ) as response:
                        assert response.status == 400
                async with client.post(
                    url + "/api/import",
                    json={"bundle": edited, "revisions": revisions, "confirm_work": False},
                    headers=headers,
                ) as response:
                    assert response.status == 200 and (await response.json())["restart_required"]
        finally:
            await runner.cleanup()

    asyncio.run(scenario())
    current = store.snapshot()["config"]
    assert current["owner_id"] == OWNER and current["max_turns"] == 5
