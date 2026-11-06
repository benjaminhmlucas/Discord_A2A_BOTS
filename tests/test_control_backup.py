"""Non-secret export/import through the real validator, storage guards and GUI routes."""

import asyncio
import base64
import copy
import json
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

import aiohttp
from aiohttp import web
import pytest

import bridge_control_config
import bridge_control_journal
import bridge_settings
from bridge_control_config import EXPORT_FORMAT, ControlConfig
from bridge_control_journal import FILE_LIMIT
from bridge_errors import CapabilityError
from bridge_settings import IMPORT_JOURNAL
from control_gui import STATE, create_app
from test_control_config import configured

ROOT = Path(__file__).resolve().parent.parent

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
    # The durable import record is written before the first configuration file.
    assert writes[:3] == [IMPORT_JOURNAL, "bridge_config.json", "local_settings.json"]
    assert files(store) == before and not store.journal.pending()

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


CRASH = """
import json, os, sys
from pathlib import Path
sys.path.insert(0, sys.argv[1])
from bridge_control_config import ControlConfig
ControlConfig.known_secrets = lambda *args: ()
store = ControlConfig(sys.argv[2])
bundle = json.loads(Path(sys.argv[3]).read_text(encoding="utf-8"))
original, writes = store.storage.atomic, []
def crash(name, data):
    original(name, data)
    writes.append(name)
    if len(writes) == int(sys.argv[4]):
        os._exit(73)  # Abrupt exit: no exception handler or rollback runs.
store.storage.atomic = crash
store.restore(bundle, store.snapshot()["revisions"])
"""


def mixed_root_bundle(store, tmp_path):
    """A valid import whose files are only consistent together (shared memory root)."""
    bundle = store.export()
    root = tmp_path / "new-private-memory"
    root.mkdir()
    bundle["bridge_config.json"]["memory"] = {
        "enabled": True,
        "root": str(root),
        "files": {},
        "user_ids": [OWNER],
        "bot_ids": [101],
        "credential_env": [],
    }
    bundle["local_settings.json"]["memory_dir"] = str(root)
    bundle["public_context.md"] = "Imported context\n"
    store.validate(bundle["bridge_config.json"], bundle["local_settings.json"])
    return bundle


# Exit after the import record, then after each of the three configuration files.
@pytest.mark.parametrize("writes", [1, 2, 3, 4])
@pytest.mark.parametrize("reader", ["control", "bot"])
def test_import_interrupted_by_process_exit_is_rolled_back_before_reads(tmp_path, writes, reader):
    with patch.object(ControlConfig, "known_secrets", return_value=()):
        store = prepared(tmp_path)
        before = files(store)
        payload = tmp_path / "payload.json"
        payload.write_text(json.dumps(mixed_root_bundle(store, tmp_path)), encoding="utf-8")
        child = subprocess.run(
            [sys.executable, "-c", CRASH, str(ROOT), str(tmp_path), str(payload), str(writes)],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert child.returncode == 73, child.stderr
        assert (tmp_path / IMPORT_JOURNAL).is_file()
        if reader == "control":
            # A new window (or any configuration read) restores the previous files first.
            snapshot = ControlConfig(tmp_path).snapshot()
            assert snapshot["config"]["owner_id"] == OWNER
        else:
            # Bot startup recovers before it reads its identity or local settings.
            bridge_settings.recover_interrupted_import(tmp_path)
        assert files(store) == before and not store.journal.pending()
        assert bridge_control_journal.recover(tmp_path) is False


def test_import_recovery_conflicts_and_damaged_records_fail_closed(tmp_path):
    with patch.object(ControlConfig, "known_secrets", return_value=()):
        store = prepared(tmp_path)
        before = files(store)
        after = {**before, "public_context.md": b"Imported\n"}
        with store.locked():
            store.journal.begin(before, after)
        (tmp_path / "public_context.md").write_bytes(b"Edited by hand\n")
        with pytest.raises(CapabilityError, match="later edit of public_context.md"):
            store.snapshot()
        assert store.journal.pending()
        assert (tmp_path / "public_context.md").read_bytes() == b"Edited by hand\n"

        path = tmp_path / IMPORT_JOURNAL
        record = json.loads(path.read_text(encoding="utf-8"))
        oversized = base64.b64encode(b"x" * (FILE_LIMIT + 1)).decode()
        for damaged in (
            "not json",
            "[]",
            json.dumps({**record, "format": "other"}),
            json.dumps({**record, "next": {}}),
            json.dumps({**record, "previous": {**record["previous"], "public_context.md": "!"}}),
            json.dumps(
                {**record, "previous": {**record["previous"], "public_context.md": oversized}}
            ),
            json.dumps({**record, "next": {**record["next"], "public_context.md": 7}}),
        ):
            path.write_text(damaged, encoding="utf-8")
            with pytest.raises(CapabilityError, match="unreadable"):
                store.snapshot()

        # The new version of a file is accepted, but a rollback that does not read back
        # exactly keeps the record for the next attempt.
        path.write_text(json.dumps(record), encoding="utf-8")
        (tmp_path / "public_context.md").write_bytes(b"Imported\n")
        original = store.storage.atomic
        with (
            patch.object(store.storage, "atomic", lambda name, data: original(name, data + b"!")),
            pytest.raises(CapabilityError, match="verification failed"),
        ):
            store.snapshot()
        assert store.journal.pending()
        (tmp_path / "public_context.md").write_bytes(b"Imported\n")
        # A reader already holding the configuration lock recovers without retaking it.
        with store.locked():
            assert store.snapshot()["context"] == before["public_context.md"].decode()
        assert files(store) == before and not store.journal.pending()
