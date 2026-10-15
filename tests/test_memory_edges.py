"""Additional memory boundary failures through real files and production request handling."""

import asyncio
import json
import os
import re
import threading
from unittest.mock import patch

import pytest

from bridge_memory import MemoryAccess
from bridge_memory_io import MemoryStore, CONTROL, digest
from bridge_privacy import Privacy
from bridge_http import CapabilityError
from test_bridge import Author, Bridge, Channel, Client, Message
from test_memory import populate, memory_config, owner_dm, C
from test_memory_io import pending_record


def test_private_authorization_root_mismatch_and_proposal_limits(tmp_path):
    root = tmp_path / "memory"
    populate(root)
    config = memory_config(root)
    config["allowed_user_ids"].append(202)
    memory = MemoryAccess(config, lambda _: None)
    with pytest.raises(CapabilityError, match="owner"):
        memory.authorize("/memory private private", Message(1, "", Channel(), Author(202)), C)
    author = owner_dm()
    message = Message(2, "", author.dm, author)

    async def execute(command, privacy=None):
        return await memory.execute(
            memory.authorize(command, message, C), privacy or Privacy(root), lambda v: v
        )

    async def scenario():
        with pytest.raises(CapabilityError, match="privacy source"):
            await execute("/memory read public", Privacy(tmp_path))
        expected = digest((root / "notes.md").read_bytes())
        for _ in range(16):
            await execute(f"/memory propose notes {expected} " + '{"text":"new"}')
        with pytest.raises(CapabilityError, match="limit"):
            await execute(f"/memory propose notes {expected} " + '{"text":"new"}')
        memory.proposals.clear()
        config["memory"]["files"]["notes"]["write"] = "append"
        (root / "notes.md").write_bytes(b"x" * 65530)
        with pytest.raises(CapabilityError, match="too large"):
            await execute(
                f"/memory propose notes {digest((root / 'notes.md').read_bytes())} "
                + '{"text":"too much"}'
            )

    asyncio.run(scenario())


@pytest.mark.parametrize("mode", ["commit", "recover"])
def test_cancellation_waits_for_actual_atomic_work_to_finish(tmp_path, mode):
    root = tmp_path / "memory"
    populate(root)
    config = memory_config(root)
    memory = MemoryAccess(config, lambda _: None)
    author = owner_dm()
    message = Message(1, "", author.dm, author)
    entered, release = threading.Event(), threading.Event()
    original_replace = os.replace
    before = (root / "notes.md").read_bytes()

    async def execute(command):
        return await memory.execute(
            memory.authorize(command, message, C), Privacy(root), lambda v: v
        )

    async def scenario():
        if mode == "commit":
            preview = await execute(f"/memory propose notes {digest(before)} " + '{"text":"after"}')
            token = re.search(r"/memory commit ([a-f0-9]{32})", preview)[1]
            command = "/memory commit " + token
        else:
            with memory.store.lock():
                pass
            record = pending_record(root, config["memory"]["files"])
            (root / CONTROL / "pending.json").write_text(json.dumps(record), encoding="utf-8")
            (root / "notes.md").write_bytes(b"after")
            command = "/memory recover " + record["id"]

        def delayed(source, destination, **options):
            if str(destination).endswith("notes.md"):
                entered.set()
                assert release.wait(3)
            return original_replace(source, destination, **options)

        with patch.object(os, "replace", delayed):
            task = asyncio.create_task(execute(command))
            assert await asyncio.to_thread(entered.wait, 2)
            task.cancel()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert (root / "notes.md").read_bytes() == (b"after" if mode == "commit" else before)
        assert memory.store.pending() is None
        if mode == "recover":
            record = pending_record(root, config["memory"]["files"])
            (root / CONTROL / "pending.json").write_text(json.dumps(record), encoding="utf-8")
            assert "recovered" in await execute("/memory recover " + record["id"])

    try:
        asyncio.run(scenario())
    finally:
        release.set()


def test_dm_other_commands_and_data_mentions_do_not_dispatch(tmp_path):
    root = tmp_path / "memory"
    populate(root)
    calls = []

    async def provider(*args, **options):
        calls.append(args)
        return "unexpected"

    async def scenario():
        bridge = Bridge(
            Client(C),
            C,
            provider,
            lambda _: None,
            root=tmp_path,
            memory_dir=root,
            config=memory_config(root),
        )
        author = owner_dm()
        await bridge.handle(Message(1, "hello", author.dm, author))
        channel = Channel()
        await bridge.handle(Message(2, "<@102> <@101> /memory read public", channel))
        await bridge.handle(Message(3, "/memory read public <@101>", channel))
        assert not calls and not channel.sent and not author.dm.sent

    asyncio.run(scenario())


def test_reads_reject_real_file_replacement_growth_and_audit_hardlinks(tmp_path):
    root = tmp_path / "memory"
    populate(root)
    store = MemoryStore(root, memory_config(root)["memory"]["files"])
    real_open, real_fstat = os.open, os.fstat
    replaced = [False]

    def replace_before_open(path, *args, **kwargs):
        if str(path).endswith("notes.md") and not replaced[0]:
            replaced[0] = True
            temp = root / "replacement"
            temp.write_bytes(b"other inode")
            os.replace(temp, root / "notes.md")
        return real_open(path, *args, **kwargs)

    with (
        patch.object(os, "open", replace_before_open),
        pytest.raises(CapabilityError, match="before read"),
    ):
        store.read("notes.md")
    inode = (root / "notes.md").stat().st_ino

    def grow_after_stat(fd):
        value = real_fstat(fd)
        if value.st_ino == inode:
            (root / "notes.md").write_bytes(b"x" * 65537)
        return value

    with (
        patch.object(os, "fstat", grow_after_stat),
        pytest.raises(CapabilityError, match="changed during"),
    ):
        store.read("notes.md")
    with store.lock():
        pass
    assert store.pending() is None
    record = pending_record(root, store.files)
    record["before"] = "x" * 65537
    record["before_hash"] = digest(record["before"].encode())
    (root / CONTROL / "pending.json").write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(CapabilityError):
        store.pending()
    (root / CONTROL / "pending.json").unlink()

    def hardlink_audit(path, *args, **kwargs):
        descriptor = real_open(path, *args, **kwargs)
        if str(path).endswith("audit.jsonl"):
            os.link(root / CONTROL / "audit.jsonl", root / "audit-hardlink")
        return descriptor

    with (
        patch.object(os, "open", hardlink_audit),
        pytest.raises(CapabilityError, match="audit file"),
    ):
        store.audit(record, "test")


def test_absent_control_pending(tmp_path):
    root = tmp_path / "memory"
    populate(root)
    assert MemoryStore(root, memory_config(root)["memory"]["files"]).pending() is None
