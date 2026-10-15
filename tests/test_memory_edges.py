"""Additional memory boundary failures through real files and production request handling."""

import asyncio
import json
import os
import re
import threading
from types import SimpleNamespace
from unittest.mock import patch

import discord
import pytest
from discord.state import ConnectionState

from bridge_authorization import owner_memory_dm
from bridge_capabilities import Capabilities
from bridge_memory import MAX_TEXT, MemoryAccess
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
    # Pause the transaction's final filesystem step: the note replacement for a commit,
    # and closing the pending record for a roll-forward recovery.
    operation, suffix = ("replace", "notes.md") if mode == "commit" else ("unlink", "pending.json")
    original = getattr(os, operation)
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

        def delayed(*args, **options):
            if str(args[-1]).endswith(suffix):
                entered.set()
                assert release.wait(3)
            return original(*args, **options)

        with patch.object(os, operation, delayed):
            task = asyncio.create_task(execute(command))
            assert await asyncio.to_thread(entered.wait, 2)
            task.cancel()
            release.set()
            with pytest.raises(asyncio.CancelledError):
                await task
        # Both transactions completed despite cancellation; recovery kept the confirmed text.
        assert (root / "notes.md").read_bytes() == b"after"
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


@pytest.mark.parametrize("command", ["/memory read public", "/memory private notes"])
def test_excerpt_limit_cannot_expose_a_partial_credential(tmp_path, command):
    root = tmp_path / "memory"
    populate(root)
    config = memory_config(root)
    canary = "synthetic-credential-canary"
    text = "a" * (MAX_TEXT - 10) + canary
    for name in ("public.md", "notes.md"):
        (root / name).write_text(text, encoding="utf-8")
    author = owner_dm()
    message = Message(1, "", author.dm, author)

    async def scenario():
        with patch.dict(os.environ, {"BOTBRIDGE_MEMORY_TEST_KEY": canary}):
            capabilities = Capabilities(config, lambda _: None)
            request = capabilities.authorize(command, message, C)
            return await capabilities.execute(request, Privacy(root))

    result = asyncio.run(scenario())
    # Redaction runs on the whole note before the 12000-character excerpt limit.
    assert canary[:10] not in result and "a" * (MAX_TEXT - 10) in result


def test_missing_memory_file_reports_a_fixed_memory_reason(tmp_path):
    root = tmp_path / "memory"
    populate(root)
    (root / "public.md").unlink()

    async def provider(*args, **options):
        raise AssertionError("memory commands never call a provider")

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
        channel = Channel()
        await bridge.handle(Message(1, "<@101> /memory read public", channel))
        assert channel.sent[-1][0].content == (
            "Bridge: memory request refused (Memory file unavailable)."
        )
        assert bridge.health["last_error"] == "CapabilityError" and not bridge.lock.locked()

    asyncio.run(scenario())


def discord_message(**overrides):
    """Build an incoming message with discord.py's own gateway parser, not a fake."""
    events = []
    state = ConnectionState(
        dispatch=lambda event, *args: events.append((event, args)),
        handlers={},
        hooks={},
        http=None,
        intents=discord.Intents.default(),
    )
    state.user = None
    author = {"id": "201", "username": "owner", "discriminator": "0", "avatar": None}
    data = {
        "id": "900",
        "channel_id": "401",
        "author": {**author, **overrides.pop("author", {})},
        "content": "/memory status",
        "timestamp": "2026-01-01T00:00:00+00:00",
        "edited_timestamp": None,
        "tts": False,
        "mention_everyone": False,
        "mentions": [],
        "mention_roles": [],
        "attachments": [],
        "embeds": [],
        "pinned": False,
        "type": 0,
        **overrides,
    }
    state.parse_message_create(data)
    return next(args[0] for event, args in events if event == "message")


def test_real_discord_dm_authorizes_only_the_owner(tmp_path):
    root = tmp_path / "memory"
    populate(root)
    config = memory_config(root)
    memory = MemoryAccess(config, lambda _: None)
    owner = discord_message()
    # discord.py leaves the recipient unknown on an inbound DM; ownership comes from
    # the authenticated author and the private, non-guild channel type.
    assert owner.channel.type is discord.ChannelType.private and owner.channel.recipient is None
    assert owner_memory_dm(owner, C, config)
    assert memory.authorize("/memory status", owner, C).mode == "status"
    group = discord_message()
    group.channel = SimpleNamespace(id=401, type=discord.ChannelType.group)
    unknown = discord_message()
    unknown.channel = SimpleNamespace(id=0, type=discord.ChannelType.private)
    for denied in (
        discord_message(author={"id": "202"}),
        discord_message(webhook_id="5"),
        discord_message(guild_id="999"),
        group,
        unknown,
    ):
        assert not owner_memory_dm(denied, C, config)
        with pytest.raises(CapabilityError):
            memory.authorize("/memory status", denied, C)
    bot = discord_message(author={"bot": True})
    assert not owner_memory_dm(bot, C, config)
    assert memory.authorize("/memory status", bot, C) is None
    assert not owner_memory_dm(owner, 999, config)


def test_dm_command_requires_the_verified_owner_dm(tmp_path):
    root = tmp_path / "memory"
    populate(root)

    async def provider(*args, **options):
        raise AssertionError("memory commands never call a provider")

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
        author.resolved_dm.id = 402  # create_dm() names a different DM than the inbound one.
        await bridge.handle(Message(1, "/memory private private", author.dm, author))
        assert author.dm.sent[-1][0].content == (
            "Bridge: memory request refused (Private memory destination denied)."
        )
        assert "SYNTHETIC PRIVATE VALUE" not in "\n".join(m.content for m, _ in author.dm.sent)

    asyncio.run(scenario())


def test_backup_count_stops_writes_before_reads_are_blocked(tmp_path):
    root = tmp_path / "memory"
    populate(root)
    store = MemoryStore(root, memory_config(root)["memory"]["files"])
    with store.lock():
        pass
    for index in range(64):
        (root / CONTROL / f"backup-orphan-{index}.md").write_text("archive", encoding="utf-8")
    before = (root / "notes.md").read_bytes()
    with pytest.raises(CapabilityError, match="capacity"):
        store.commit("notes", digest(before), b"after")
    assert len(store.backup_texts()) == 64 and (root / "notes.md").read_bytes() == before


def test_privacy_scan_tolerates_only_vanished_non_markdown_entries(tmp_path):
    root = tmp_path / "memory"
    populate(root)
    walk = os.walk

    def listing(name):
        # A directory listing that names an entry removed before it is inspected.
        def fake_walk(top, **options):
            for directory, children, files in walk(top, **options):
                yield directory, children, files + [name]

        return fake_walk

    with patch("bridge_privacy.os.walk", listing(".memory-vanished.tmp")):
        assert Privacy(root).refresh()
    with patch("bridge_privacy.os.walk", listing("vanished.md")):
        with pytest.raises(FileNotFoundError):
            Privacy(root).refresh()


def test_credential_containing_a_private_value_is_masked_whole(tmp_path):
    root = tmp_path / "memory"
    populate(root)
    credential = "credprefix-SYNTHETIC PRIVATE VALUE-credsuffix"
    (root / "public.md").write_text("Shared: " + credential, encoding="utf-8")
    config = memory_config(root)
    message = Message(1, "", Channel())

    async def scenario():
        with patch.dict(os.environ, {"BOTBRIDGE_MEMORY_TEST_KEY": credential}):
            capabilities = Capabilities(config, lambda _: None)
            request = capabilities.authorize("/memory read public", message, C)
            return await capabilities.execute(request, Privacy(root))

    result = asyncio.run(scenario())
    assert "credprefix" not in result and "credsuffix" not in result
    assert "[REDACTED CREDENTIAL]" in result
