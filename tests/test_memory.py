"""Exercise actual memory policy, files, quota state and Discord consumer boundaries."""

import asyncio
import json
import os
import re
import copy
import sys
import subprocess
import time
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

import pytest
import discord

from bridge_capabilities import Capabilities
from bridge_http import CapabilityError
from bridge_privacy import Privacy
from bridge_memory import MemoryAccess
from bridge_memory_io import MemoryStore, digest, CONTROL
from test_bridge import Author, Bridge, Channel, Client, Message

OWNER, C = 201, 101
FIXTURE = Path(__file__).parent / "fixtures/bridge_config.json"


def memory_config(root):
    config = json.loads(FIXTURE.read_text())
    config["memory"] = {
        "enabled": True,
        "root": str(root),
        "user_ids": [OWNER],
        "bot_ids": [C],
        "credential_env": ["BOTBRIDGE_MEMORY_TEST_KEY"],
        "files": {
            "public": {"path": "public.md", "public": True, "private": False, "write": None},
            "private": {"path": "private.md", "public": False, "private": True, "write": None},
            "notes": {"path": "notes.md", "public": False, "private": True, "write": "replace"},
        },
    }
    return config


def populate(root):
    root.mkdir()
    (root / "public.md").write_text(
        "Approved facts; SYNTHETIC PRIVATE VALUE; synthetic-credential-canary", encoding="utf-8"
    )
    (root / "private.md").write_text(
        "<!--PRIVATE:START-->SYNTHETIC PRIVATE VALUE<!--PRIVATE:END-->", encoding="utf-8"
    )
    (root / "notes.md").write_text("Initial notes.", encoding="utf-8")


def test_public_memory_real_consumer_redaction_and_no_provider(tmp_path):
    root = tmp_path / "memory"
    populate(root)
    config = memory_config(root)
    calls, logs = [], []

    async def provider(*args, **kwargs):
        calls.append(args)
        return "unexpected provider"

    async def scenario():
        bridge = Bridge(
            Client(C), C, provider, logs.append, root=tmp_path, memory_dir=root, config=config
        )
        channel = Channel()
        public = root / "public.md"
        public.write_text(public.read_text() + '\nSecond "quoted" line.', encoding="utf-8")
        with patch.dict(os.environ, {"BOTBRIDGE_MEMORY_TEST_KEY": "synthetic-credential-canary"}):
            await bridge.handle(Message(1, "<@101> /memory read public", channel))
        output = "\n".join(message.content for message, _ in channel.sent)
        assert "Memory public (approved public excerpt):\nApproved facts" in output
        # A direct reply shows the note as written, not as an escaped JSON string.
        assert '\nSecond "quoted" line.' in output and "\\n" not in output
        assert "SYNTHETIC PRIVATE VALUE" not in output
        assert "synthetic-credential-canary" not in output
        assert "untrusted data" not in output and not calls
        assert not bridge.lock.locked() and bridge.pending == 0
        assert "SYNTHETIC PRIVATE VALUE" not in "\n".join(logs)
        assert "synthetic-credential-canary" not in "\n".join(logs)

    asyncio.run(scenario())


def owner_dm():
    """Owner whose inbound DM channel matches discord.py's shape.

    discord.py 2.x builds the channel of an incoming DM without recipients
    (DMChannel._from_message), so `recipient` is None there. Only create_dm()
    returns a channel with the recipient filled in; both share the DM's id.
    """
    author = Author()
    author.dm.id = 401
    author.dm.type = discord.ChannelType.private
    author.dm.recipient = None
    resolved = Channel(401)
    resolved.type, resolved.recipient, resolved.sent = (
        discord.ChannelType.private,
        author,
        author.dm.sent,
    )
    author.resolved_dm = resolved

    async def create_dm():
        return resolved

    author.create_dm = create_dm
    return author


def test_private_reads_exact_preview_confirm_replay_and_conflict(tmp_path):
    root = tmp_path / "memory"
    populate(root)
    config = memory_config(root)
    calls, logs = [], []

    async def provider(*args, **kwargs):
        calls.append(args)
        return "unexpected"

    async def scenario():
        bridge = Bridge(
            Client(C), C, provider, logs.append, root=tmp_path, memory_dir=root, config=config
        )
        author = owner_dm()
        public = Channel()
        await bridge.handle(Message(1, "<@101> /memory private private", public, author))
        assert "SYNTHETIC PRIVATE VALUE" in "\n".join(m.content for m, _ in author.dm.sent)
        assert "SYNTHETIC PRIVATE VALUE" not in "\n".join(m.content for m, _ in public.sent)
        note = root / "notes.md"
        text = 'Decision with <@102> [bridge:example] and "quotes"\nSecond line.'
        original = note.read_bytes()
        command = f"/memory propose notes {digest(original)} " + json.dumps({"text": text})
        await bridge.handle(Message(2, command, author.dm, author))
        assert note.read_bytes() == original
        preview = "\n".join(m.content for m, _ in author.dm.sent)
        token = re.findall(r"/memory commit ([a-f0-9]{32})", preview)[-1]
        assert text in preview
        await bridge.handle(Message(3, "/memory commit " + token, author.dm, author))
        assert note.read_bytes() == text.encode()
        receipt = json.loads(next((root / CONTROL).glob("receipt-*.json")).read_text())
        assert receipt["before_hash"] == digest(original) and receipt["after_hash"] == digest(
            text.encode()
        )
        journal = (root / CONTROL / "audit.jsonl").read_bytes()
        assert "delivered privately" not in "\n".join(m.content for m, _ in author.dm.sent)
        assert any("delivered privately" in m.content for m, _ in public.sent)
        await bridge.handle(Message(4, "/memory commit " + token, author.dm, author))
        assert author.dm.sent[-1][0].content == (
            "Bridge: memory request refused (Memory confirmation unavailable)."
        )
        assert (
            note.read_bytes() == text.encode()
            and (root / CONTROL / "audit.jsonl").read_bytes() == journal
        )
        await bridge.handle(Message(5, "/memory status", author.dm, author))
        assert "no pending recovery" in "\n".join(m.content for m, _ in author.dm.sent)
        await bridge.handle(
            Message(
                6,
                f"/memory propose notes {digest(note.read_bytes())} "
                + json.dumps({"text": "pending change"}),
                author.dm,
                author,
            )
        )
        token = re.findall(
            r"/memory commit ([a-f0-9]{32})", "\n".join(m.content for m, _ in author.dm.sent)
        )[-1]
        note.write_bytes(b"external edit")
        await bridge.handle(Message(7, "/memory commit " + token, author.dm, author))
        assert note.read_bytes() == b"external edit"
        assert author.dm.sent[-1][0].content == (
            "Bridge: memory request refused (Memory revision conflict)."
        )
        assert not calls and bridge.pending == 0 and not bridge.lock.locked()
        assert "SYNTHETIC PRIVATE VALUE" not in "\n".join(logs)
        assert text not in "\n".join(logs)

    asyncio.run(scenario())


def test_private_destination_failure_prevents_actual_memory_opens(tmp_path):
    root = tmp_path / "memory"
    populate(root)
    seen, active, calls = [], [True], []

    def audit(event, args):
        if (
            active[0]
            and event == "open"
            and isinstance(args[0], (str, bytes))
            and str(root) in str(args[0])
        ):
            seen.append(args[0])

    sys.addaudithook(audit)

    async def provider(*args, **kwargs):
        calls.append(args)
        return "unexpected"

    async def scenario():
        author = owner_dm()
        author.resolved_dm.recipient = Author(999)
        bridge = Bridge(
            Client(C),
            C,
            provider,
            lambda _: None,
            root=tmp_path,
            memory_dir=root,
            config=memory_config(root),
        )
        await bridge.handle(Message(1, "<@101> /memory private private", Channel(), author))
        assert not seen and not calls and not bridge.capabilities.memory.proposals

    try:
        asyncio.run(scenario())
    finally:
        active[0] = False


@pytest.mark.parametrize(
    "command",
    [
        "/memory",
        "/memory read unknown",
        "/memory private public",
        "/memory read public trailing",
        "/memory status trailing",
        "/memory commit bad",
        "/memory recover " + "f" * 32 + " extra",
        "/memory propose notes " + "f" * 64 + " invalid",
        "/memory propose notes " + "f" * 64 + " []",
        "/memory propose notes " + "f" * 64 + ' {"text":1}',
        "/memory propose notes " + "f" * 64 + ' {"text":"x","other":"x"}',
        "/memory propose private " + "f" * 64 + ' {"text":"x"}',
        "/memory propose notes bad " + '{"text":"x"}',
    ],
)
def test_command_policy_fails_closed(tmp_path, command):
    root = tmp_path / "memory"
    populate(root)
    memory = MemoryAccess(memory_config(root), lambda _: None)
    author = owner_dm()
    with pytest.raises(CapabilityError):
        memory.authorize(command, Message(1, command, author.dm, author), C)


def test_config_validation_and_disabled_bot_and_quote_behaviour(tmp_path):
    base = memory_config(tmp_path)
    variants = [None, [], {}, {"enabled": 1}, {"enabled": False, "extra": 1}]
    data = base["memory"]
    for key, values in {
        "root": ["relative", "\\\\server\\share", None, 3],
        "files": [
            [],
            {str(i): {} for i in range(33)},
            {"bad name": {}},
            {"public": None},
            {"public": {}},
        ],
        "user_ids": [None, [True], [999]],
        "bot_ids": [None, [], [True], [999]],
        "credential_env": [None, [1], ["invalid-name"], ["x"] * 33],
    }.items():
        for value in values:
            invalid = copy.deepcopy(data)
            invalid[key] = value
            variants.append(invalid)
    definition = data["files"]["notes"]
    for key, values in {
        "path": ["../outside.md", "/outside.md", "a\\b.md", "CON.md", "notes.txt"],
        "public": [1],
        "private": [1, False],
        "write": ["delete"],
    }.items():
        for value in values:
            invalid = copy.deepcopy(data)
            invalid["files"]["notes"] = {**definition, key: value}
            variants.append(invalid)
    for protected in ["AGENTS.md", "STATIC_PROCEDURES.md", "SESSION_LOG.md", "LIVE_STATE.md"]:
        invalid = copy.deepcopy(data)
        invalid["files"]["notes"]["path"] = protected
        variants.append(invalid)
    duplicate = copy.deepcopy(data)
    duplicate["files"]["private"]["path"] = "PUBLIC.md"
    variants.append(duplicate)
    for value in variants:
        with pytest.raises(ValueError):
            MemoryAccess({**base, "memory": value}, lambda _: None)
    missing = copy.deepcopy(base)
    missing.pop("memory")
    memory = MemoryAccess(missing, lambda _: None)
    message = Message(1, "", Channel())
    with pytest.raises(CapabilityError):
        memory.authorize("/memory read public", message, C)
    assert memory.authorize("quoted /memory read public", message, C) is None
    message.author.bot = True
    assert memory.authorize("/memory read public", message, C) is None
    memory = MemoryAccess(base, lambda _: None)
    with pytest.raises(CapabilityError):
        memory.authorize("/memory read public", Message(2, "", Channel(), Author(202)), C)


def test_expired_wrong_bot_and_bad_proposals_never_mutate(tmp_path):
    root = tmp_path / "memory"
    populate(root)
    config = memory_config(root)
    config["memory"]["bot_ids"] = [101, 102]
    memory = MemoryAccess(config, lambda _: None)
    author = owner_dm()
    message = Message(1, "", author.dm, author)
    note = root / "notes.md"
    original = note.read_bytes()

    async def execute(command, bot=C):
        request = memory.authorize(command, message, bot)
        return await memory.execute(request, Privacy(root), lambda value: value)

    async def scenario():
        for text, expected in [("x", "f" * 64), ("<!--PRIVATE:START-->bad", digest(original))]:
            with pytest.raises((CapabilityError, RuntimeError)):
                await execute(f"/memory propose notes {expected} " + json.dumps({"text": text}))
        result = await execute(f"/memory propose notes {digest(original)} " + '{"text":"new"}')
        token = re.search(r"/memory commit ([a-f0-9]{32})", result)[1]
        with pytest.raises(CapabilityError, match="confirmation"):
            await execute("/memory commit " + token, bot=102)
        result = await execute(f"/memory propose notes {digest(original)} " + '{"text":"new"}')
        token = re.search(r"/memory commit ([a-f0-9]{32})", result)[1]
        memory.proposals[token] = replace(memory.proposals[token], expires=time.monotonic() - 1)
        with pytest.raises(CapabilityError, match="confirmation"):
            await execute("/memory commit " + token)
        assert note.read_bytes() == original

    asyncio.run(scenario())


@pytest.mark.parametrize("stage", ["notes.md", "pending.json"])
@pytest.mark.parametrize("mode", ["replace", "append"])
def test_real_process_crash_and_durable_recovery_preserve_audit(tmp_path, mode, stage):
    """Kill a real writer after the note (or only the pending record) was replaced."""
    root = tmp_path / "memory"
    populate(root)
    config = memory_config(root)
    config["memory"]["files"]["notes"]["write"] = mode
    files = config["memory"]["files"]
    note = root / "notes.md"
    before = note.read_bytes()
    after = before + b"\nappended" if mode == "append" else b"new version"
    script = """
import json,os,sys
from pathlib import Path
from bridge_memory_io import MemoryStore,digest
root=Path(sys.argv[1]); files=json.loads(sys.argv[2]); after=bytes.fromhex(sys.argv[3])
real=os.replace
def crash(source,destination,**options):
    real(source,destination,**options)
    if str(destination).endswith(sys.argv[4]):
        os._exit(73)
os.replace=crash
MemoryStore(root,files).commit("notes",digest((root/"notes.md").read_bytes()),after)
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(root), json.dumps(files), after.hex(), stage],
        cwd=Path(__file__).parent.parent,
        capture_output=True,
        timeout=15,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    assert result.returncode == 73, result.stderr
    store = MemoryStore(root, files)
    record = store.pending()
    applied = stage == "notes.md"
    assert record and note.read_bytes() == (after if applied else before)
    audit = root / CONTROL / "audit.jsonl"
    journal = audit.read_bytes() if audit.exists() else b""
    assert "pending receipt" in store.status()
    # Roll forward: keep the confirmed revision if written, otherwise leave the note as is.
    result = store.recover(record["id"])
    assert ("confirmed revision kept" if applied else "change was not applied") in result
    assert note.read_bytes() == (after if applied else before)
    assert audit.read_bytes().startswith(journal)
    outcome = "recovered-applied" if applied else "recovered-unapplied"
    assert f'"outcome":"{outcome}"' in audit.read_text()
    assert store.pending() is None and before.decode() in store.backup_texts()
    with pytest.raises(CapabilityError):
        store.recover(record["id"])


def test_actual_serialized_note_writers_and_history_redaction(tmp_path):
    from concurrent.futures import ThreadPoolExecutor

    root = tmp_path / "memory"
    populate(root)
    files = memory_config(root)["memory"]["files"]
    before = b"<!--PRIVATE:START-->PAST PRIVATE CANARY<!--PRIVATE:END-->"
    note = root / "notes.md"
    note.write_bytes(before)

    def writer(value):
        try:
            return MemoryStore(root, files).commit("notes", digest(before), value)
        except CapabilityError:
            return "conflict"

    with ThreadPoolExecutor(2) as pool:
        results = list(pool.map(writer, [b"first", b"second"]))
    assert sum("committed" in result for result in results) == 1 and results.count("conflict") == 1
    privacy = Privacy(root)
    assert privacy.filter("PAST PRIVATE CANARY") == "[private]"
    audit = (root / CONTROL / "audit.jsonl").read_text()
    assert "PAST PRIVATE CANARY" not in audit


def test_real_root_directory_is_pinned_on_windows(tmp_path):
    if os.name != "nt":
        return  # POSIX pins are exercised by the same operations on Linux CI.
    root = tmp_path / "memory"
    populate(root)
    store = MemoryStore(root, memory_config(root)["memory"]["files"])
    with store.parent("notes.md"):
        with pytest.raises(PermissionError):
            root.rename(tmp_path / "moved")
    assert (root / "notes.md").read_text() == "Initial notes."


@pytest.mark.parametrize(
    "mutation",
    [
        lambda m: setattr(m.author, "id", 999),
        lambda m: setattr(m.author, "bot", 1),
        lambda m: setattr(m, "webhook_id", 1),
        lambda m: setattr(m.channel, "id", 999),
    ],
)
def test_memory_unauthorized_transport_is_denied(tmp_path, mutation):
    root = tmp_path / "memory"
    populate(root)
    caps = Capabilities(memory_config(root), lambda _: None)
    message = Message(1, "<@101> /memory read public", Channel())
    mutation(message)
    with pytest.raises(CapabilityError):
        caps.authorize("/memory read public", message, C)
    assert (root / "notes.md").read_text() == "Initial notes."


def test_memory_private_alias_and_public_write_payload_denied(tmp_path):
    root = tmp_path / "memory"
    populate(root)
    caps = Capabilities(memory_config(root), lambda _: None)
    message = Message(1, "", Channel(), Author(OWNER))
    for command in (
        "/memory read private",
        "/memory commit " + "a" * 32,
        "/memory propose notes " + "a" * 64 + ' {"text":"new"}',
    ):
        with pytest.raises(CapabilityError):
            caps.authorize(command, message, C)


@pytest.mark.parametrize("kind", ["malformed", "oversized", "hardlink", "missing"])
def test_memory_files_fail_closed_through_actual_dispatch(tmp_path, kind):
    root = tmp_path / "memory"
    populate(root)
    private = root / "private.md"
    if kind == "malformed":
        private.write_text("<!--PRIVATE:START-->never close")
    elif kind == "oversized":
        private.write_text("x" * 65537)
    elif kind == "hardlink":
        os.link(private, tmp_path / "outside.md")
    else:
        private.unlink()
    caps = Capabilities(memory_config(root), lambda _: None)
    request = caps.authorize("/memory read public", Message(1, "", Channel()), C)

    error, reason = {
        "malformed": (RuntimeError, "Malformed privacy markers"),
        "oversized": (CapabilityError, "Memory file denied"),
        "hardlink": (CapabilityError, "Memory links denied"),
        "missing": (CapabilityError, "Memory file unavailable"),
    }[kind]

    async def scenario():
        with pytest.raises(error, match=reason):
            await caps.execute(request, Privacy(root))

    asyncio.run(scenario())


@pytest.mark.parametrize("kind", ["linked_directory", "denied_file"])
def test_actual_link_and_permission_denial_prevent_memory_dispatch(tmp_path, kind):
    root = tmp_path / "memory"
    populate(root)
    config = memory_config(root)
    original = (root / "private.md").read_bytes()
    target = root / "private.md"
    linked = root / "linked"

    def windows_run(arguments):
        return subprocess.run(
            arguments,
            check=True,
            capture_output=True,
            timeout=15,
            creationflags=subprocess.CREATE_NO_WINDOW,
        )

    user = os.environ.get("USERDOMAIN", "") + "\\" + os.environ.get("USERNAME", "")
    icacls = str(Path(os.environ.get("SYSTEMROOT", "C:/Windows")) / "System32/icacls.exe")
    if kind == "linked_directory":
        outside = tmp_path / "outside"
        outside.mkdir()
        target = outside / "private.md"
        target.write_bytes(original)
        config["memory"]["files"]["private"]["path"] = "linked/private.md"
        if os.name == "nt":

            def quote(value):
                return "'" + str(value).replace("'", "''") + "'"

            windows_run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "New-Item -ItemType Junction -Path "
                    + quote(linked)
                    + " -Target "
                    + quote(outside)
                    + " | Out-Null",
                ]
            )
        else:
            linked.symlink_to(outside, target_is_directory=True)
    elif os.name == "nt":
        windows_run([icacls, str(target), "/deny", user + ":(RD)"])
    else:
        target.chmod(0)
    try:
        caps = Capabilities(config, lambda _: None)
        request = caps.authorize("/memory read public", Message(1, "", Channel()), C)

        reason = "Memory links denied" if kind == "linked_directory" else "Memory file unavailable"

        async def scenario():
            with pytest.raises(CapabilityError, match=reason):
                await caps.execute(request, Privacy(root))

        asyncio.run(scenario())
    finally:
        if kind == "linked_directory":
            linked.rmdir() if os.name == "nt" else linked.unlink()
        elif os.name == "nt":
            windows_run([icacls, str(target), "/remove:d", user])
        else:
            target.chmod(0o600)
    assert target.read_bytes() == original
    assert not (root / CONTROL).exists()
