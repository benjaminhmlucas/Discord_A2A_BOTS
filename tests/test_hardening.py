"""Regression tests for trust boundaries, persistent quotas and Windows I/O failures."""

import asyncio
import json
import sqlite3
import threading
import os
import subprocess
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import test_bridge as fixtures
from bridge_health_io import write_health
from bridge_privacy import Privacy
from bridge_runtime import Bridge, load_config
from bridge_state import State


class Hardening(unittest.IsolatedAsyncioTestCase):
    setUp = fixtures.Tests.setUp
    tearDown = fixtures.Tests.tearDown

    async def test_work_uses_only_explicit_owner_text_and_ignores_outsiders(self):
        fixtures.Message(1, "UNTRUSTED-HISTORY", self.channel, fixtures.Author(42))
        outsider = fixtures.Message(
            2, f"<@{fixtures.C}> /work bad", self.channel, fixtures.Author(42)
        )
        await self.c.handle(outsider)
        self.assertEqual(self.channel.sent, [])
        self.c.config["allowed_user_ids"].append(42)
        await self.c.handle(outsider)
        self.assertIn("only the owner", self.channel.sent[-1][0].content)
        owner = fixtures.Author()
        owner.display_name = "UNTRUSTED-NAME"
        request = fixtures.Message(
            3, f"<@{fixtures.C}> /work explicit-owner-task", self.channel, owner
        )
        request.attachments = [
            SimpleNamespace(filename="UNTRUSTED-FILE", url="https://example.invalid/UNTRUSTED-URL")
        ]
        (self.root / "public_context.md").write_text("UNTRUSTED-PUBLIC")
        await self.c.handle(request)
        prompt, work = self.calls[0]
        self.assertTrue(work)
        self.assertIn("explicit-owner-task", prompt)
        self.assertNotIn("UNTRUSTED-", prompt)
        self.assertTrue(any("A reply" in m.content for m, _ in owner.dm.sent))

    async def test_quota_blocks_provider_and_discussion_handoff(self):
        self.c.config["bot_requests_per_day"] = 1
        await self.c.handle(fixtures.Message(1, f"<@{fixtures.C}> first", self.channel))
        before = len(self.channel.sent)
        await self.c.handle(fixtures.Message(2, f"<@{fixtures.C}> /discuss 3 second", self.channel))
        self.assertEqual(len(self.calls), 1)
        self.assertIn("request limit", self.channel.sent[-1][0].content)
        self.assertEqual(len(self.channel.sent), before + 1)
        self.assertEqual(self.channel.sent[-1][1]["reference"].message_id, 2)
        self.assertEqual(self.c.pending, 0)
        self.assertFalse(self.c.lock.locked())
        with self.c.state.connect() as db:
            self.assertEqual(db.execute("SELECT status FROM discussions").fetchone()[0], "failed")
        await self.c.handle(fixtures.Message(3, f"<@{fixtures.C}> /work third", self.channel))
        self.assertEqual(len(self.calls), 1)

    async def test_privacy_scans_run_off_event_loop_and_refresh_new_rules_before_reply(self):
        main_thread = threading.get_ident()
        threads = []
        refresh = self.c.privacy.refresh

        def checked_refresh():
            threads.append(threading.get_ident())
            return refresh()

        async def reply(prompt, work=False):
            self.assertNotIn("HIDDEN VALUE", prompt)
            (self.memory / "late.md").write_text(
                "<!--PRIVATE:START-->LATE-PRIVATE-VALUE<!--PRIVATE:END-->"
            )
            return "LATE-PRIVATE-VALUE"

        self.c.provider = reply
        with patch.object(self.c.privacy, "refresh", side_effect=checked_refresh):
            await self.c.handle(fixtures.Message(1, f"<@{fixtures.C}> HIDDEN VALUE", self.channel))
        self.assertEqual(len(threads), 2)  # One input batch, then fresh output rules.
        self.assertTrue(all(identity != main_thread for identity in threads))
        self.assertEqual(self.channel.sent[-1][0].content, "[private]")

    async def test_injected_services_reuse_the_same_policy_and_state(self):
        bridge = Bridge(
            self.c.client,
            fixtures.C,
            self.provider,
            lambda _: None,
            self.root,
            config=self.c.config,
            state=self.c.state,
            privacy=self.c.privacy,
        )
        self.assertIs(bridge.state, self.c.state)
        self.assertIs(bridge.privacy, self.c.privacy)
        await bridge.handle(fixtures.Message(1, f"<@{fixtures.C}> HIDDEN VALUE", self.channel))
        self.assertNotIn("HIDDEN VALUE", self.calls[0][0])

    async def test_queue_timeout_refunds_daily_capacity_but_keeps_admission_rate(self):
        self.c.config.update(
            bot_requests_per_day=1,
            bot_requests_per_minute=2,
            user_requests_per_minute=2,
            queue_wait_seconds=0.002,
        )
        await self.c.lock.acquire()
        try:
            await self.c.handle(fixtures.Message(1, f"<@{fixtures.C}> waiting", self.channel))
        finally:
            self.c.lock.release()
        self.assertIn("timed out", self.channel.sent[-1][0].content)
        self.assertEqual(self.calls, [])
        with self.c.state.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM provider_budget").fetchone()[0], 0)
            self.assertEqual(db.execute("SELECT count(*) FROM request_budget").fetchone()[0], 1)
        await self.c.handle(fixtures.Message(2, f"<@{fixtures.C}> next", self.channel))
        self.assertEqual(len(self.calls), 1)
        await self.c.handle(fixtures.Message(3, f"<@{fixtures.C}> limited", self.channel))
        self.assertEqual(len(self.calls), 1)
        self.assertIn("request limit", self.channel.sent[-1][0].content)

    async def test_failed_provider_attempt_stays_charged_and_restart_preserves_it(self):
        self.c.config["bot_requests_per_day"] = 1
        calls = []

        async def fail(prompt, work=False):
            calls.append(prompt)
            raise RuntimeError("synthetic provider failure")

        self.c.provider = fail
        await self.c.handle(fixtures.Message(1, f"<@{fixtures.C}> failing", self.channel))
        self.c.state = State(self.root / "runtime_state/discussions.sqlite3", self.c.config)
        await self.c.handle(fixtures.Message(2, f"<@{fixtures.C}> limited", self.channel))
        self.assertEqual(len(calls), 1)
        with self.c.state.connect() as db:
            self.assertEqual(db.execute("SELECT started FROM provider_budget").fetchone()[0], 1)

    async def test_cancelled_queued_request_releases_daily_capacity(self):
        queued = asyncio.Event()
        send = self.channel.send

        async def capture(text, **kwargs):
            result = await send(text, **kwargs)
            if "Bridge: queued" in text:
                queued.set()
            return result

        self.channel.send = capture
        await self.c.lock.acquire()
        task = asyncio.create_task(
            self.c.handle(fixtures.Message(1, f"<@{fixtures.C}> waiting", self.channel))
        )
        try:
            await asyncio.wait_for(queued.wait(), 2)
            task.cancel()
            with self.assertRaises(asyncio.CancelledError):
                await task
        finally:
            self.c.lock.release()
        self.assertEqual(self.c.pending, 0)
        with self.c.state.connect() as db:
            self.assertEqual(db.execute("SELECT count(*) FROM provider_budget").fetchone()[0], 0)

    async def test_expired_reservation_never_invokes_provider(self):
        with patch.object(self.c.state, "start_request", return_value=False):
            await self.c.handle(fixtures.Message(1, f"<@{fixtures.C}> expired", self.channel))
        self.assertEqual(self.calls, [])
        self.assertIn("timed out", self.channel.sent[-1][0].content)

    async def test_quota_cleanup_failure_does_not_leak_queue_lock(self):
        with patch.object(
            self.c.state,
            "release_request",
            side_effect=sqlite3.OperationalError("synthetic DB failure"),
        ):
            with self.assertRaises(sqlite3.OperationalError):
                await self.c.handle(fixtures.Message(1, f"<@{fixtures.C}> request", self.channel))
        self.assertFalse(self.c.lock.locked())
        self.assertEqual(self.c.pending, 0)

    @unittest.skipUnless(os.name == "nt", "Actual Windows ACL semantics")
    async def test_privacy_denied_subtree_fails_closed_for_fresh_and_cached_filters(self):
        blocked = self.memory / "blocked"
        blocked.mkdir()
        secret = "SYNTHETIC-NESTED-SECRET"
        (blocked / "private.md").write_text("<!--PRIVATE:START-->" + secret + "<!--PRIVATE:END-->")
        self.assertEqual(self.c.privacy.filter(secret), "[private]")
        icacls = Path(os.environ["SYSTEMROOT"]) / "System32/icacls.exe"
        user = os.environ["USERDOMAIN"] + "\\" + os.environ["USERNAME"]

        def acl(*args):
            subprocess.run(
                [str(icacls), str(blocked), *args],
                check=True,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=10,
            )

        try:
            acl("/deny", user + ":(RD)")
            with self.assertRaises(PermissionError):
                list(blocked.iterdir())
            for privacy in (Privacy(self.memory), self.c.privacy):
                with self.assertRaises(PermissionError):
                    privacy.filter(secret)
            await self.c.handle(fixtures.Message(1, f"<@{fixtures.C}> " + secret, self.channel))
            self.assertEqual(self.calls, [])
            self.assertIn("request failed", self.channel.sent[-1][0].content)
            self.assertNotIn(secret, self.channel.sent[-1][0].content)
        finally:
            acl("/remove:d", user)
        self.assertEqual(self.c.privacy.filter(secret), "[private]")


def test_privacy_directory_scan_error_blocks_fresh_and_previously_used_filters(tmp_path):
    path = tmp_path / "rules.md"
    path.write_text("<!--PRIVATE:START-->SYNTHETIC-SECRET<!--PRIVATE:END-->")
    privacy = Privacy(tmp_path)
    assert privacy.filter("SYNTHETIC-SECRET") == "[private]"

    def fail_walk(root, **options):
        assert root == tmp_path and options["followlinks"] is False
        options["onerror"](PermissionError("synthetic directory denial"))

    with patch("bridge_privacy.os.walk", side_effect=fail_walk):
        for instance in (Privacy(tmp_path), privacy):
            with pytest.raises(PermissionError, match="directory denial"):
                instance.filter("SYNTHETIC-SECRET")
    assert privacy.filter("SYNTHETIC-SECRET") == "[private]"


def test_privacy_reparse_and_unreadable_file_block_refresh_until_repaired(tmp_path):
    path = tmp_path / "rules.md"
    path.write_text("<!--PRIVATE:START-->SYNTHETIC-SECRET<!--PRIVATE:END-->")
    privacy = Privacy(tmp_path)
    privacy.refresh()
    with patch.object(
        Path, "lstat", return_value=SimpleNamespace(st_mode=0, st_file_attributes=0x400)
    ):
        with pytest.raises(RuntimeError, match="reparse"):
            privacy.refresh()
    with patch.object(Path, "read_text", side_effect=PermissionError("synthetic ACL")):
        with pytest.raises(PermissionError):
            privacy.refresh()
    assert privacy.filter("synthetic-secret") == "[private]"


def test_atomic_health_retries_sharing_errors_and_preserves_existing_snapshot(tmp_path):
    path = tmp_path / "health.json"
    write_health(path, {"ready": True})
    replace = Path.replace
    calls = []

    def transient(source, destination):
        calls.append(source)
        if len(calls) < 3:
            raise PermissionError("synthetic sharing conflict")
        return replace(source, destination)

    with patch.object(Path, "replace", transient), patch("bridge_health_io.time.sleep") as sleep:
        write_health(path, {"ready": False})
        assert sleep.call_count == 2
    assert json.loads(path.read_text()) == {"ready": False}
    with patch.object(Path, "replace", side_effect=PermissionError("persistent conflict")):
        with pytest.raises(PermissionError):
            write_health(path, {"ready": True})
    assert json.loads(path.read_text()) == {"ready": False}
    with patch.object(Path, "replace", side_effect=OSError("disk failure")):
        with pytest.raises(OSError):
            write_health(path, {})


def test_persistent_atomic_quota_user_minute_bot_minute_and_day(tmp_path):
    config = {
        "user_requests_per_minute": 1,
        "bot_requests_per_minute": 2,
        "bot_requests_per_day": 3,
    }
    state = State(tmp_path / "state.sqlite3", config)
    with patch("bridge_state.time.time", return_value=100000):
        assert state.reserve_request(101, 201)
        assert not state.reserve_request(102, 201)  # User limit spans identities.
        assert state.reserve_request(101, None)  # Continuation still costs bot budget.
        assert not state.reserve_request(101, None)
    with patch("bridge_state.time.time", return_value=100061):
        assert state.reserve_request(101, 201)
        assert not State(tmp_path / "state.sqlite3", config).reserve_request(101, None)
    with patch("bridge_state.time.time", return_value=200000):
        assert state.reserve_request(101, 201)
    config.update(user_requests_per_minute=20, bot_requests_per_minute=4, bot_requests_per_day=4)
    other = State(tmp_path / "concurrent.sqlite3", config)
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(lambda _: bool(other.reserve_request(101, None)), range(16))) == 4


def test_daily_reservation_refund_expiry_spending_and_concurrent_capacity(tmp_path):
    config = {
        "user_requests_per_minute": 20,
        "bot_requests_per_minute": 20,
        "bot_requests_per_day": 1,
        "total_request_seconds": 10,
    }
    state = State(tmp_path / "budget.sqlite3", config)
    with patch("bridge_state.time.time", return_value=100000):
        reservation = state.reserve_request(101, 201)
        assert reservation
        assert not state.reserve_request(101, None)  # Pending capacity cannot be oversold.
        state.release_request(reservation)
        replacement = state.reserve_request(101, 201)
        assert replacement
    with patch("bridge_state.time.time", return_value=100036):
        assert not state.start_request(replacement)
        replacement = state.reserve_request(101, 201)  # Orphaned pending reservation expires.
        assert state.start_request(replacement)
        assert not state.start_request(replacement)
        state.release_request(replacement)
        assert not state.reserve_request(101, None)  # Spent usage cannot be refunded.
        reloaded = State(tmp_path / "budget.sqlite3", config)
        assert not reloaded.reserve_request(101, None)
    with patch("bridge_state.time.time", return_value=186437):
        assert state.reserve_request(101, None)
    config["bot_requests_per_day"] = 3
    concurrent = State(tmp_path / "concurrent-day.sqlite3", config)
    with ThreadPoolExecutor(max_workers=8) as pool:
        reservations = list(pool.map(lambda _: concurrent.reserve_request(101, None), range(12)))
    assert sum(bool(value) for value in reservations) == 3
    for reservation in filter(None, reservations):
        concurrent.release_request(reservation)
    assert concurrent.reserve_request(101, None)


def test_legacy_quota_migration_is_atomic_and_does_not_reimport_new_admissions(tmp_path):
    path = tmp_path / "legacy.sqlite3"
    config = {
        "user_requests_per_minute": 20,
        "bot_requests_per_minute": 20,
        "bot_requests_per_day": 2,
    }
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE request_budget(bot INTEGER, author INTEGER, at REAL)")
        db.execute("INSERT INTO request_budget VALUES (101,201,100000)")
    with patch("bridge_state.time.time", return_value=100061):
        state = State(path, config)
        pending = state.reserve_request(101, 201)
        assert pending
        state.release_request(pending)
        reloaded = State(path, config)
        with reloaded.connect() as db:
            assert db.execute("SELECT count(*) FROM provider_budget").fetchone()[0] == 1
        assert reloaded.reserve_request(101, 201)
        assert not reloaded.reserve_request(101, 201)


@pytest.mark.parametrize(
    "key,value",
    [
        ("allow_work", "false"),
        ("bot_requests_per_day", 0),
        ("bot_requests_per_minute", True),
        ("user_requests_per_minute", 10001),
    ],
)
def test_invalid_security_settings_rejected(tmp_path, key, value):
    data = json.loads((Path(__file__).parent / "fixtures/bridge_config.json").read_text())
    data[key] = value
    (tmp_path / "bridge_config.json").write_text(json.dumps(data))
    with pytest.raises(ValueError):
        load_config(tmp_path)


@pytest.mark.parametrize(
    "platform,found", [("nt", True), ("nt", False), ("posix", True), ("posix", False)]
)
def test_release_checker_uses_executable_resolution_without_windows_open_with(
    tmp_path, platform, found
):
    from scripts import check_release

    (tmp_path / ".git").mkdir()
    executable = "git.exe" if platform == "nt" else "git"
    with (
        patch.object(check_release, "os", SimpleNamespace(name=platform)),
        patch.object(
            check_release.shutil, "which", return_value="/safe/" + executable if found else None
        ),
        patch.object(
            check_release.subprocess, "run", return_value=SimpleNamespace(stdout=b"")
        ) as run,
    ):
        assert list(check_release.files(tmp_path)) == []
    assert run.call_args.args[0][0] == ("/safe/" + executable if found else executable)
