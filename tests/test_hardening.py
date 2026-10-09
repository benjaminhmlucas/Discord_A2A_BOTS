"""Regression tests for trust boundaries, persistent quotas and Windows I/O failures."""

import json
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
        await self.c.handle(fixtures.Message(2, f"<@{fixtures.C}> /discuss 3 second", self.channel))
        self.assertEqual(len(self.calls), 1)
        self.assertIn("request limit", self.channel.sent[-1][0].content)
        self.assertEqual(self.c.pending, 0)
        self.assertFalse(self.c.lock.locked())
        with self.c.state.connect() as db:
            self.assertEqual(db.execute("SELECT status FROM discussions").fetchone()[0], "failed")
        await self.c.handle(fixtures.Message(3, f"<@{fixtures.C}> /work third", self.channel))
        self.assertEqual(len(self.calls), 1)

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

    @unittest.skipUnless(os.name == "nt", "Actual Windows ACL semantics")
    async def test_privacy_denied_subtree_fails_closed_for_fresh_and_cached_filters(self):
        blocked = self.memory / "blocked"
        blocked.mkdir()
        secret = "SYNTHETIC-NESTED-SECRET"
        (blocked / "private.md").write_text("<!--PRIVATE:START-->" + secret + "<!--PRIVATE:END-->")
        self.assertEqual(self.c.privacy.filter(secret), "[private]")
        prior = self.c.privacy.secrets.copy()
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
            self.assertEqual(self.c.privacy.secrets, prior)
            await self.c.handle(fixtures.Message(1, f"<@{fixtures.C}> " + secret, self.channel))
            self.assertEqual(self.calls, [])
            self.assertIn("request failed", self.channel.sent[-1][0].content)
            self.assertNotIn(secret, self.channel.sent[-1][0].content)
        finally:
            acl("/remove:d", user)
        self.assertEqual(self.c.privacy.filter(secret), "[private]")


def test_privacy_reparse_and_unreadable_file_keep_previous_rules(tmp_path):
    path = tmp_path / "rules.md"
    path.write_text("<!--PRIVATE:START-->SYNTHETIC-SECRET<!--PRIVATE:END-->")
    privacy = Privacy(tmp_path)
    privacy.refresh()
    prior = privacy.secrets.copy()
    with patch.object(
        Path, "lstat", return_value=SimpleNamespace(st_mode=0, st_file_attributes=0x400)
    ):
        with pytest.raises(RuntimeError, match="reparse"):
            privacy.refresh()
    with patch.object(Path, "read_text", side_effect=PermissionError("synthetic ACL")):
        with pytest.raises(PermissionError):
            privacy.refresh()
    assert privacy.secrets == prior
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
        assert sum(pool.map(lambda _: other.reserve_request(101, None), range(16))) == 4


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
