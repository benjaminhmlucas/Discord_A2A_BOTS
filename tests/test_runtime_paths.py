import asyncio
import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
import test_bridge as fixtures
from test_bridge import Author, Channel, Message, C, A
from bridge_runtime import dispatch


class RuntimePaths(unittest.IsolatedAsyncioTestCase):
    setUp = fixtures.Tests.setUp
    tearDown = fixtures.Tests.tearDown

    async def test_ready_identity_background_lifecycle(self):
        client = self.c.client
        client.close = AsyncMock()
        client.user.id = 999
        with self.assertRaises(RuntimeError):
            await self.c.ready()
        client.close.assert_awaited_once()
        client.user.id = C
        self.c.heartbeat = AsyncMock()
        await self.c.ready()
        await self.c.background
        await self.c.ready()
        await self.c.background
        self.c.background = SimpleNamespace(done=lambda: False)
        await self.c.ready()
        self.assertEqual(self.c.heartbeat.await_count, 2)

    async def test_heartbeat_expiry_disconnected_missing_channel_and_error(self):
        self.c.client.is_closed = MagicMock(side_effect=[False, False, False, False, True])
        self.c.client.is_ready = MagicMock(side_effect=[True, True, False, True])
        self.c.client.get_channel = MagicMock(side_effect=[self.channel, None, self.channel])
        self.c.state.expired = MagicMock(
            side_effect=[[{"channel": 301}, {"channel": 302}], [{"channel": 301}], []]
        )
        self.c.write_health = MagicMock()
        logs = []
        self.c.log = logs.append
        original_send = self.channel.send
        calls = []

        async def send(text, **kwargs):
            calls.append(text)
            if len(calls) == 2:
                raise OSError("synthetic send failure")
            return await original_send(text, **kwargs)

        self.channel.send = send
        from unittest.mock import patch

        with patch("bridge_runtime.asyncio.sleep", AsyncMock()):
            await self.c.heartbeat()
        self.assertEqual(len(calls), 2)
        self.assertTrue(any("Heartbeat error" in line for line in logs))

    async def test_available_self_invalid_missing_stale_and_ready(self):
        self.assertTrue(self.c.available(C))
        self.assertFalse(self.c.available(999))
        path = self.root / f"runtime_state/health_{A}.json"
        path.write_text("{bad")
        self.assertFalse(self.c.available(A))
        path.write_text('{"ready":true,"timestamp":0}')
        self.assertFalse(self.c.available(A))
        self.a.write_health()
        self.assertTrue(self.c.available(A))

    async def test_history_skip_and_attachment_capture(self):
        Message(1, "skip webhook", self.channel, webhook=1)
        Message(2, "Bridge: queue notice", self.channel)
        Message(3, "earlier question", self.channel)
        request = Message(4, f"<@{C}> attachment question", self.channel)
        request.attachments = [
            SimpleNamespace(filename="fixture.txt", url="https://example.invalid/fixture.txt")
        ]
        await self.c.handle(request)
        text = self.calls[0][0]
        self.assertIn("earlier question", text)
        self.assertIn("fixture.txt", text)
        self.assertNotIn("skip webhook", text)
        self.assertNotIn("queue notice", text)

    async def test_message_gates_mention_order_and_empty_topic(self):
        await self.c.handle(Message(1, "no mention", self.channel))
        await self.c.handle(Message(2, f"<@{C}> self", self.channel, Author(C, True)))
        await self.c.handle(Message(3, f"<@{C}> /discuss 2 hi", Channel(999)))
        await self.c.handle(Message(4, f"<@{A}> <@{C}> /discuss 2 hi", self.channel))
        self.assertFalse(self.calls)
        await self.c.handle(Message(5, f"<@{C}> /discuss 3", self.channel))
        self.assertIn("followed by a topic", self.channel.sent[-1][0].content)
        await self.a.handle(Message(6, f"<@{A}> /work task", self.channel))
        self.assertIn("use CodexBot", self.channel.sent[-1][0].content)
        self.assertFalse(self.calls)

    async def test_claimed_duplicate_aborts_and_full_discussion_fails(self):
        await self.c.handle(Message(1, f"<@{C}> /discuss 3 topic", self.channel))
        trigger = self.channel.sent[-1][0]
        self.a.state.seen(A, trigger.id)
        await self.a.handle(trigger)
        self.assertEqual(len(self.calls), 1)
        self.c.pending = self.c.config["queue_capacity"]
        await self.c.handle(Message(2, f"<@{C}> /discuss 3 next", self.channel))
        with self.c.state.connect() as db:
            self.assertEqual(
                [r[0] for r in db.execute("SELECT status FROM discussions")], ["failed", "failed"]
            )
        self.c.pending = 0

    async def test_empty_work_empty_provider_and_delivery_failures(self):
        await self.c.handle(Message(1, f"<@{C}> /work", self.channel))
        self.assertFalse(self.calls)
        for value in (None, "", "   "):
            self.c.provider = AsyncMock(return_value=value)
            await self.c.handle(Message(10 + len(self.channel.sent), f"<@{C}> hi", self.channel))
            self.assertIn("request failed", self.channel.sent[-1][0].content)
        self.c.provider = self.provider
        self.channel.send = AsyncMock(side_effect=OSError("synthetic send failure"))
        logs = []
        self.c.log = logs.append
        await self.c.handle(Message(50, f"<@{C}> hi", self.channel))
        self.assertTrue(any("Failure notice could not be sent" in line for line in logs))
        self.assertEqual(self.c.pending, 0)

    async def test_single_participant_and_waiting_request_preserve_current_active(self):
        self.c.config["enabled_bots"] = [C]
        self.c.state.config["enabled_bots"] = [C]
        await self.c.handle(Message(1, f"<@{C}> /discuss 2 topic", self.channel))
        self.assertIn("participant is unavailable", self.channel.sent[-1][0].content)
        await self.c.lock.acquire()
        self.c.config["queue_wait_seconds"] = 0.001
        self.c.health["active_message_id"] = 777
        await self.c.handle(Message(2, f"<@{C}> wait", self.channel))
        self.assertEqual(self.c.health["active_message_id"], 777)
        self.c.lock.release()

    async def test_parent_cancellation_aborts_claimed_session(self):
        started = asyncio.Event()

        async def provider(prompt, work=False):
            started.set()
            await asyncio.sleep(60)

        self.c.provider = provider
        task = asyncio.create_task(
            self.c.handle(Message(1, f"<@{C}> /discuss 2 topic", self.channel))
        )
        await started.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(self.c.pending, 0)
        with self.c.state.connect() as db:
            self.assertEqual(db.execute("SELECT status FROM discussions").fetchone()[0], "failed")

    async def test_parent_cancellation_without_discussion(self):
        started = asyncio.Event()

        async def provider(prompt, work=False):
            started.set()
            await asyncio.sleep(60)

        self.c.provider = provider
        task = asyncio.create_task(self.c.handle(Message(1, f"<@{C}> hello", self.channel)))
        await started.wait()
        task.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await task
        self.assertEqual(self.c.pending, 0)


@pytest.mark.parametrize(
    "error", [None, ValueError("synthetic consumer failure"), asyncio.CancelledError()]
)
def test_dispatch_boundary(error):
    bridge = SimpleNamespace(handle=AsyncMock(side_effect=error), log=MagicMock())
    if isinstance(error, asyncio.CancelledError):
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(dispatch(bridge, object()))
    else:
        asyncio.run(dispatch(bridge, object()))
        assert bridge.log.called == bool(error)


class DiscussionControls(unittest.IsolatedAsyncioTestCase):
    setUp = fixtures.Tests.setUp
    tearDown = fixtures.Tests.tearDown

    async def test_cannot_access_request_stops_without_handoff(self):
        self.c.provider = AsyncMock(
            return_value=json.dumps(
                {
                    "decision": "stop",
                    "reply": "CodexBot: I cannot retrieve that repository; stopping as requested.",
                }
            )
        )
        await self.c.handle(
            Message(
                1,
                f"<@{C}> /discuss 25 review https://example.invalid/repository; "
                "if you cannot access it, stop immediately",
                self.channel,
            )
        )
        result, options = self.channel.sent[-1]
        self.assertNotIn("[bridge:", result.content)
        self.assertNotIn(f"<@{A}>", result.content)
        self.assertIn("Discussion stopped", result.content)
        self.assertFalse(options["allowed_mentions"].users)
        with self.c.state.connect() as db:
            row = db.execute("SELECT status,busy,token FROM discussions").fetchone()
            self.assertEqual(tuple(row), ("complete", 0, ""))
        await self.a.handle(result)
        self.assertFalse(self.calls)

    async def test_later_participant_can_stop_and_previous_marker_cannot_replay(self):
        self.c.provider = AsyncMock(
            return_value=json.dumps({"decision": "continue", "reply": "First reply."})
        )
        self.a.provider = AsyncMock(
            return_value=json.dumps({"decision": "stop", "reply": "Blocked; stopping."})
        )
        await self.c.handle(Message(1, f"<@{C}> /discuss 6 topic", self.channel))
        trigger = self.channel.sent[-1][0]
        self.channel.sender = A
        await self.a.handle(trigger)
        result = self.channel.sent[-1][0]
        self.assertNotIn("[bridge:", result.content)
        self.assertIn("Discussion stopped", result.content)
        await self.c.handle(result)
        await self.a.handle(trigger)
        self.assertEqual(self.c.provider.await_count, 1)
        self.assertEqual(self.a.provider.await_count, 1)

    async def test_consensus_ends_before_turn_budget(self):
        self.c.provider = AsyncMock(
            return_value=json.dumps({"decision": "consensus", "reply": "All participants agree."})
        )
        await self.c.handle(Message(1, f"<@{C}> /discuss 6 reach consensus", self.channel))
        result = self.channel.sent[-1][0]
        self.assertIn("Discussion complete: consensus reported", result.content)
        self.assertNotIn("[bridge:", result.content)

    async def test_plaintext_or_malformed_control_never_continues(self):
        replies = [
            "I cannot inspect the link. I am stopping here.",
            "[]",
            "{}",
            '{"decision":"go","reply":"answer"}',
            '{"decision":"continue","reply":null}',
            '{"decision":"continue","reply":" "}',
            '{"decision":"continue","reply":"answer","next_bot":999}',
            '{"decision":"continue","reply":"answer"} trailing text',
        ]
        for identity, reply in enumerate(replies, 1):
            self.c.provider = AsyncMock(return_value=reply)
            await self.c.handle(Message(identity, f"<@{C}> /discuss 6 topic", self.channel))
            result, options = self.channel.sent[-1]
            self.assertIn("invalid participant control", result.content)
            self.assertNotIn("[bridge:", result.content)
            self.assertFalse(options["allowed_mentions"].users)
        with self.c.state.connect() as db:
            self.assertEqual(
                db.execute("SELECT count(*) FROM discussions WHERE status='active'").fetchone()[0],
                0,
            )

    async def test_fenced_control_and_quoted_stop_do_not_override_decision(self):
        self.c.provider = AsyncMock(
            return_value="```json\n"
            + json.dumps(
                {
                    "decision": "continue",
                    "reply": 'An example sentence is "I am stopping here"; we are still discussing.',
                }
            )
            + "\n```"
        )
        await self.c.handle(Message(1, f"<@{C}> /discuss 3 talk about wording", self.channel))
        self.assertIn("[bridge:", self.channel.sent[-1][0].content)
        self.assertNotIn('"decision":', self.channel.sent[-1][0].content)

    async def test_provider_diagnostics_preserve_only_safe_code(self):
        from bridge_providers import ProviderError

        logs = []
        self.c.log = logs.append
        self.c.provider = AsyncMock(side_effect=ProviderError("GeminiHTTP429"))
        await self.c.handle(Message(1, f"<@{C}> /discuss 3 topic", self.channel))
        self.assertEqual(self.c.health["last_error"], "GeminiHTTP429")
        self.assertTrue(any("failed: GeminiHTTP429" in line for line in logs))
        self.assertNotIn("[bridge:", self.channel.sent[-1][0].content)
        self.c.provider = AsyncMock(side_effect=RuntimeError("SYNTHETIC_SECRET_MUST_NOT_APPEAR"))
        await self.c.handle(Message(2, f"<@{C}> hi", self.channel))
        self.assertFalse(any("SYNTHETIC_SECRET" in line for line in logs))
