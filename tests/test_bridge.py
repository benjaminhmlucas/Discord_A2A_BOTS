import asyncio
import json
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

import os
REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))
os.environ['BOTBRIDGE_CONFIG_FILE'] = str(Path(__file__).parent / 'fixtures/bridge_config.json')
from bridge_runtime import Bridge
from bridge_state import MARKER
from bridge_privacy import Privacy
from bridge_providers import child_env

C, A, OWNER = 101, 102, 201


class Author:
    def __init__(self, identity=OWNER, bot=False):
        self.id, self.bot, self.display_name = identity, bot, 'example-user'
        self.dm = Channel(0)

    async def create_dm(self):
        return self.dm


class Typing:
    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        pass


class Channel:
    def __init__(self, identity=301):
        self.id, self.sent, self.messages, self.sender = identity, [], [], C

    async def send(self, text, **kwargs):
        result = Message(10000 + len(self.sent), text, self, Author(self.sender, True))
        self.sent.append((result, kwargs))
        return result

    async def fetch_message(self, identity):
        return next(m for m in self.messages if m.id == identity)

    def typing(self):
        return Typing()

    async def history(self, limit, before):
        for msg in sorted([m for m in self.messages if m.id < before.id], key=lambda m: m.id, reverse=True)[:limit]:
            yield msg


class Message:
    def __init__(self, identity, text, channel, author=None, webhook=None):
        self.id, self.content, self.channel = identity, text, channel
        self.author, self.webhook_id, self.attachments = author or Author(), webhook, []
        channel.messages.append(self)

    def to_reference(self, **kwargs):
        return SimpleNamespace(message_id=self.id, **kwargs)


class Client:
    def __init__(self, identity):
        self.user, self.ready = SimpleNamespace(id=identity), True

    def is_ready(self):
        return self.ready


class Tests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        for name in ('bridge_config.json', 'public_context.md'):
            shutil.copyfile(Path(__file__).parent / 'fixtures' / name, self.root / name)
        self.memory = self.root / 'memory'
        self.memory.mkdir()
        (self.memory / 'MEMORY.md').write_text('<!--PRIVATE:START-->Hidden Value<!--PRIVATE:END-->')
        self.calls = []

        async def provider(prompt, work=False):
            self.calls.append((prompt, work))
            reply = 'A reply with HIDDEN VALUE and @everyone.'
            return json.dumps({'decision': 'continue', 'reply': reply}) if 'DISCUSSION RESPONSE PROTOCOL' in prompt else reply

        self.provider = provider
        self.c = Bridge(Client(C), C, provider, lambda _: None, self.root, self.memory)
        self.a = Bridge(Client(A), A, provider, lambda _: None, self.root, self.memory)
        self.c.write_health()
        self.a.write_health()
        self.channel = Channel()

    def tearDown(self):
        self.temp.cleanup()

    async def test_five_turn_discussion_and_replay(self):
        trigger = Message(1, f'<@{C}> /discuss 5 test topic', self.channel)
        engine = self.c
        for turn in range(5):
            self.channel.sender = engine.bot_id
            await engine.handle(trigger)
            result, opts = self.channel.sent[-1]
            self.assertNotIn('HIDDEN VALUE', result.content)
            self.assertFalse(opts['allowed_mentions'].everyone)
            self.assertFalse(opts['allowed_mentions'].roles)
            if turn < 4:
                self.assertTrue(MARKER.search(result.content))
                expected = A if engine.bot_id == C else C
                self.assertEqual([u.id for u in opts['allowed_mentions'].users], [expected])
                engine = self.a if expected == A else self.c
                trigger = result
            else:
                self.assertIn('Discussion complete', result.content)
                self.assertFalse(opts['allowed_mentions'].users)
        self.assertEqual(len(self.calls), 5)
        self.assertTrue(all('test topic' in prompt for prompt, _ in self.calls))
        await self.c.handle(trigger)
        self.assertEqual(len(self.calls), 5)

    async def test_forged_webhook_unknown_and_parked_messages_ignored(self):
        for identity in (A, 103, 123):
            for marker in ('[discuss:99999:123]', '[bridge:' + '0' * 32 + ':' + '1' * 32 + ':15]'):
                await self.c.handle(Message(identity, f'<@{C}> {marker}', self.channel, Author(identity, True)))
        await self.c.handle(Message(8, f'<@{C}> hi', self.channel, webhook=77))
        self.assertEqual(self.calls, [])

    async def test_wrong_bot_wrong_channel_token_and_budget_rejected(self):
        await self.c.handle(Message(2, f'<@{C}> discuss 3 topic', self.channel))
        real = self.channel.sent[-1][0]
        forged = Message(500, real.content, self.channel, Author(123, True))
        await self.a.handle(forged)
        forged.author = Author(C, True)
        forged.channel = Channel(123)
        await self.a.handle(forged)
        forged.channel = self.channel
        forged.content = real.content.replace(':2]', ':99]')
        await self.a.handle(forged)
        forged.content = real.content.replace(MARKER.search(real.content).group(2), '0' * 32)
        await self.a.handle(forged)
        self.assertEqual(len(self.calls), 1)
        await self.a.handle(real)
        self.assertEqual(len(self.calls), 2)

    async def test_queue_preserves_original_request_and_history_cutoff(self):
        gate = asyncio.Event()
        async def provider(prompt, work=False):
            self.calls.append((prompt, work))
            if len(self.calls) == 1:
                await gate.wait()
            return 'ok'
        self.a.provider = provider
        first = asyncio.create_task(self.a.handle(Message(100, f'<@{A}> first question', self.channel)))
        while not self.calls:
            await asyncio.sleep(0)
        self.channel.messages.extend(Message(i, 'UNRELATED NEWER TRAFFIC', self.channel) for i in range(201, 230))
        second = asyncio.create_task(self.a.handle(Message(200, f'<@{A}> second question', self.channel)))
        await asyncio.sleep(.02)
        gate.set()
        await asyncio.gather(first, second)
        self.assertIn('second question', self.calls[1][0])
        self.assertNotIn('UNRELATED NEWER TRAFFIC', self.calls[1][0])

    async def test_only_owner_can_work_and_results_are_private(self):
        await self.c.handle(Message(2, f'<@{C}> /work task', self.channel, Author(42)))
        self.assertFalse(self.calls)
        owner = Author()
        await self.c.handle(Message(3, f'<@{C}> /work task', self.channel, owner))
        self.assertTrue(self.calls[0][1])
        self.assertIn('AUTHENTICATED OWNER', self.calls[0][0])
        self.assertTrue(any('A reply' in m.content for m, _ in owner.dm.sent))
        self.assertFalse(any('A reply' in m.content for m, _ in self.channel.sent))

    async def test_privacy_input_output_and_malformed_fail_closed(self):
        await self.c.handle(Message(2, f'<@{C}> HIDDEN VALUE', self.channel))
        self.assertNotIn('HIDDEN VALUE', self.calls[0][0])
        self.assertNotIn('HIDDEN VALUE', self.channel.sent[-1][0].content)
        (self.memory / 'broken.md').write_text('<!--PRIVATE:START-->no end')
        await self.c.handle(Message(3, f'<@{C}> next', self.channel))
        self.assertEqual(len(self.calls), 1)
        self.assertIn('request failed', self.channel.sent[-1][0].content)

    async def test_provider_failure_releases_queue_and_aborts_discussion(self):
        async def fail(prompt, work=False):
            raise RuntimeError('provider failed')
        self.c.provider = fail
        await self.c.handle(Message(1, f'<@{C}> discuss 5 hi', self.channel))
        self.assertEqual(self.c.pending, 0)
        self.assertFalse(self.c.lock.locked())
        with self.c.state.connect() as db:
            self.assertEqual(db.execute('SELECT status FROM discussions').fetchone()[0], 'failed')
        self.c.provider = self.provider
        await self.c.handle(Message(2, f'<@{C}> retry', self.channel))
        self.assertEqual(len(self.calls), 1)

    async def test_timeout_cancels_provider_and_releases_slot(self):
        cancelled = []
        async def slow(prompt, work=False):
            try:
                await asyncio.sleep(2)
            except asyncio.CancelledError:
                cancelled.append(True)
                raise
        self.c.provider = slow
        self.c.config['request_seconds'] = .02
        await self.c.handle(Message(2, f'<@{C}> slow', self.channel))
        self.assertEqual(cancelled, [True])
        self.assertEqual(self.c.pending, 0)
        self.assertIn('timed out', self.channel.sent[-1][0].content)

    async def test_total_deadline_releases_queue(self):
        async def slow(prompt, work=False):
            await asyncio.sleep(2)
        self.c.provider = slow
        self.c.config['total_request_seconds'] = .03
        await self.c.handle(Message(2, f'<@{C}> slow', self.channel))
        self.assertEqual(self.c.pending, 0)
        self.assertFalse(self.c.lock.locked())
        self.assertEqual(self.c.health['last_error'], 'TotalDeadline')
        self.assertIn('total request deadline', self.channel.sent[-1][0].content)

    async def test_queue_capacity_and_wait_deadline(self):
        self.c.pending = self.c.config['queue_capacity']
        await self.c.handle(Message(2, f'<@{C}> full', self.channel))
        self.assertIn('queue full', self.channel.sent[-1][0].content)
        self.c.pending = 0
        await self.c.lock.acquire()
        self.c.config['queue_wait_seconds'] = .02
        await self.c.handle(Message(3, f'<@{C}> waiting', self.channel))
        self.assertIn('timed out', self.channel.sent[-1][0].content)
        self.assertEqual(self.c.pending, 0)
        self.c.lock.release()

    async def test_offline_peer_stops_loudly_and_expiry_is_once(self):
        self.a.client.ready = False
        self.a.write_health()
        await self.c.handle(Message(2, f'<@{C}> discuss 5 hi', self.channel))
        self.assertIn('participant is unavailable', self.channel.sent[-1][0].content)
        sid, _ = self.c.state.start(Message(3, 'topic', self.channel), C, 5)
        with self.c.state.connect() as db:
            db.execute('UPDATE discussions SET expires=? WHERE id=?', (time.time() - 1, sid))
        self.assertEqual(len(self.a.state.expired()), 1)
        self.assertEqual(self.c.state.expired(), [])

    async def test_duplicate_human_message_and_multichunk_marker(self):
        async def long(prompt, work=False):
            self.calls.append(prompt)
            return json.dumps({'decision': 'continue', 'reply': 'x' * 6000 + ' [discuss:99999:42]'})
        self.c.provider = long
        message = Message(2, f'<@{C}> discuss 3 hi', self.channel)
        await self.c.handle(message)
        await self.c.handle(message)
        self.assertEqual(len(self.calls), 1)
        replies = [m for m, _ in self.channel.sent if not m.content.startswith('Bridge:')]
        self.assertTrue(all(len(m.content) <= 2000 for m in replies))
        self.assertTrue(MARKER.search(replies[-1].content))
        self.assertFalse(any(MARKER.search(m.content) for m in replies[:-1]))

    def test_nested_private_whitespace_and_no_owner_bypass(self):
        nested = self.memory / 'nested'
        nested.mkdir()
        (nested / 'private.md').write_text('<!--PRIVATE:START-->Second secret<!--PRIVATE:END-->')
        p = Privacy(self.memory)
        self.assertEqual(p.filter('hidden\nVALUE / SECOND SECRET'), '[private] / [private]')

    def test_child_environment_excludes_bot_credentials(self):
        import os
        os.environ['CODEXBOT_TOKEN'] = 'synthetic-token'
        try:
            self.assertNotIn('CODEXBOT_TOKEN', child_env())
        finally:
            del os.environ['CODEXBOT_TOKEN']

    def test_atomic_handoff_claim(self):
        from concurrent.futures import ThreadPoolExecutor
        root = Message(2, 'topic', self.channel)
        sid, _ = self.c.state.start(root, C, 5)
        marker = self.c.state.advance(sid, C, A)
        message = Message(3, f'<@{A}> {marker}', self.channel, Author(C, True))
        with ThreadPoolExecutor(max_workers=8) as pool:
            claims = list(pool.map(lambda _: self.a.state.claim(message, A), range(8)))
        self.assertEqual(sum(c is not None for c in claims), 1)

    async def test_maximum_discussion_budget_clamped(self):
        await self.c.handle(Message(2, f'<@{C}> /discuss 999999 topic', self.channel))
        match = MARKER.search(self.channel.sent[-1][0].content)
        self.assertEqual(int(match.group(3)), 14)

    async def test_private_destination_failure_does_not_invoke_provider(self):
        owner = Author()
        async def denied():
            raise RuntimeError('DM unavailable')
        owner.create_dm = denied
        await self.c.handle(Message(2, f'<@{C}> /work private task', self.channel, owner))
        self.assertFalse(self.calls)
        self.assertIn('request failed', self.channel.sent[-1][0].content)

    async def test_local_work_disabled_by_default(self):
        self.c.config['allow_work'] = False
        await self.c.handle(Message(2, f'<@{C}> /work task', self.channel))
        self.assertFalse(self.calls)
        self.assertIn('work is disabled', self.channel.sent[-1][0].content)

    async def test_untrusted_human_cannot_consume_provider(self):
        await self.c.handle(Message(2, f'<@{C}> hello', self.channel, Author(42)))
        self.assertFalse(self.calls)
        self.assertFalse(self.channel.sent)

    async def test_three_bot_six_turns(self):
        import json
        config = json.loads((self.root / 'bridge_config.json').read_text())
        config['enabled_bots'] = [C, A, 103]
        (self.root / 'bridge_config.json').write_text(json.dumps(config))
        engines = {i: Bridge(Client(i), i, self.provider, lambda _: None, self.root, self.memory) for i in (C, A, 103)}
        for engine in engines.values():
            engine.write_health()
        trigger = Message(1, f'<@{C}> /discuss 6 test all three', self.channel)
        order = [C, A, 103, C, A, 103]
        for turn, identity in enumerate(order):
            self.channel.sender = identity
            await engines[identity].handle(trigger)
            trigger, opts = self.channel.sent[-1]
            self.assertIsNone(engines[identity].health['last_error'])
            if turn < 5:
                self.assertEqual([u.id for u in opts['allowed_mentions'].users], [order[turn + 1]])
            else:
                self.assertIn('Discussion complete', trigger.content)
        self.assertEqual(len(self.calls), 6)
        self.assertEqual([engines[i].health['requests_ok'] for i in (C, A, 103)], [2, 2, 2])

    def test_independent_monitor_detects_stale_and_provider_failure(self):
        from bridge_health import inspect
        (self.root / 'log_management_state.json').write_text('{"errors":[]}')
        (self.root / f'runtime_state/health_{A}.json').write_text('{"timestamp":0,"ready":false}')
        report = inspect(self.root)
        self.assertEqual(report['status'], 'degraded')
        self.assertTrue(any(str(A) in f for f in report['failures']))


if __name__ == '__main__':
    unittest.main(verbosity=2)
