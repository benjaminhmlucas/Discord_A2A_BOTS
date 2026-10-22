"""Protocol regressions through real sockets and the production MCP/HTTP clients."""

import asyncio
import json
from contextlib import suppress

import pytest
from aiohttp import web

from bridge_http import CapabilityError, SafeHTTP
from bridge_mcp import MCPClient, PROTOCOL_2025, PROTOCOL
from test_capabilities import call_client, FixtureServer


class StreamingServer(FixtureServer):
    def __init__(self, payload, *, hold=False):
        super().__init__()
        self.payload = payload
        self.hold = hold
        self.release = asyncio.Event()
        self.open_streams = 0
        self.eof_writes = 0

    async def __aexit__(self, *args):
        self.release.set()
        await super().__aexit__(*args)

    async def mcp(self, request):
        body = await request.json()
        if body["method"] in ("initialize", "notifications/initialized"):
            return await super().mcp(request)
        self.calls.append((body, dict(request.headers)))
        result = (
            {"tools": [{"name": "read_example"}]}
            if body["method"] == "tools/list"
            else {"content": [{"type": "text", "text": "public é answer"}]}
        )
        envelope = {"jsonrpc": "2.0", "id": body["id"], "result": result}
        chunks = self.payload(envelope)
        response = web.StreamResponse(headers={"Content-Type": "text/event-stream"})
        await response.prepare(request)
        self.open_streams += 1
        try:
            with suppress(ConnectionResetError):
                for chunk in chunks:
                    await response.write(chunk)
                    await asyncio.sleep(0.003)
            # Hold the producer even if the client closes after reading a final CR.
            if self.hold:
                await self.release.wait()
            with suppress(ConnectionResetError):
                self.eof_writes += 1
                await response.write_eof()
        finally:
            self.open_streams -= 1
        return response


def event(envelope, newline=b"\n"):
    return b"data:" + json.dumps(envelope, ensure_ascii=False).encode() + newline * 2


@pytest.mark.parametrize("legacy", [False, True])
@pytest.mark.parametrize("newline", [b"\n", b"\r\n", b"\r"])
def test_empty_primers_chunk_boundaries_and_result_before_eof(legacy, newline):
    def payload(envelope):
        primer = b": keepalive" + newline + b"id: prime" + newline + b"data:" + newline * 2
        raw = (
            b"data: {"
            + newline
            + b"data: "
            + json.dumps(envelope, ensure_ascii=False).encode()[1:]
            + newline * 2
        )
        split = raw.find(b"\xc3") + 1 if b"\xc3" in raw else len(raw) - 1
        return [primer[:-1], primer[-1:] + raw[:split], raw[split:]]

    async def scenario():
        async with StreamingServer(payload, hold=True) as server:
            server.legacy = legacy
            http = SafeHTTP(internal_origins=(server.origin,), seconds=1)
            client = MCPClient(
                http, server.origin + "/mcp", protocol=PROTOCOL_2025 if legacy else PROTOCOL
            )
            assert await call_client(client, "read_example", {}) == "public é answer"
            assert server.open_streams == 2  # Neither server handler reached EOF.
            assert server.eof_writes == 0 and not server.release.is_set()
            assert not client.session and client.cancelled_request is None

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "payload,error",
    [
        (lambda e: [b"data:\n\n: comment\n\nid: only\n\n"], "Missing MCP response"),
        (lambda e: [b"data: {bad}\n\n"], "Invalid MCP response"),
        (lambda e: [event({**e, "id": e["id"] + 1})], "MCP request failed"),
        (
            lambda e: [event({"jsonrpc": "2.0", "method": "roots/list", "id": e["id"]})],
            "server requests",
        ),
        (lambda e: [event({"jsonrpc": "2.0", "method": "notifications/message"}), event(e)], None),
        (lambda e: [event(e, b"\r")], None),
        (lambda e: [event(e)[:-1]], "Missing MCP response"),
        (lambda e: [b"data: \xff\n\n"], "Invalid response encoding"),
        (lambda e: [b"\xff"], "Invalid response encoding"),
        (
            lambda e: [b"data: " + b"[" * 1500 + b"0" + b"]" * 1500 + b"\n\n"],
            "Invalid MCP response",
        ),
        (lambda e: [b": " + b"x" * 66000 + b"\n\n"], "Response too large"),
        # Bytes following the correlated final result are outside this completed request.
        (lambda e: [event(e) + event(e)], None),
    ],
)
def test_stream_validation_and_completed_request_boundary(payload, error):
    async def scenario():
        async with StreamingServer(payload) as server:
            client = MCPClient(SafeHTTP(internal_origins=(server.origin,)), server.origin + "/mcp")
            if error:
                with pytest.raises(CapabilityError, match=error):
                    await call_client(client, "read_example", {})
            else:
                assert await call_client(client, "read_example", {}) == "public é answer"

    asyncio.run(scenario())


class CancellationServer(FixtureServer):
    def __init__(self, stage, notification="ok"):
        super().__init__()
        self.stage = stage
        self.notification = notification
        self.active_id = None
        self.release = asyncio.Event()
        self.cancelled = asyncio.Event()
        self.notification_started = asyncio.Event()

    async def __aexit__(self, *args):
        self.release.set()
        await super().__aexit__(*args)

    async def mcp(self, request):
        body = await request.json()
        if body["method"] == "notifications/cancelled":
            self.calls.append((body, dict(request.headers)))
            assert "id" not in body and body["params"] == {"requestId": self.active_id}
            self.notification_started.set()
            if self.notification == "ok":
                self.cancelled.set()
                self.release.set()
            elif self.notification == "hang":
                await self.release.wait()
            return web.Response(status=202 if self.notification == "ok" else 500)
        if body["method"] != self.stage:
            return await super().mcp(request)
        self.calls.append((body, dict(request.headers)))
        self.active_id = body["id"]
        headers = {"Content-Type": "text/event-stream"}
        if self.stage == "initialize" and self.session_id:
            headers["Mcp-Session-Id"] = self.session_id
        response = web.StreamResponse(headers=headers)
        await response.prepare(request)
        self.started.set()
        await self.release.wait()
        return response


@pytest.mark.parametrize(
    "legacy,session,stage",
    [
        (True, None, "tools/call"),
        (True, "synthetic-session", "tools/call"),
        (True, None, "tools/list"),
        (True, "synthetic-session", "initialize"),
        (False, None, "tools/list"),
        (False, None, "tools/call"),
    ],
)
@pytest.mark.parametrize("timeout", [False, True])
def test_active_request_cancellation_and_timeout_signal(legacy, session, stage, timeout):
    async def scenario():
        async with CancellationServer(stage) as server:
            server.legacy, server.session_id = legacy, session
            http = SafeHTTP(internal_origins=(server.origin,), seconds=0.08 if timeout else 1)
            client = MCPClient(
                http, server.origin + "/mcp", protocol=PROTOCOL_2025 if legacy else PROTOCOL
            )
            task = asyncio.create_task(call_client(client, "read_example", {}))
            await asyncio.wait_for(server.started.wait(), 1)
            if not timeout:
                task.cancel()
            with pytest.raises(asyncio.TimeoutError if timeout else asyncio.CancelledError):
                await task
            expected = legacy and stage != "initialize"
            assert server.cancelled.is_set() == expected
            notices = [b for b, _ in server.calls if b["method"] == "notifications/cancelled"]
            assert len(notices) == int(expected)
            if expected:
                assert notices[0]["params"]["requestId"] == server.active_id
                assert server.release.is_set()
            assert len(server.deletes) == int(session is not None)
            assert client.session is None and client.cancelled_request is None

    asyncio.run(scenario())


@pytest.mark.parametrize("notification", ["error", "hang"])
def test_cancellation_cleanup_failure_is_bounded_and_preserves_original(notification):
    async def scenario():
        async with CancellationServer("tools/call", notification) as server:
            server.legacy = True
            http = SafeHTTP(internal_origins=(server.origin,), seconds=3)
            client = MCPClient(http, server.origin + "/mcp", protocol=PROTOCOL_2025)
            task = asyncio.create_task(call_client(client, "read_example", {}))
            await asyncio.wait_for(server.started.wait(), 1)
            before = asyncio.get_running_loop().time()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert asyncio.get_running_loop().time() - before < 2.6
            assert server.notification_started.is_set()
            assert not server.cancelled.is_set()
            assert len(server.deletes) == int(notification == "error")
            assert client.session is None and client.cancelled_request is None

    asyncio.run(scenario())
