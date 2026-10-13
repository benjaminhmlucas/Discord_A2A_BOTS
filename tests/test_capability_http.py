"""Exercise the network boundary with real sockets; only OS DNS is substituted."""

import asyncio
import socket
from unittest.mock import patch

import pytest
from aiohttp import web

from bridge_http import CapabilityError, GuardedResolver, SafeHTTP, checked_url, public_address


@pytest.mark.parametrize(
    "value",
    [None, "x" * 2049, "https://a\nb", "https://a b", "https://[bad]", "relative", "file:///x"],
)
def test_malformed_url(value):
    with pytest.raises(CapabilityError, match="Invalid destination"):
        checked_url(value)


@pytest.mark.parametrize(
    "value",
    [
        "http://example.com",
        "https://user:password@example.com",
        "https://example.com/#x",
        "https://127.0.0.1",
        "https://[::1]",
        "https://[::ffff:127.0.0.1]",
        "https://[fe80::1%25eth0]",
        "ftp://example.com",
        "https://169.254.169.254",
        "https://10.1.1.1",
        "https://100.64.0.1",
        "https://224.0.0.1",
        "https://192.0.0.8",
        "https://[64:ff9b::a00:1]",
        "https://[64:ff9b:1::a00:1]",
        "https://[2002:0a00:0001::]",
        "https://[2001:1::1]",
        "https://[fec0::1]",
    ],
)
def test_blocked_url(value):
    with pytest.raises(CapabilityError, match="Destination denied"):
        checked_url(value)


def test_addresses_and_explicit_internal_origin():
    assert public_address("8.8.8.8")
    assert public_address("192.0.0.9")
    assert public_address("192.0.0.10")
    assert public_address("2606:4700:4700::1111")
    assert not public_address("224.0.0.1")
    assert str(checked_url("https://example.com/a?q=x")) == "https://example.com/a?q=x"
    assert str(checked_url("http://127.0.0.1:123/a", ("http://127.0.0.1:123",)))
    with pytest.raises(CapabilityError):
        checked_url("http://127.0.0.1:124/a", ("http://127.0.0.1:123",))


def test_dns_answers_all_checked():
    async def scenario():
        resolver = GuardedResolver()
        loop = asyncio.get_running_loop()

        async def dns(*args, **kwargs):
            return answers

        try:
            for hosts, allowed in [
                ([], False),
                (["8.8.8.8"], True),
                (["8.8.8.8", "127.0.0.1"], False),
            ]:
                answers = [
                    (socket.AF_INET, socket.SOCK_STREAM, 6, "", (host, 443)) for host in hosts
                ]
                with patch.object(loop, "getaddrinfo", dns):
                    if allowed:
                        assert (await resolver.resolve("test.invalid", 443))[0]["host"] == "8.8.8.8"
                    else:
                        with pytest.raises(CapabilityError):
                            await resolver.resolve("test.invalid", 443)
        finally:
            await resolver.close()

    asyncio.run(scenario())


def test_real_http_limits_redirects_dns_pinning_and_cleanup():
    async def scenario():
        calls = []
        slow_started = asyncio.Event()

        async def handler(request):
            calls.append((request.path, dict(request.headers)))
            route = request.path
            if route == "/redirect":
                raise web.HTTPFound("/ok")
            if route == "/private":
                raise web.HTTPFound("https://169.254.169.254/latest")
            if route == "/loop":
                raise web.HTTPFound("/loop")
            if route == "/missing":
                return web.Response(status=302)
            if route == "/error":
                return web.Response(status=500, text="SECRET server traceback")
            if route == "/binary":
                return web.Response(body=b"abc", content_type="application/octet-stream")
            if route == "/encoding":
                return web.Response(body=b"abc", headers={"Content-Encoding": "gzip"})
            if route == "/large":
                return web.Response(text="x" * 129)
            if route == "/stream":
                response = web.StreamResponse(headers={"Content-Type": "text/plain"})
                await response.prepare(request)
                await response.write(b"x" * 129)
                await response.write_eof()
                return response
            if route == "/utf8":
                return web.Response(body=b"\xff", content_type="text/plain")
            if route == "/slow":
                slow_started.set()
                await asyncio.sleep(0.15)
                return web.Response(text="late")
            return web.Response(text="hello", content_type="text/plain")

        app = web.Application()
        app.router.add_route("*", "/{tail:.*}", handler)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        origin = f"http://127.0.0.1:{port}"
        http = SafeHTTP(internal_origins=(origin,), max_bytes=128, seconds=1, redirects=1)
        try:
            assert await http.page(origin + "/redirect") == "hello"
            for path, error in [
                ("private", "Destination denied"),
                ("loop", "Redirect limit"),
                ("missing", "Redirect limit"),
                ("error", "Web request failed"),
                ("binary", "Unsupported page type"),
                ("encoding", "Compressed"),
                ("large", "Response too large"),
                ("stream", "Response too large"),
                ("utf8", "Invalid response encoding"),
            ]:
                with pytest.raises(CapabilityError, match=error):
                    await http.page(origin + "/" + path)
            assert all(headers["Accept-Encoding"] == "identity" for _, headers in calls)
            async with http.open(
                "POST", origin + "/ok", body={"test": "value"}, headers={"X-Test": "scoped"}
            ) as response:
                assert await http.read(response) == "hello"
            assert calls[-1][1]["X-Test"] == "scoped"
            # The connector uses the resolver's returned IP. No ambient proxy or cookies.
            domain_origin = f"http://fixture.invalid:{port}"
            pinned = SafeHTTP(internal_origins=(domain_origin,), max_bytes=128, seconds=1)
            loop = asyncio.get_running_loop()

            async def dns(*args, **kwargs):
                return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

            with (
                patch.object(loop, "getaddrinfo", dns),
                patch.dict("os.environ", {"HTTP_PROXY": "http://127.0.0.1:1"}),
            ):
                assert await pinned.page(domain_origin + "/ok") == "hello"
            # Same DNS answer without the distinct internal policy is rejected before a request.
            before = len(calls)
            with patch.object(loop, "getaddrinfo", dns), pytest.raises(CapabilityError):
                await SafeHTTP(seconds=1).page("https://fixture.invalid/ok")
            assert len(calls) == before
            timed = SafeHTTP(internal_origins=(origin,), seconds=0.02)
            with pytest.raises(asyncio.TimeoutError):
                await timed.page(origin + "/slow")
            slow_started.clear()
            task = asyncio.create_task(http.page(origin + "/slow"))
            await slow_started.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
            assert await http.page(origin + "/ok") == "hello"
        finally:
            await runner.cleanup()

    asyncio.run(scenario())
