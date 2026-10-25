"""Real OAuth discovery with only the operating-system DNS/browser boundaries replaced."""

import asyncio
from contextlib import asynccontextmanager
import socket

from aiohttp import resolver, web
import pytest
from yarl import URL

from bridge_http import CapabilityError, SafeHTTP
from bridge_oauth_flow import OAuthFlow

AUTH_ORIGIN = "https://browser-boundary.example"


class BrowserReached(Exception):
    """Stop at the browser boundary without opening a window or visiting a public site."""


@asynccontextmanager
async def authorization_peer():
    origin = ""

    async def handle(request):
        if request.path == "/mcp":
            return web.Response(status=401)
        if request.path == "/.well-known/oauth-protected-resource/mcp":
            return web.json_response(
                {"resource": origin + "/mcp", "authorization_servers": [origin]}
            )
        return web.json_response(
            {
                "issuer": origin,
                "authorization_endpoint": AUTH_ORIGIN + "/authorize",
                "token_endpoint": origin + "/token",
                "code_challenge_methods_supported": ["S256"],
                "response_types_supported": ["code"],
                "token_endpoint_auth_methods_supported": ["none"],
            }
        )

    app = web.Application()
    app.router.add_get("/{path:.*}", handle)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", 0).start()
    origin = "http://127.0.0.1:" + str(runner.addresses[0][1])
    profile = {
        "transport": "http",
        "endpoint": origin + "/mcp",
        "authentication": {
            "type": "oauth",
            "credential": {"source": "native", "name": "fixture"},
            "issuer": origin,
            "client_id": "synthetic-client",
            "scopes": ["read"],
            "allowed_origins": [origin, AUTH_ORIGIN],
            "internal_origins": [origin],
            "callback_port": 0,
        },
    }
    try:
        yield OAuthFlow(profile, SafeHTTP(internal_origins=[origin]))
    finally:
        await runner.cleanup()


def dns_boundary(monkeypatch, addresses, *, entered=None, released=None):
    events = []
    original_close = resolver.ThreadedResolver.close

    async def resolve(self, host, port=0, family=socket.AF_INET):
        assert host == URL(AUTH_ORIGIN).host
        # A browser can use either family: checking only A records misses a private AAAA.
        assert family == socket.AF_UNSPEC
        events.append(("resolve", id(self)))
        if entered is not None:
            entered.set()
            try:
                await asyncio.Event().wait()
            finally:
                released.set()
        return [
            {
                "hostname": host,
                "host": address,
                "port": port,
                "family": socket.AF_INET6 if ":" in address else socket.AF_INET,
                "proto": 0,
                "flags": 0,
            }
            for address in addresses
        ]

    async def close(self):
        events.append(("close", id(self)))
        await original_close(self)

    monkeypatch.setattr(resolver.ThreadedResolver, "resolve", resolve)
    monkeypatch.setattr(resolver.ThreadedResolver, "close", close)
    return events


@pytest.mark.parametrize(
    "addresses",
    [
        ["127.0.0.1"],
        ["10.0.0.1"],
        ["::ffff:127.0.0.1"],
        ["1.1.1.1", "10.0.0.1"],
        ["1.1.1.1", "fd00::1"],
        [],
    ],
)
def test_authorization_private_dns_is_refused_before_browser(monkeypatch, addresses):
    async def scenario():
        events = dns_boundary(monkeypatch, addresses)
        opened = []

        async def opener(url):
            opened.append(url)
            raise BrowserReached()

        async with authorization_peer() as flow:
            with pytest.raises(CapabilityError):
                await flow.signin(opener, seconds=3)
        assert opened == []
        resolved = [identity for event, identity in events if event == "resolve"]
        assert len(resolved) == 1
        assert ("close", resolved[0]) in events

    asyncio.run(scenario())


@pytest.mark.parametrize("addresses", [["1.1.1.1"], ["2606:4700:4700::1111"]])
def test_authorization_public_dns_is_checked_and_closed_before_browser(monkeypatch, addresses):
    async def scenario():
        events = dns_boundary(monkeypatch, addresses)

        async def opener(url):
            resolved = [identity for event, identity in events if event == "resolve"]
            assert len(resolved) == 1
            assert ("close", resolved[0]) in events
            assert str(URL(url).origin()) == AUTH_ORIGIN
            assert URL(url).query["code_challenge_method"] == "S256"
            raise BrowserReached()

        async with authorization_peer() as flow:
            with pytest.raises(BrowserReached):
                await flow.signin(opener, seconds=3)

    asyncio.run(scenario())


def test_authorization_dns_cancellation_closes_resolver_without_browser(monkeypatch):
    async def scenario():
        entered, released = asyncio.Event(), asyncio.Event()
        events = dns_boundary(monkeypatch, [], entered=entered, released=released)
        opened = []

        async def opener(url):
            opened.append(url)

        async with authorization_peer() as flow:
            task = asyncio.create_task(flow.signin(opener, seconds=3))
            await asyncio.wait_for(entered.wait(), 1)
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task
        assert released.is_set() and opened == []
        resolved = [identity for event, identity in events if event == "resolve"]
        assert len(resolved) == 1 and ("close", resolved[0]) in events

    asyncio.run(scenario())
