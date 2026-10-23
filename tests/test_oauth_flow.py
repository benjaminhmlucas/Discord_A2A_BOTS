"""Real loopback HTTP peers validate PKCE/code flow and callback lifecycle."""

import asyncio
import base64
from contextlib import asynccontextmanager
import hashlib

from aiohttp import ClientSession, web
import pytest
from yarl import URL

from bridge_auth_policy import AuthenticationError
from bridge_http import CapabilityError, SafeHTTP
from bridge_oauth_flow import Callback, OAuthFlow


@asynccontextmanager
async def peer(*, token_changes=None, bad_issuer=False, deny=False):
    state = {"exchanges": [], "authorizations": [], "revocations": [], "requests": []}

    async def handle(request):
        state["requests"].append(request.path)
        origin = state["origin"]
        if request.path == "/mcp":
            return web.Response(status=401)
        if request.path == "/.well-known/oauth-protected-resource/mcp":
            return web.json_response(
                {"resource": origin + "/mcp", "authorization_servers": [origin]}
            )
        if request.path == "/.well-known/oauth-authorization-server":
            return web.json_response(
                {
                    "issuer": origin,
                    "authorization_endpoint": origin + "/authorize",
                    "token_endpoint": origin + "/token",
                    "revocation_endpoint": origin + "/revoke",
                    "code_challenge_methods_supported": ["S256"],
                    "response_types_supported": ["code"],
                    "token_endpoint_auth_methods_supported": ["none"],
                    "authorization_response_iss_parameter_supported": True,
                }
            )
        if request.path == "/authorize":
            state["authorizations"].append(dict(request.query))
            query = request.query
            assert query["resource"] == origin + "/mcp"
            assert query["client_id"] == "fixture-client"
            assert query["code_challenge_method"] == "S256" and query["scope"] == "read"
            response = {
                "state": query["state"],
                "iss": "https://evil.example" if bad_issuer else origin,
            }
            response.update(
                {"error": "access_denied", "error_description": "SENSITIVE-NEVER-ECHO"}
                if deny
                else {"code": "synthetic-code"}
            )
            # The simulated browser follows this location; the peer issues no open redirect.
            return web.json_response(
                {"location": str(URL(query["redirect_uri"]).with_query(response))}
            )
        if request.path == "/token":
            assert request.content_type == "application/x-www-form-urlencoded"
            fields = dict(await request.post())
            state["exchanges"].append(fields)
            assert fields["resource"] == origin + "/mcp" and fields["client_id"] == "fixture-client"
            if fields["grant_type"] == "authorization_code":
                expected = (
                    base64.urlsafe_b64encode(
                        hashlib.sha256(fields["code_verifier"].encode()).digest()
                    )
                    .rstrip(b"=")
                    .decode()
                )
                assert expected == state["authorizations"][-1]["code_challenge"]
                assert fields["code"] == "synthetic-code"
                assert fields["redirect_uri"] == state["authorizations"][-1]["redirect_uri"]
            else:
                assert (
                    fields["grant_type"] == "refresh_token"
                    and fields["refresh_token"] == "synthetic-refresh"
                )
            return web.json_response(
                {
                    "access_token": "synthetic-access",
                    "refresh_token": "synthetic-refresh",
                    "token_type": "Bearer",
                    "expires_in": 3600,
                    "scope": "read",
                    **(token_changes or {}),
                }
            )
        if request.path == "/revoke":
            state["revocations"].append(dict(await request.post()))
            return web.Response(status=200)
        return web.Response(status=404)

    app = web.Application()
    app.router.add_route("*", "/{path:.*}", handle)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    await web.TCPSite(runner, "127.0.0.1", 0).start()
    origin = state["origin"] = "http://127.0.0.1:" + str(runner.addresses[0][1])
    profile = {
        "transport": "http",
        "endpoint": origin + "/mcp",
        "authentication": {
            "type": "oauth",
            "credential": {"source": "native", "name": "fixture"},
            "issuer": origin,
            "client_id": "fixture-client",
            "scopes": ["read"],
            "allowed_origins": [origin],
            "internal_origins": [origin],
            "callback_port": 0,
        },
    }
    try:
        yield OAuthFlow(profile, SafeHTTP(internal_origins=[origin], seconds=0.5)), state
    finally:
        await runner.cleanup()


async def browser(url):
    # Simulates only the browser boundary; authorization, token and callback are real HTTP.
    # The authorization peer returns its redirect target instead of issuing a 302.
    async with ClientSession() as session:
        async with session.get(url) as response:
            location = (await response.json())["location"]
        async with session.get(location) as response:
            return await response.text()


def test_full_public_client_signin_refresh_and_revoke():
    async def scenario():
        async with peer() as (flow, state):
            grant = await flow.signin(browser)
            assert grant["access_token"] == "synthetic-access"
            assert (
                grant["issuer"] == state["origin"] and grant["resource"] == state["origin"] + "/mcp"
            )
            assert grant["scopes"] == ["read"]
            refreshed = await flow.refresh(grant)
            assert refreshed["refresh_token"] == "synthetic-refresh"
            await flow.revoke(refreshed)
            assert len(state["exchanges"]) == 2
            assert state["revocations"] == [
                {"token": "synthetic-refresh", "client_id": "fixture-client"}
            ]

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "token_changes",
    [
        {"token_type": "MAC"},
        {"expires_in": 0},
        {"expires_in": True},
        {"access_token": "bad\nheader"},
        {"scope": "read write"},
        {"resource": "https://wrong.example"},
    ],
)
def test_invalid_token_responses_rejected(token_changes):
    async def scenario():
        async with peer(token_changes=token_changes) as (flow, _):
            with pytest.raises(CapabilityError):
                await flow.signin(browser)

    asyncio.run(scenario())


@pytest.mark.parametrize("bad_issuer,deny", [(True, False), (False, True)])
def test_consent_failure_and_issuer_mismatch_never_exchange_code(bad_issuer, deny):
    async def scenario():
        async with peer(bad_issuer=bad_issuer, deny=deny) as (flow, state):
            with pytest.raises(AuthenticationError) as error:
                await flow.signin(browser)
            assert "SENSITIVE" not in str(error.value) and state["exchanges"] == []

    asyncio.run(scenario())


def test_callback_rejects_mismatch_duplicate_unicode_and_replay():
    async def scenario():
        callback = Callback("https://issuer.example", True)
        async with callback.listen(0), ClientSession() as session:
            for query in ["state=wrong&code=x", "state=%E2%98%83&code=x", "state=x&state=y&code=z"]:
                async with session.get(callback.redirect + "?" + query) as response:
                    assert response.status == 400
            assert not callback.result.done()
            url = URL(callback.redirect).with_query(
                {"state": callback.state, "code": "fixture", "iss": callback.issuer}
            )
            async with session.get(url) as response:
                assert response.status == 200
            assert await callback.wait(1) == "fixture"
            async with session.get(url) as response:
                assert response.status == 410

    asyncio.run(scenario())


def test_cancellation_and_timeout_close_callback_listener():
    async def scenario():
        for cancel in (False, True):
            async with peer() as (flow, state):
                listening = asyncio.Event()
                captured = []

                async def opener(url):
                    captured.append(URL(url).query["redirect_uri"])
                    listening.set()

                task = asyncio.create_task(flow.signin(opener, seconds=0.1 if not cancel else 10))
                await listening.wait()
                if cancel:
                    task.cancel()
                with pytest.raises(asyncio.CancelledError if cancel else TimeoutError):
                    await task
                url = URL(captured[0])
                with pytest.raises(OSError):
                    await asyncio.open_connection(url.host, url.port)
                assert state["exchanges"] == []

    asyncio.run(scenario())


@pytest.mark.parametrize("operation", ["refresh", "revoke"])
@pytest.mark.parametrize(
    "field,value",
    [
        ("issuer", "https://other.example"),
        ("resource", "https://other.example/mcp"),
        ("scopes", ["write"]),
    ],
)
def test_cross_profile_grants_never_make_any_network_request(operation, field, value):
    async def scenario():
        async with peer() as (flow, state):
            grant = {
                "issuer": state["origin"],
                "resource": state["origin"] + "/mcp",
                "scopes": ["read"],
                "access_token": "OTHER-PROFILE-ACCESS",
                "refresh_token": "OTHER-PROFILE-REFRESH",
            }
            grant[field] = value
            with pytest.raises(AuthenticationError, match="binding mismatch"):
                await getattr(flow, operation)(grant)
            assert state["requests"] == []

    asyncio.run(scenario())


def test_callback_rejects_cross_origin_and_rebound_hosts_without_consuming_state():
    async def scenario():
        callback = Callback("https://issuer.example", False)
        async with callback.listen(0), ClientSession() as session:
            url = URL(callback.redirect).with_query({"state": callback.state, "code": "x"})
            for headers in (
                {"Origin": "https://attacker.example"},
                {"Host": "attacker.example"},
            ):
                async with session.get(url, headers=headers) as response:
                    assert response.status == 400
            async with session.get(str(url) + "&" + "x" * 4097) as response:
                assert response.status == 400
            assert not callback.used and not callback.result.done()
            async with session.get(url) as response:
                assert response.status == 200
            assert await callback.wait(1) == "x"

    asyncio.run(scenario())
