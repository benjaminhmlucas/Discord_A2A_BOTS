"""Actual resource/authorization peers exercise discovery and guarded HTTP transport."""

import asyncio
import json
from contextlib import asynccontextmanager

import pytest
from aiohttp import web

from bridge_auth_policy import AuthenticationError
from bridge_http import CapabilityError, SafeHTTP
from bridge_oauth_discovery import Discovery, challenge, object_json


@asynccontextmanager
async def peers(
    *, mutate=None, oidc=0, root=False, advertised=False, challenged_scope="read", endpoint_query=""
):
    hits = []
    setup = {}

    async def handle(request):
        hits.append((request.method, request.path))
        if (
            request.path == "/.well-known/oauth-protected-resource/mcp"
            and request.query_string != endpoint_query
        ):
            return web.Response(status=404)
        origin = setup["origin"]
        if request.path == "/mcp":
            header = 'Bearer scope="' + challenged_scope + '"'
            if advertised:
                header += ', resource_metadata="' + origin + '/metadata"'
            return web.Response(status=401, headers={"WWW-Authenticate": header})
        if request.path == "/metadata" or request.path == (
            "/.well-known/oauth-protected-resource"
            if root
            else "/.well-known/oauth-protected-resource/mcp"
        ):
            data = {
                "resource": origin + "/mcp" + ("?" + endpoint_query if endpoint_query else ""),
                "authorization_servers": [origin + "/tenant"],
                "scopes_supported": ["read"],
            }
        elif (
            request.path
            == [
                "/.well-known/oauth-authorization-server/tenant",
                "/.well-known/openid-configuration/tenant",
                "/tenant/.well-known/openid-configuration",
            ][oidc]
        ):
            data = {
                "issuer": origin + "/tenant",
                "authorization_endpoint": origin + "/authorize",
                "token_endpoint": origin + "/token",
                "revocation_endpoint": origin + "/revoke",
                "code_challenge_methods_supported": ["S256"],
                "response_types_supported": ["code"],
                "token_endpoint_auth_methods_supported": ["none"],
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "scopes_supported": ["read"],
                "authorization_response_iss_parameter_supported": True,
            }
        else:
            return web.Response(status=404)
        if mutate:
            data = mutate(data)
        if isinstance(data, web.StreamResponse):
            return data
        return web.json_response(data)

    app = web.Application()
    app.router.add_route("*", "/{path:.*}", handle)
    runner = web.AppRunner(app)
    await runner.setup()
    site = web.TCPSite(runner, "127.0.0.1", 0)
    await site.start()
    setup["origin"] = origin = "http://127.0.0.1:" + str(site._server.sockets[0].getsockname()[1])
    profile = {
        "transport": "http",
        "endpoint": origin + "/mcp" + ("?" + endpoint_query if endpoint_query else ""),
        "authentication": {
            "type": "oauth",
            "credential": {"source": "native", "name": "fixture"},
            "issuer": origin + "/tenant",
            "client_id": "fixture-client",
            "scopes": ["read"],
            "allowed_origins": [origin],
            "internal_origins": [origin],
            "callback_port": 0,
        },
    }
    try:
        yield Discovery(profile, SafeHTTP(internal_origins=[origin], seconds=0.5)), hits
    finally:
        await runner.cleanup()


@pytest.mark.parametrize(
    "oidc,root,advertised", [(0, False, False), (1, True, False), (2, False, True)]
)
def test_real_discovery_all_standard_locations(oidc, root, advertised):
    async def scenario():
        async with peers(oidc=oidc, root=root, advertised=advertised) as (discovery, hits):
            result = await discovery.discover()
            assert result["token_endpoint"] == discovery.origin + "/token"
            assert result["require_iss"] is True
            assert hits[0] == ("GET", "/mcp")
            if root:
                assert ("GET", "/.well-known/oauth-protected-resource") in hits
            if advertised:
                assert hits[1] == ("GET", "/metadata")
            assert not any(method != "GET" for method, _ in hits)

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "field,value",
    [
        ("resource", "https://other.example/mcp"),
        ("authorization_servers", ["https://other.example"]),
        ("authorization_servers", "not-a-list"),
        ("issuer", "https://other.example"),
        ("authorization_endpoint", "http://169.254.169.254/steal"),
        ("token_endpoint", "https://unapproved.example/token"),
        ("token_endpoint", "https://user:pass@approved.example/token"),
        ("code_challenge_methods_supported", ["plain"]),
        ("response_types_supported", ["token"]),
        ("token_endpoint_auth_methods_supported", ["client_secret_basic"]),
        ("grant_types_supported", ["password"]),
        ("scopes_supported", ["other"]),
        ("authorization_response_iss_parameter_supported", 1),
    ],
)
def test_metadata_cannot_expand_network_issuer_grant_or_scope(field, value):
    def mutate(data):
        if field in data:
            data[field] = value
        return data

    async def scenario():
        async with peers(mutate=mutate) as (discovery, hits):
            with pytest.raises(CapabilityError):
                await discovery.discover()
            assert all(method == "GET" for method, _ in hits)

    asyncio.run(scenario())


def test_scope_challenge_requires_explicit_operator_permission():
    async def scenario():
        async with peers(challenged_scope="write") as (discovery, hits):
            with pytest.raises(AuthenticationError, match="operator approval"):
                await discovery.discover()
            assert hits == [("GET", "/mcp")]

    asyncio.run(scenario())


def test_resource_metadata_preserves_endpoint_query():
    async def scenario():
        async with peers(endpoint_query="tenant=a") as (discovery, hits):
            result = await discovery.discover()
            assert result["token_endpoint"] == discovery.origin + "/token"
            assert discovery.resource.endswith("/mcp?tenant=a")
            assert hits[1] == ("GET", "/.well-known/oauth-protected-resource/mcp")

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "response",
    [
        web.Response(status=302, headers={"Location": "http://169.254.169.254/steal"}),
        web.Response(text="{}", content_type="text/html"),
        web.Response(text='{"resource":"a","resource":"b"}', content_type="application/json"),
        web.Response(text="x" * 65537, content_type="application/json"),
    ],
)
def test_real_metadata_errors_and_redirects_fail_closed(response):
    async def scenario():
        async with peers(mutate=lambda _: response) as (discovery, hits):
            with pytest.raises(CapabilityError):
                await discovery.discover()
            assert len(hits) == 2

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "headers",
    [
        ['Bearer scope="read", scope="write"'],
        ['Bearer scope="read"', 'Bearer scope="read"'],
        ['Bearer scope="read\nwrite"'],
        ["Bearer broken"],
        ['Bearer scope="unclosed'],
    ],
)
def test_ambiguous_or_malformed_challenge_rejected(headers):
    with pytest.raises(AuthenticationError):
        challenge(headers)


def test_challenge_supports_other_schemes_and_quoted_values():
    assert challenge(['Basic realm="other", Bearer scope="read", error_description="a,b"']) == {
        "scope": "read",
        "error_description": "a,b",
    }
    assert challenge(["Basic realm=other"]) == {}
    assert challenge(["Bearer"]) == {}


@pytest.mark.parametrize(
    "text", ["[]", "invalid", '{"x": NaN}', '{"x": Infinity}', '{"x":1,"x":2}']
)
def test_json_is_strict_and_diagnostics_do_not_echo_response(text):
    with pytest.raises(AuthenticationError) as error:
        object_json(text)
    assert text not in str(error.value)


def test_form_encoding_uses_the_same_guarded_transport():
    async def scenario():
        seen = []

        async def handle(request):
            seen.append((request.content_type, dict(await request.post())))
            return web.json_response({"ok": True})

        app = web.Application()
        app.router.add_post("/token", handle)
        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        origin = "http://127.0.0.1:" + str(site._server.sockets[0].getsockname()[1])
        http = SafeHTTP(internal_origins=[origin])
        try:
            async with http.open(
                "POST", origin + "/token", form={"code": "a+b &?", "resource": origin + "/mcp"}
            ) as response:
                assert json.loads(await http.read(response)) == {"ok": True}
            assert seen == [
                (
                    "application/x-www-form-urlencoded",
                    {"code": "a+b &?", "resource": origin + "/mcp"},
                )
            ]
            with pytest.raises(CapabilityError, match="Ambiguous"):
                async with http.open("POST", origin + "/token", form={"x": "y"}, body={}):
                    pass
            assert len(seen) == 1
        finally:
            await runner.cleanup()

    asyncio.run(scenario())
