"""OAuth grants through the real manager, grant store and loopback MCP/authorization peers.

Native credentials are the real OS store on Windows (or when the native credential
job sets BOTBRIDGE_TEST_NATIVE_CREDENTIALS=1). Elsewhere only the OS keychain
boundary is replaced by an in-memory backend; grant, lease and policy code is real.
"""

import argparse
import asyncio
import copy
import io
import json
import os
from pathlib import Path
import sqlite3
import sys
from unittest.mock import patch

from aiohttp import ClientSession, web
import pytest
from yarl import URL

from bridge_auth_policy import AuthenticationError
from bridge_capabilities import Capabilities
from bridge_credentials import PARTS
from bridge_mcp import AuthorizationRejected
from bridge_oauth_flow import GrantRejected
from test_capabilities import config_for, C, OWNER
from test_bridge import Bridge, Channel, Client, Message
import mcp_connections as cli

NATIVE = sys.platform == "win32" or os.environ.get("BOTBRIDGE_TEST_NATIVE_CREDENTIALS") == "1"
TOKEN_PREFIX = "synthetic-ticket27-grant-"


class MemoryCredentials:
    """OS keychain boundary substitute for hosts without a disposable native store."""

    def __init__(self):
        self.values = {}

    def get(self, key):
        return self.values.get(key)

    def set(self, key, value):
        self.values[key] = value

    def delete(self, key):
        self.values.pop(key, None)


class OAuthService:
    """One origin serving a protected MCP resource and its authorization server."""

    def __init__(self):
        self.issued = 0
        self.access, self.refresh = set(), set()
        self.exchanges, self.revocations, self.calls, self.authorizations = [], [], [], []
        self.expires_in = 3600
        self.token_delay = 0
        self.token_started = asyncio.Event()
        self.rotate = True
        self.revoke_status = 200
        self.issue_refresh = True
        self.revocation_endpoint = True
        self.metadata = True
        self.server_metadata = True
        self.echo = False

    def tokens(self):
        self.issued += 1
        access = TOKEN_PREFIX + "access-" + str(self.issued)
        refresh = TOKEN_PREFIX + "refresh-" + str(self.issued)
        self.access.add(access)
        if self.rotate:
            self.refresh.add(refresh)
        return access, refresh

    async def __aenter__(self):
        app = web.Application()
        app.router.add_route("*", "/{path:.*}", self.handle)
        self.runner = web.AppRunner(app, access_log=None)
        await self.runner.setup()
        await web.TCPSite(self.runner, "127.0.0.1", 0).start()
        self.origin = "http://127.0.0.1:" + str(self.runner.addresses[0][1])
        return self

    async def __aexit__(self, *args):
        await self.runner.cleanup()

    def challenge(self):
        metadata = self.origin + "/.well-known/oauth-protected-resource/mcp"
        return web.Response(
            status=401, headers={"WWW-Authenticate": f'Bearer resource_metadata="{metadata}"'}
        )

    async def handle(self, request):
        origin = self.origin
        if request.path == "/mcp":
            presented = request.headers.get("Authorization", "")
            key = request.headers.get("X-API-Key")
            if request.method != "POST" or (
                presented.removeprefix("Bearer ") not in self.access and key not in self.access
            ):
                return self.challenge()
            body = await request.json()
            self.calls.append((body["method"], presented or "X-API-Key " + key))
            # A hostile server may reflect the presented credential into its result.
            text = "authorized answer " + (presented or key) if self.echo else "authorized answer"
            result = (
                {"content": [{"type": "text", "text": text}]}
                if body["method"] == "tools/call"
                else {"tools": [{"name": "read_example", "inputSchema": {}}]}
            )
            return web.json_response({"jsonrpc": "2.0", "id": body["id"], "result": result})
        if request.path == "/.well-known/oauth-protected-resource/mcp" and self.metadata:
            return web.json_response(
                {"resource": origin + "/mcp", "authorization_servers": [origin]}
            )
        if request.path == "/.well-known/oauth-authorization-server" and self.server_metadata:
            server = {
                "issuer": origin,
                "authorization_endpoint": origin + "/authorize",
                "token_endpoint": origin + "/token",
                "code_challenge_methods_supported": ["S256"],
                "response_types_supported": ["code"],
                "token_endpoint_auth_methods_supported": ["none"],
            }
            if self.revocation_endpoint:
                server["revocation_endpoint"] = origin + "/revoke"
            return web.json_response(server)
        if request.path == "/authorize":
            query = request.query
            self.authorizations.append(dict(query))
            target = URL(query["redirect_uri"]).with_query(
                {"state": query["state"], "code": "synthetic-code", "iss": origin}
            )
            # The simulated browser follows this location; the peer issues no open redirect.
            return web.json_response({"location": str(target)})
        if request.path == "/token":
            fields = dict(await request.post())
            self.exchanges.append(fields["grant_type"])
            if fields["grant_type"] == "refresh_token":
                if fields["refresh_token"] not in self.refresh:
                    return web.json_response({"error": "invalid_grant"}, status=400)
                if self.rotate:
                    self.refresh.discard(fields["refresh_token"])  # Rotation: single use.
            self.token_started.set()
            await asyncio.sleep(self.token_delay)
            access, refresh = self.tokens()
            response = {
                "access_token": access,
                "token_type": "Bearer",
                "expires_in": self.expires_in,
                "scope": "read",
            }
            if self.issue_refresh and (self.rotate or fields["grant_type"] == "authorization_code"):
                response["refresh_token"] = refresh
                self.refresh.add(refresh)
            return web.json_response(response)
        if request.path == "/revoke":
            if self.revoke_status != 200:
                return web.Response(status=self.revoke_status)
            fields = dict(await request.post())
            self.revocations.append(fields["token"])
            self.refresh.discard(fields["token"])
            return web.Response(status=200)
        return web.Response(status=404)


async def browser(url):
    # Simulates only the browser; authorization, callback and token exchange are real HTTP.
    # The authorization peer returns its redirect target instead of issuing a 302.
    async with ClientSession() as session:
        async with session.get(url) as response:
            location = (await response.json())["location"]
        async with session.get(location) as response:
            await response.read()


def oauth_config(origin, name="docs"):
    config = config_for(origin)
    data = config["capabilities"]
    data["search"] = None
    data["connections"]["servers"] = {
        name: {
            "transport": "http",
            "endpoint": origin + "/mcp",
            "protocol": "2026-07-28",
            "authentication": {
                "type": "oauth",
                "credential": {"source": "native", "name": "docs-oauth"},
                "issuer": origin,
                "client_id": "fixture-client",
                "scopes": ["read"],
                "allowed_origins": [origin],
                "internal_origins": [origin],
                "callback_port": 0,
            },
        }
    }
    data["tools"]["lookup"]["connection"] = name
    return config


def capabilities(config, root, memory=None):
    caps = Capabilities(config, lambda _: None, root)
    if not NATIVE:
        caps.authentication.store._native = memory
    return caps


def cleanup(caps, names):
    store = caps.authentication.store
    for name in names:
        profile = caps.registry.profile(name)
        binding = caps.authentication.binding(name, profile)
        for part in PARTS:
            store.delete(profile["authentication"]["credential"], binding, part)


def stored_text(root):
    data = (Path(root) / "runtime_state" / "mcp_auth.sqlite3").read_bytes()
    return data.decode("latin-1")


def test_signin_refresh_rotation_rejection_and_logout_through_manager(tmp_path):
    async def scenario():
        async with OAuthService() as service:
            memory = MemoryCredentials()
            caps = capabilities(oauth_config(service.origin), tmp_path, memory)
            auth, profile = caps.authentication, caps.registry.profile("docs")
            try:
                assert await auth.status("docs", profile) == {
                    "authentication": "required",
                    "credentials": {},
                }
                with pytest.raises(AuthenticationError, match="sign-in required"):
                    await caps.connections.discover("docs")
                assert service.calls == [] and service.exchanges == []
                with pytest.raises(AuthenticationError, match="explicit sign-in"):
                    await auth.set_credential("docs", profile, "docs-oauth", "x")
                secrets = set()
                service.expires_in = 30  # Within the refresh skew: next use must refresh.
                await auth.signin("docs", profile, browser, secrets)
                assert service.exchanges == ["authorization_code"]
                assert service.authorizations[0]["resource"] == service.origin + "/mcp"
                assert (await auth.status("docs", profile))["authentication"] == "configured"
                service.expires_in = 3600
                used = set()
                assert (await caps.connections.discover("docs", used))[0]["name"] == "read_example"
                assert service.exchanges == ["authorization_code", "refresh_token"]
                assert service.calls[-1][1] == "Bearer " + TOKEN_PREFIX + "access-2"
                assert TOKEN_PREFIX + "access-2" in used and TOKEN_PREFIX + "refresh-2" in used
                # Cached access token: no second refresh, and the rotated refresh is stored.
                await caps.connections.discover("docs")
                assert service.exchanges.count("refresh_token") == 1
                # The resource revokes the access token: one 401, then one recovery refresh.
                service.access.clear()
                with pytest.raises(AuthorizationRejected):
                    await caps.connections.discover("docs")
                assert caps.connections.status("docs")["outcome"] == "rejected"
                await caps.connections.discover("docs")
                assert service.exchanges.count("refresh_token") == 2
                assert service.calls[-1][1] == "Bearer " + TOKEN_PREFIX + "access-3"
                for text in (stored_text(tmp_path), json.dumps(await auth.status("docs", profile))):
                    assert TOKEN_PREFIX not in text  # Metadata only; tokens are native.
                result = await auth.logout("docs", profile, set())
                assert result == {"authentication": "required", "revocation": "revoked"}
                assert service.revocations == [TOKEN_PREFIX + "refresh-3"]
                binding = auth.binding("docs", profile)
                reference = profile["authentication"]["credential"]
                for part in ("access", "refresh"):
                    assert auth.store.get(reference, binding, part) is None
                assert (await auth.status("docs", profile))["authentication"] == "required"
                with pytest.raises(AuthenticationError, match="sign-in required"):
                    await caps.connections.discover("docs")
                assert await auth.logout("docs", profile, set()) == {
                    "authentication": "required",
                    "revocation": "not_signed_in",
                }
            finally:
                cleanup(caps, ["docs"])

    asyncio.run(scenario())


def test_rejected_refresh_requires_sign_in_and_unrevocable_logout_is_local(tmp_path):
    async def scenario():
        async with OAuthService() as service:
            memory = MemoryCredentials()
            caps = capabilities(oauth_config(service.origin), tmp_path, memory)
            auth, profile = caps.authentication, caps.registry.profile("docs")
            try:
                service.expires_in = 30
                await auth.signin("docs", profile, browser, set())
                service.refresh.clear()  # Provider-side revocation of the refresh token.
                with pytest.raises(GrantRejected, match="sign in again"):
                    await caps.connections.discover("docs")
                assert (await auth.status("docs", profile))["authentication"] == "expired"
                with pytest.raises(AuthenticationError, match="sign-in required"):
                    await caps.connections.discover("docs")
                assert service.exchanges.count("refresh_token") == 1
                # Revocation endpoint failure leaves only the local deletion guarantee.
                service.revoke_status = 503
                result = await auth.logout("docs", profile, set())
                assert result["revocation"] == "local_only" and service.revocations == []
                assert (await auth.status("docs", profile))["authentication"] == "required"
            finally:
                cleanup(caps, ["docs"])

    asyncio.run(scenario())


def test_concurrent_processes_refresh_once_and_never_cross_profiles(tmp_path):
    async def scenario():
        async with OAuthService() as service:
            memory = MemoryCredentials()
            config = oauth_config(service.origin)
            other = copy.deepcopy(config["capabilities"]["connections"]["servers"]["docs"])
            config["capabilities"]["connections"]["servers"]["other"] = other
            first = capabilities(config, tmp_path, memory)
            # A second process shares the folder (metadata) and the native store only.
            second = capabilities(copy.deepcopy(config), tmp_path, memory)
            profile = first.registry.profile("docs")
            try:
                service.expires_in = 30
                await first.authentication.signin("docs", profile, browser, set())
                service.expires_in = 3600
                service.token_delay = 0.2
                results = await asyncio.gather(
                    first.connections.discover("docs"),
                    first.authentication.oauth.token(
                        profile, first.authentication.binding("docs", profile), set()
                    ),
                    second.connections.discover("docs"),
                )
                assert results[0][0]["name"] == results[2][0]["name"] == "read_example"
                assert service.exchanges == ["authorization_code", "refresh_token"]
                # An identical profile under another alias has a separate binding/grant.
                with pytest.raises(AuthenticationError, match="sign-in required"):
                    await first.connections.discover("other")
                assert {c[1] for c in service.calls} == {"Bearer " + TOKEN_PREFIX + "access-2"}
            finally:
                cleanup(first, ["docs", "other"])

    asyncio.run(scenario())


def test_cancelled_refresh_still_commits_and_logout_cannot_be_resurrected(tmp_path):
    async def scenario():
        async with OAuthService() as service:
            memory = MemoryCredentials()
            caps = capabilities(oauth_config(service.origin), tmp_path, memory)
            auth, profile = caps.authentication, caps.registry.profile("docs")
            binding = auth.binding("docs", profile)
            reference = profile["authentication"]["credential"]
            try:
                service.expires_in = 30
                await auth.signin("docs", profile, browser, set())
                service.token_delay = 0.2
                waiter = asyncio.create_task(auth.oauth.token(profile, binding, set()))
                await asyncio.wait_for(service.token_started.wait(), 2)
                waiter.cancel()
                with pytest.raises(asyncio.CancelledError):
                    await waiter
                service.token_delay = 0
                # The shielded refresh finished and stored the rotated grant.
                token = await auth.oauth.token(profile, binding, set())
                assert token == TOKEN_PREFIX + "access-2"
                assert service.exchanges.count("refresh_token") == 1
                assert auth.store.get(reference, binding, "refresh") == TOKEN_PREFIX + "refresh-2"
                # A logout during a slow refresh wins; the late result is discarded.
                auth.oauth.grants.mark(binding, 2, refreshable=True)
                service.token_started.clear()
                service.token_delay = 0.3
                refresh = asyncio.create_task(auth.oauth.token(profile, binding, set()))
                await asyncio.wait_for(service.token_started.wait(), 2)
                await auth.logout("docs", profile, set())
                with pytest.raises(AuthenticationError, match="changed during refresh"):
                    await refresh
                for part in ("access", "refresh"):
                    assert auth.store.get(reference, binding, part) is None
                assert (await auth.status("docs", profile))["authentication"] == "required"
            finally:
                cleanup(caps, ["docs"])

    asyncio.run(scenario())


def test_abandoned_lease_expires_and_busy_lease_is_bounded(tmp_path):
    async def scenario():
        caps = capabilities(oauth_config("https://fixture.example"), tmp_path, MemoryCredentials())
        grants = caps.authentication.oauth.grants
        grants.lease_seconds = 0.2
        assert await asyncio.to_thread(grants.acquire, "b" * 64, "crashed-owner")
        async with grants.lease("b" * 64):
            pass  # Acquired after the abandoned lease expired.
        # A live holder's lease outlasts this waiter's bounded wait (one short period).
        grants.lease_seconds = 30
        assert await asyncio.to_thread(grants.acquire, "c" * 64, "live-owner")
        grants.lease_seconds = 0.2
        with pytest.raises(AuthenticationError, match="busy"):
            async with grants.lease("c" * 64):
                pass
        with sqlite3.connect(grants.path) as db:
            assert db.execute("SELECT count(*) FROM oauth_grants").fetchone() == (0,)

    asyncio.run(scenario())


def test_cli_credential_crud_signin_status_and_logout_never_print_secrets(tmp_path, capsys):
    async def scenario():
        async with OAuthService() as service:
            config = oauth_config(service.origin)
            servers = config["capabilities"]["connections"]["servers"]
            servers["bearer"] = {
                "transport": "http",
                "endpoint": service.origin + "/mcp",
                "protocol": "2026-07-28",
                "authentication": {
                    "type": "bearer",
                    "credential": {"source": "native", "name": "bearer-token"},
                },
            }
            source = tmp_path / "config.json"
            source.write_text(json.dumps(config))
            memory = MemoryCredentials()
            original = Capabilities

            def factory(config, log, root=tmp_path):
                caps = original(config, log, root)
                if not NATIVE:
                    caps.authentication.store._native = memory
                return caps

            loop = asyncio.get_running_loop()

            def launched(url):
                asyncio.run_coroutine_threadsafe(browser(url), loop).result(5)
                return True

            def run(action, **extra):
                return cli.execute(argparse.Namespace(config=str(source), action=action, **extra))

            secret = TOKEN_PREFIX + "bearer-value"
            service.access.add(secret)
            with patch.object(cli, "Capabilities", factory):
                try:
                    with patch("sys.stdin", io.StringIO(secret + "\r\n")):
                        status = await run(
                            "credential-set", name="bearer", reference="bearer-token", stdin=True
                        )
                    assert status["credentials"] == {"bearer-token": "set"}
                    with patch("getpass.getpass", return_value=secret):
                        await run(
                            "credential-set", name="bearer", reference="bearer-token", stdin=False
                        )
                    with pytest.raises(AuthenticationError, match="Unknown"):
                        await run("credential-set", name="bearer", reference="x", stdin=True)
                    with patch("webbrowser.open", launched):
                        status = await run("signin", name="docs", no_browser=False)
                    assert status["authentication"] == "configured"
                    listing = await run("status")
                    assert [s["authentication"] for s in listing] == ["configured", "configured"]
                    tested = await run("discover", name="bearer")
                    assert tested["tools"] == ["read_example"]
                    assert tested["authentication"] == "configured"
                    assert service.calls[-1][1] == "Bearer " + secret
                    assert (await run("logout", name="docs"))["revocation"] == "revoked"
                    status = await run("credential-delete", name="bearer", reference="bearer-token")
                    assert status["credentials"] == {"bearer-token": "not_set"}
                    with pytest.raises(AuthenticationError, match="does not use OAuth"):
                        await run("signin", name="bearer", no_browser=True)
                finally:
                    caps = factory(config, lambda _: None)
                    cleanup(caps, ["docs"])
                    caps.authentication.store.delete(
                        {"source": "native", "name": "bearer-token"},
                        caps.authentication.binding("bearer", caps.registry.profile("bearer")),
                    )
            captured = capsys.readouterr()
            assert TOKEN_PREFIX not in captured.out + captured.err
            assert "Complete sign-in in your browser" in captured.err

    asyncio.run(scenario())


def test_cli_reports_static_authentication_guidance(tmp_path, capsys):
    config = oauth_config("https://fixture.example")
    source = tmp_path / "config.json"
    source.write_text(json.dumps(config))
    assert cli.main(["--config", str(source), "logout", "missing"]) == 1
    assert "configuration or connection failed" in capsys.readouterr().err
    with patch.object(
        cli, "Capabilities", lambda data, _log: capabilities(data, tmp_path, MemoryCredentials())
    ):
        assert cli.main(["--config", str(source), "credential-set", "docs", "docs-oauth"]) == 1
    error = capsys.readouterr().err
    assert error.startswith("MCP authentication failed: OAuth credentials are stored only")
    assert C and OWNER


class FailingWrites(MemoryCredentials):
    """Keychain boundary that refuses writes, as a locked or full native store would."""

    def set(self, key, value):
        raise OSError("synthetic native write failure " + value)


def test_grant_edge_paths_store_failures_and_races(tmp_path):
    async def scenario():
        async with OAuthService() as service:
            memory = MemoryCredentials()
            caps = capabilities(oauth_config(service.origin), tmp_path, memory)
            auth, profile = caps.authentication, caps.registry.profile("docs")
            oauth, grants = auth.oauth, auth.oauth.grants
            binding = auth.binding("docs", profile)
            reference = profile["authentication"]["credential"]
            try:
                # Never signed in: logout/rejection are no-ops with masked results.
                assert await auth.logout("docs", profile, set()) == {
                    "authentication": "required",
                    "revocation": "not_signed_in",
                }
                await oauth.rejected(profile, binding)
                # A provider without refresh tokens: expiry requires a new sign-in.
                service.issue_refresh, service.expires_in = False, 30
                await auth.signin("docs", profile, browser, set())
                assert grants.refresh_token(reference, binding) is None
                assert (await auth.status("docs", profile))["authentication"] == "expired"
                with pytest.raises(AuthenticationError, match="sign-in required"):
                    await caps.connections.discover("docs")
                service.issue_refresh = True
                # Native refresh entry removed outside the bridge: sign-in, never plaintext.
                await auth.signin("docs", profile, browser, set())
                auth.store.delete(reference, binding, "refresh")
                with pytest.raises(AuthenticationError, match="sign-in required"):
                    await caps.connections.discover("docs")
                # Logout races a waiter queued behind another process's lease.
                await auth.signin("docs", profile, browser, set())
                assert grants.acquire(binding, "other-process")
                waiter = asyncio.create_task(oauth.token(profile, binding, set()))
                await asyncio.sleep(0.2)
                await asyncio.to_thread(grants.remove, reference, binding)
                grants.release(binding, "other-process")
                with pytest.raises(AuthenticationError, match="sign-in required"):
                    await waiter
                # A failed native write disables the grant and reports a static error.
                caps.authentication.store._native = FailingWrites()
                with pytest.raises(Exception) as error:
                    await auth.signin("docs", profile, browser, set())
                assert TOKEN_PREFIX not in str(error.value)
                caps.authentication.store._native = memory if not NATIVE else None
                assert (await auth.status("docs", profile))["authentication"] == "required"
                # Unavailable native store for an active grant: masked status, no fallback.
                await auth.signin("docs", profile, browser, set())
                with patch("sys.platform", "unsupported"):
                    caps.authentication.store._native = None
                    assert await auth.status("docs", profile) == {
                        "authentication": "unavailable",
                        "credentials": {},
                    }
                caps.authentication.store._native = memory if not NATIVE else None
                # No revocation endpoint: logout is local-only guidance.
                service.revocation_endpoint = False
                assert (await auth.logout("docs", profile, set()))["revocation"] == "local_only"
                service.revocation_endpoint = True
                # Discovery metadata missing at every RFC 8414 / OIDC location, then RFC 9728.
                service.server_metadata = False
                with pytest.raises(AuthenticationError, match="authorization metadata"):
                    await auth.signin("docs", profile, browser, set())
                service.metadata = False
                with pytest.raises(AuthenticationError, match="resource metadata"):
                    await auth.signin("docs", profile, browser, set())
                assert service.exchanges.count("authorization_code") == 5
            finally:
                cleanup(caps, ["docs"])

    asyncio.run(scenario())


def test_bearer_rejection_and_stdio_native_credentials_use_the_same_api(tmp_path):
    async def scenario():
        async with OAuthService() as service:
            memory = MemoryCredentials()
            config = oauth_config(service.origin)
            servers = config["capabilities"]["connections"]["servers"]
            servers["bearer"] = {
                "transport": "http",
                "endpoint": service.origin + "/mcp",
                "protocol": "2026-07-28",
                "authentication": {
                    "type": "bearer",
                    "credential": {"source": "native", "name": "bearer-token"},
                },
            }
            servers["local"] = {
                "transport": "stdio",
                "command": sys.executable,
                "arguments": ["-c", "pass"],
                "cwd": str(tmp_path),
                "environment": {},
                "credentials": {"LOCAL_TOKEN": {"source": "native", "name": "local-token"}},
            }
            caps = capabilities(config, tmp_path, memory)
            auth = caps.authentication
            bearer, local = caps.registry.profile("bearer"), caps.registry.profile("local")
            try:
                await auth.set_credential("bearer", bearer, "bearer-token", TOKEN_PREFIX + "x")
                with pytest.raises(AuthorizationRejected):
                    await caps.connections.discover("bearer")
                assert caps.connections.status("bearer")["outcome"] == "rejected"
                with pytest.raises(AuthenticationError, match="header"):
                    await auth.set_credential("bearer", bearer, "bearer-token", "bad value")
                # Stdio values are environment strings, not header values.
                await auth.set_credential(
                    "local", local, "local-token", TOKEN_PREFIX + "with space"
                )
                assert await auth.environment("local", local, set()) == {
                    "LOCAL_TOKEN": TOKEN_PREFIX + "with space"
                }
                assert (await auth.status("local", local))["credentials"] == {"local-token": "set"}
                # An unavailable store is reported, never replaced by another source.
                backend = auth.store._native
                with patch("sys.platform", "unsupported"):
                    auth.store._native = None
                    assert await auth.status("local", local) == {
                        "authentication": "unavailable",
                        "credentials": {"local-token": "unavailable"},
                    }
                auth.store._native = backend
                await auth.delete_credential("local", local, "local-token")
                with pytest.raises(AuthenticationError, match="does not use OAuth"):
                    await auth.logout("local", local, set())
            finally:
                for name, profile, reference in (
                    ("bearer", bearer, "bearer-token"),
                    ("local", local, "local-token"),
                ):
                    auth.store.delete(
                        {"source": "native", "name": reference}, auth.binding(name, profile)
                    )

    asyncio.run(scenario())


def test_open_browser_without_launch_only_prints(capsys):
    with patch("webbrowser.open", side_effect=AssertionError("browser must not open")):
        asyncio.run(cli.open_browser("http://127.0.0.1:1/authorize?state=x", False))
    assert "127.0.0.1:1/authorize" in capsys.readouterr().err


def test_custom_headers_and_reflected_oauth_tokens_through_the_discord_consumer(tmp_path):
    (tmp_path / "MEMORY.md").write_text("public synthetic context")
    (tmp_path / "public_context.md").write_text("public context")

    async def scenario():
        async with OAuthService() as service:
            memory = MemoryCredentials()
            config = oauth_config(service.origin)
            config["capabilities"]["connections"]["servers"]["keyed"] = {
                "transport": "http",
                "endpoint": service.origin + "/mcp",
                "protocol": "2026-07-28",
                "authentication": {
                    "type": "headers",
                    "credentials": {"X-API-Key": {"source": "native", "name": "docs-key"}},
                },
            }
            logs, prompts = [], []

            async def provider(prompt, work=False):
                prompts.append(prompt)
                return json.dumps({"decision": "stop", "reply": "summary"})

            bridge = Bridge(Client(C), C, provider, logs.append, tmp_path, tmp_path, config=config)
            caps = bridge.capabilities
            if not NATIVE:
                caps.authentication.store._native = memory
            auth = caps.authentication
            keyed = caps.registry.profile("keyed")
            try:
                key = TOKEN_PREFIX + "header-key"
                service.access.add(key)
                await auth.set_credential("keyed", keyed, "docs-key", key)
                assert (await caps.connections.discover("keyed"))[0]["name"] == "read_example"
                assert service.calls[-1][1] == "X-API-Key " + key
                await auth.signin("docs", caps.registry.profile("docs"), browser, set())
                service.echo = True
                channel = Channel()
                await bridge.handle(Message(1, f'<@{C}> /mcp lookup {{"query":"x"}}', channel))
                public = "\n".join(m.content for m, _ in channel.sent)
                assert service.calls[-1][0] == "tools/call"
                assert prompts and "REDACTED CREDENTIAL" in prompts[0]
                for text in (prompts[0], public, "\n".join(logs), stored_text(tmp_path)):
                    assert TOKEN_PREFIX not in text
            finally:
                cleanup(caps, ["docs"])
                auth.store.delete(
                    {"source": "native", "name": "docs-key"}, auth.binding("keyed", keyed)
                )

    asyncio.run(scenario())


def test_slow_refresh_cannot_outlive_its_lease(tmp_path):
    async def scenario():
        async with OAuthService() as service:
            caps = capabilities(oauth_config(service.origin), tmp_path, MemoryCredentials())
            auth, profile = caps.authentication, caps.registry.profile("docs")
            binding = auth.binding("docs", profile)
            try:
                service.expires_in = 30
                await auth.signin("docs", profile, browser, set())
                auth.oauth.grants.lease_seconds = 0.4
                service.token_delay = 0.5
                with pytest.raises(TimeoutError):
                    await auth.oauth.token(profile, binding, set())
                # The lease was released and nothing was committed from the late response.
                assert auth.oauth.grants.acquire(binding, "next-process")
                auth.oauth.grants.release(binding, "next-process")
                assert service.issued == 1 and service.exchanges.count("refresh_token") == 1
            finally:
                cleanup(caps, ["docs"])

    asyncio.run(scenario())
