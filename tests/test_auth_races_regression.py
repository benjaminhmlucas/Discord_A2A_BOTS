"""Adversarial auth regressions using real grants, transports and Discord consumer.

Only the native OS credential boundary is substituted, with explicit read/delete
faults. All credentials, HTTP servers, browser callbacks and providers are synthetic.
"""

import asyncio
import json

import pytest

from bridge_auth_policy import AuthenticationError
from bridge_capabilities import Capabilities
from bridge_credentials import CredentialError, PARTS
from bridge_mcp import AuthorizationRejected
from test_bridge import Bridge, Channel, Client, Message
from test_capabilities import C, config_for
from test_oauth_grants import MemoryCredentials, OAuthService, browser, oauth_config


class FaultyNativeBoundary(MemoryCredentials):
    def __init__(self):
        super().__init__()
        self.failed_operation = None

    def get(self, key):
        if self.failed_operation == "get":
            raise OSError("synthetic native read unavailable")
        return super().get(key)

    def delete(self, key):
        if self.failed_operation == "delete":
            raise OSError("synthetic native deletion unavailable")
        return super().delete(key)


def synthetic_caps(config, root, native):
    caps = Capabilities(config, lambda _: None, root)
    caps.authentication.store._native = native
    return caps


def cleanup(caps, name):
    profile = caps.registry.profile(name)
    reference = profile["authentication"]["credential"]
    binding = caps.authentication.binding(name, profile)
    for part in PARTS:
        caps.authentication.store.delete(reference, binding, part)


@pytest.mark.parametrize("operation", ["get", "delete"])
def test_native_logout_failure_does_not_reactivate_grant(tmp_path, operation):
    async def scenario():
        async with OAuthService() as service:
            native = FaultyNativeBoundary()
            caps = synthetic_caps(oauth_config(service.origin), tmp_path, native)
            auth, profile = caps.authentication, caps.registry.profile("docs")
            binding = auth.binding("docs", profile)
            reference = profile["authentication"]["credential"]
            try:
                await auth.signin("docs", profile, browser, set())
                native.failed_operation = operation
                with pytest.raises(CredentialError):
                    await auth.logout("docs", profile, set())
                native.failed_operation = None
                row, access = auth.oauth.grants.load(reference, binding)
                assert row is not None and not row["active"]
                assert access is None
                assert (await auth.status("docs", profile))["authentication"] == "required"
                with pytest.raises(AuthenticationError, match="sign-in required"):
                    await caps.connections.discover("docs")
                assert not service.calls
            finally:
                native.failed_operation = None
                cleanup(caps, "docs")
                assert not native.values

    asyncio.run(scenario())


def test_late_rejection_cannot_create_or_reactivate_a_grant(tmp_path):
    async def scenario():
        async with OAuthService() as service:
            native = MemoryCredentials()
            caps = synthetic_caps(oauth_config(service.origin), tmp_path, native)
            auth, profile = caps.authentication, caps.registry.profile("docs")
            reference = profile["authentication"]["credential"]
            binding = auth.binding("docs", profile)
            try:
                await auth.oauth.rejected(profile, binding, "Bearer synthetic-old-token")
                assert auth.oauth.grants.load(reference, binding) == (None, None)
                assert not native.values and not service.calls
                await auth.signin("docs", profile, browser, set())
                await auth.logout("docs", profile, set())
                before, _ = auth.oauth.grants.load(reference, binding)
                await auth.oauth.rejected(profile, binding, "Bearer synthetic-old-token")
                after, access = auth.oauth.grants.load(reference, binding)
                assert before == after and not after["active"] and access is None
            finally:
                cleanup(caps, "docs")
                assert not native.values

    asyncio.run(scenario())


class DelayedOldRejection(OAuthService):
    def __init__(self):
        super().__init__()
        self.rejected_authorization = None
        self.request_started = asyncio.Event()
        self.release_response = asyncio.Event()

    async def handle(self, request):
        if (
            request.path == "/mcp"
            and request.method == "POST"
            and request.headers.get("Authorization") == self.rejected_authorization
        ):
            self.request_started.set()
            await self.release_response.wait()
            return self.challenge()
        return await super().handle(request)


def test_late_old_401_cannot_expire_newer_signin(tmp_path):
    async def scenario():
        async with DelayedOldRejection() as service:
            native = MemoryCredentials()
            caps = synthetic_caps(oauth_config(service.origin), tmp_path, native)
            auth, profile = caps.authentication, caps.registry.profile("docs")
            binding = auth.binding("docs", profile)
            reference = profile["authentication"]["credential"]
            pending = None
            try:
                await auth.signin("docs", profile, browser, set())
                first = await auth.headers("docs", profile, set())
                service.rejected_authorization = first["Authorization"]
                pending = asyncio.create_task(caps.connections.discover("docs"))
                await asyncio.wait_for(service.request_started.wait(), 2)
                await auth.signin("docs", profile, browser, set())
                before, new_access = auth.oauth.grants.load(reference, binding)
                assert before["generation"] == 2 and new_access is not None
                service.release_response.set()
                with pytest.raises(AuthorizationRejected):
                    await pending
                after, access = auth.oauth.grants.load(reference, binding)
                assert after == before and access == new_access
                assert (await caps.connections.discover("docs"))[0]["name"] == "read_example"
                assert service.exchanges == ["authorization_code", "authorization_code"]
            finally:
                service.release_response.set()
                if pending is not None:
                    await asyncio.gather(pending, return_exceptions=True)
                cleanup(caps, "docs")
                assert not native.values

    asyncio.run(scenario())


@pytest.mark.parametrize(
    "placement",
    ["argument", "message", "public_context", "reply_message", "reply_mcp", "reply_search"],
)
def test_native_credentials_cannot_reach_tools_or_provider(tmp_path, placement):
    async def scenario():
        async with OAuthService() as service:
            secret = "synthetic-pr30-native-redaction-canary"
            (tmp_path / "MEMORY.md").write_text("public synthetic memory")
            (tmp_path / "public_context.md").write_text(
                secret if placement == "public_context" else "public context"
            )
            config = config_for(service.origin)
            profile = config["capabilities"]["connections"]["servers"]["fixture"]
            profile["authentication"] = {
                "type": "bearer",
                "credential": {"source": "native", "name": "fixture"},
            }
            prompts, logs = [], []

            async def provider(prompt, work=False):
                prompts.append(prompt)
                return secret if placement.startswith("reply_") else "synthetic provider answer"

            bridge = Bridge(Client(C), C, provider, logs.append, tmp_path, tmp_path, config=config)
            native = MemoryCredentials()
            caps = bridge.capabilities
            caps.authentication.store._native = native
            try:
                await caps.authentication.set_credential("fixture", profile, "fixture", secret)
                service.access.add(secret)
                if placement in ("message", "reply_message"):
                    value = secret if placement == "message" else "public synthetic value"
                    text = f"Please explain this value: {value}"
                elif placement == "reply_search":
                    text = "/search public query"
                else:
                    query = secret if placement == "argument" else "public query"
                    text = "/mcp lookup " + json.dumps({"query": query})
                channel = Channel()
                await bridge.handle(Message(1, f"<@{C}> " + text, channel))
                if placement == "argument":
                    assert not service.calls
                    assert not prompts
                else:
                    assert len(prompts) == 1
                    if placement.startswith("reply_"):
                        assert any(
                            "REDACTED CREDENTIAL" in message.content for message, _ in channel.sent
                        )
                    else:
                        assert "REDACTED CREDENTIAL" in prompts[0]
                assert all(secret not in text for text in prompts + logs)
                assert all(secret not in message.content for message, _ in channel.sent)
            finally:
                cleanup(caps, "fixture")
                assert not native.values

    asyncio.run(scenario())
