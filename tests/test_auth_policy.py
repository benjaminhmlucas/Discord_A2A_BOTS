"""Authentication policy resolves real scoped references, not mocked credentials."""

import asyncio
import copy
import json
import os
import sys
import uuid
from unittest.mock import patch

import pytest

from bridge_auth_policy import AuthenticationError, checked_authentication
from bridge_authentication import Authentication
from bridge_credentials import CredentialStore, CredentialError
from bridge_http import SafeHTTP
from bridge_oauth_grants import GrantStore, OAuthTokens

ENV = {"source": "environment", "name": "BOTBRIDGE_MCP_FIXTURE"}
NATIVE = {"source": "native", "name": "fixture"}
CANARY = "synthetic-ticket27-auth-policy-canary"


def service(store, principal, path):
    return Authentication(
        store, principal, OAuthTokens(GrantStore(store, path / "auth.sqlite3"), SafeHTTP())
    )


def profile(auth):
    return {
        "transport": "http",
        "endpoint": "https://example.com/mcp",
        "protocol": "2025-11-25",
        "authentication": auth,
    }


def oauth():
    return {
        "type": "oauth",
        "credential": NATIVE,
        "issuer": "https://issuer.example",
        "client_id": "registered-public-client",
        "scopes": ["docs:read"],
        "allowed_origins": ["https://issuer.example"],
        "internal_origins": [],
        "callback_port": 0,
    }


@pytest.mark.parametrize(
    "auth",
    [
        None,
        [],
        {},
        {"type": "unknown"},
        {"type": "none", "extra": 1},
        {"type": "bearer"},
        {"type": "bearer", "credential": "plaintext"},
        {"type": "headers", "credentials": {}},
        {"type": "headers", "credentials": []},
        *[
            {"type": "headers", "credentials": {h: ENV}}
            for h in [
                "Host",
                "Authorization",
                "Cookie",
                "Content-Length",
                "Mcp-Name",
                "X-Forwarded-Host",
                "X-Real-IP",
                "X-HTTP-Method-Override",
                "bad\nname",
            ]
        ],
        {"type": "headers", "credentials": {"X-Key": ENV, "x-key": ENV}},
    ],
)
def test_authentication_configuration_is_explicit_and_restricted(auth):
    with pytest.raises(ValueError):
        checked_authentication(auth)


@pytest.mark.parametrize(
    "key,value",
    [
        ("credential", ENV),
        ("client_id", []),
        ("client_id", ""),
        ("client_id", "bad\n"),
        ("callback_port", True),
        ("callback_port", 65536),
        ("scopes", ["bad scope"]),
        ("scopes", ["docs:read"] * 2),
        ("scopes", [] * 0 + ["x"] * 17),
        ("allowed_origins", []),
        ("allowed_origins", 1),
        ("internal_origins", 1),
        ("internal_origins", ["http://127.0.0.1:9999"]),
        ("allowed_origins", ["https://issuer.example/path"]),
        ("issuer", "https://issuer.example?query=1"),
        ("issuer", "https://other.example"),
    ],
)
def test_oauth_policy_binds_operator_selected_issuer_and_network_origins(key, value):
    data = oauth()
    data[key] = value
    with pytest.raises(ValueError):
        checked_authentication(data)


def test_explicit_environment_credentials_headers_and_no_secret_status(tmp_path):
    async def scenario():
        auth_api = service(CredentialStore("test"), [201, 301], tmp_path)
        secrets = set()
        with patch.dict(os.environ, {ENV["name"]: CANARY}):
            for kind, expected, masked in [
                ("none", {}, {"authentication": "none", "credentials": {}}),
                (
                    "bearer",
                    {"Authorization": "Bearer " + CANARY},
                    {"authentication": "configured", "credentials": {ENV["name"]: "set"}},
                ),
                (
                    "headers",
                    {"X-API-Key": CANARY},
                    {"authentication": "configured", "credentials": {ENV["name"]: "set"}},
                ),
            ]:
                auth = {"type": kind}
                if kind == "bearer":
                    auth["credential"] = ENV
                if kind == "headers":
                    auth["credentials"] = {"X-API-Key": ENV}
                configured = profile(auth)
                assert await auth_api.headers("docs", configured, secrets) == expected
                status = await auth_api.status("docs", configured)
                assert status == masked
                assert CANARY not in json.dumps(status)
            assert secrets == {CANARY}
            configured = {"credentials": {"API_KEY": ENV}}
            assert await auth_api.environment("local", configured, secrets) == {"API_KEY": CANARY}
            for bad in ("", "bad\nheader", "has spaces", "unicode-\u00e9"):
                with patch.dict(os.environ, {ENV["name"]: bad}):
                    with pytest.raises(ValueError):
                        await auth_api.headers(
                            "docs", profile({"type": "bearer", "credential": ENV}), secrets
                        )
        with patch.dict(os.environ):
            os.environ.pop(ENV["name"], None)
            assert await auth_api.status(
                "docs", profile({"type": "bearer", "credential": ENV})
            ) == {"authentication": "required", "credentials": {ENV["name"]: "not_set"}}

    asyncio.run(scenario())


@pytest.mark.skipif(
    sys.platform != "win32" and os.environ.get("BOTBRIDGE_TEST_NATIVE_CREDENTIALS") != "1",
    reason="Native credential CI/session required",
)
def test_native_credential_is_bound_to_principal_alias_and_configuration(tmp_path):
    async def scenario():
        store = CredentialStore("test-" + uuid.uuid4().hex)
        auth_api = service(store, [201, 301], tmp_path)
        configured = profile({"type": "bearer", "credential": NATIVE})
        binding = auth_api.binding("docs", configured)
        try:
            store.set(NATIVE, binding, CANARY)
            assert await auth_api.headers("docs", configured, set()) == {
                "Authorization": "Bearer " + CANARY
            }
            changed = copy.deepcopy(configured)
            changed["endpoint"] = "https://different.example/mcp"
            for other, alias, config in [
                (auth_api, "other", configured),
                (auth_api, "docs", changed),
                (service(store, [202, 301], tmp_path), "docs", configured),
            ]:
                with pytest.raises(CredentialError, match="unavailable"):
                    await other.headers(alias, config, set())
            assert CANARY not in json.dumps(await auth_api.status("docs", configured))
            with pytest.raises(AuthenticationError, match="sign-in required"):
                await auth_api.headers("oauth", profile(oauth()), set())
            with patch("sys.platform", "unsupported"):
                unavailable = service(
                    CredentialStore("test-" + uuid.uuid4().hex), [201, 301], tmp_path
                )
                assert await unavailable.status("docs", configured) == {
                    "authentication": "unavailable",
                    "credentials": {"fixture": "unavailable"},
                }
        finally:
            store.delete(NATIVE, binding)

    asyncio.run(scenario())
