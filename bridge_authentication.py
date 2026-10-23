"""One authentication/secret API for the runtime, operator CLI and future GUI.

Statuses are masked. Credentials never enable a tool or change authorization policy.
"""

import asyncio
from collections.abc import Awaitable, Callable
import hashlib
import os
from pathlib import Path
from typing import Any

from bridge_auth_policy import (
    checked_authentication,
    header_value,
    references,
    require,
)
from bridge_credentials import (
    CredentialError,
    CredentialStore,
    checked_reference,
    checked_secret,
    connection_binding,
)
from bridge_http import SafeHTTP
from bridge_oauth_grants import GrantStore, OAuthTokens


class Authentication:
    def __init__(self, store: CredentialStore, principal: object, oauth: OAuthTokens) -> None:
        self.store, self.principal, self.oauth = store, principal, oauth

    def binding(self, connection: str, profile: dict[str, Any]) -> str:
        return connection_binding(self.principal, connection, profile)

    @staticmethod
    def oauth_profile(profile: dict[str, Any]) -> bool:
        return bool(profile["transport"] == "http" and profile["authentication"]["type"] == "oauth")

    async def credential(self, reference: dict[str, str], binding: str, secrets: set[str]) -> str:
        value = await asyncio.to_thread(self.store.get, reference, binding)
        if value is None:
            raise CredentialError("MCP credential unavailable; configure the selected reference")
        secrets.add(value)
        return value

    async def headers(
        self, connection: str, profile: dict[str, Any], secrets: set[str]
    ) -> dict[str, str]:
        auth = profile["authentication"]
        checked_authentication(auth)
        binding = self.binding(connection, profile)
        if auth["type"] == "none":
            return {}
        if auth["type"] == "oauth":
            token = await self.oauth.token(profile, binding, secrets)
            return {"Authorization": "Bearer " + header_value(token)}
        if auth["type"] == "bearer":
            value = await self.credential(auth["credential"], binding, secrets)
            return {"Authorization": "Bearer " + header_value(value)}
        result = {}
        for name, ref in auth["credentials"].items():
            result[name] = header_value(await self.credential(ref, binding, secrets))
        return result

    async def environment(
        self, connection: str, profile: dict[str, Any], secrets: set[str]
    ) -> dict[str, str]:
        binding = self.binding(connection, profile)
        result = {}
        for name, ref in profile["credentials"].items():
            checked_reference(ref)
            result[name] = await self.credential(ref, binding, secrets)
        return result

    async def rejected(self, connection: str, profile: dict[str, Any]) -> None:
        """A server refused the presented credential; OAuth refreshes next time."""
        if self.oauth_profile(profile):
            await self.oauth.rejected(profile, self.binding(connection, profile))

    def settable(self, profile: dict[str, Any], name: str) -> dict[str, str]:
        require(
            not self.oauth_profile(profile),
            "OAuth credentials are stored only by the explicit sign-in command",
        )
        refs = references(profile)
        require(name in refs, "Unknown MCP credential reference")
        require(
            refs[name]["source"] == "native",
            "Environment credentials are externally managed; set them outside the bridge",
        )
        return refs[name]

    async def set_credential(
        self, connection: str, profile: dict[str, Any], name: str, value: str
    ) -> None:
        reference = self.settable(profile, name)
        checked_secret(value)
        if profile["transport"] == "http":
            header_value(value)
        binding = self.binding(connection, profile)
        await asyncio.to_thread(self.store.set, reference, binding, value)

    async def delete_credential(self, connection: str, profile: dict[str, Any], name: str) -> None:
        reference = self.settable(profile, name)
        binding = self.binding(connection, profile)
        await asyncio.to_thread(self.store.delete, reference, binding)

    async def signin(
        self,
        connection: str,
        profile: dict[str, Any],
        opener: Callable[[str], Awaitable[None]],
        secrets: set[str],
    ) -> None:
        """Only an explicit operator action supplies the browser/GUI opener."""
        require(self.oauth_profile(profile), "MCP connection does not use OAuth sign-in")
        await self.oauth.signin(profile, self.binding(connection, profile), opener, secrets)

    async def logout(
        self, connection: str, profile: dict[str, Any], secrets: set[str]
    ) -> dict[str, str]:
        require(self.oauth_profile(profile), "MCP connection does not use OAuth sign-in")
        revocation = await self.oauth.logout(profile, self.binding(connection, profile), secrets)
        return {"authentication": "required", "revocation": revocation}

    async def status(self, connection: str, profile: dict[str, Any]) -> dict[str, Any]:
        binding = self.binding(connection, profile)
        if self.oauth_profile(profile):
            try:
                state = await self.oauth.status(profile, binding)
            except CredentialError:
                state = "unavailable"
            return {"authentication": state, "credentials": {}}
        refs = references(profile)
        states = await asyncio.gather(
            *(asyncio.to_thread(self.store.status, ref, binding) for ref in refs.values())
        )
        masked = {name: state["state"] for name, state in zip(refs, states)}
        if not masked:
            summary = "none"
        elif "unavailable" in masked.values():
            summary = "unavailable"
        elif "not_set" in masked.values():
            summary = "required"
        else:
            summary = "configured"
        return {"authentication": summary, "credentials": masked}


def deployment_authentication(config: dict[str, Any], root: Path, http: SafeHTTP) -> Authentication:
    """Credentials are scoped to one installation folder and its configured operator."""
    location = os.path.normcase(str(Path(root).resolve()))
    namespace = "deploy-" + hashlib.sha256(location.encode("utf-8")).hexdigest()[:16]
    store = CredentialStore(namespace)
    grants = GrantStore(store, Path(root) / "runtime_state" / "mcp_auth.sqlite3")
    return Authentication(store, config["owner_id"], OAuthTokens(grants, http))
