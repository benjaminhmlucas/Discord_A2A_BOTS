"""Explicit public-client OAuth flow: PKCE, single-use loopback callback, bounded tokens."""

import asyncio
import base64
from collections.abc import AsyncIterator, Awaitable, Callable
from contextlib import asynccontextmanager
import hashlib
import secrets
import time
from typing import Any

from aiohttp import web
from yarl import URL

from bridge_auth_policy import AuthenticationError, header_value, require
from bridge_credentials import checked_secret
from bridge_http import SafeHTTP
from bridge_oauth_discovery import Discovery, object_json


class GrantRejected(AuthenticationError):
    """The authorization server refused the code or refresh token."""


def pkce() -> tuple[str, str]:
    verifier = secrets.token_urlsafe(32)
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode("ascii")).digest())
    return verifier, challenge.rstrip(b"=").decode("ascii")


class Callback:
    def __init__(self, issuer: str, require_iss: bool) -> None:
        self.issuer, self.require_iss = issuer, require_iss
        self.state = secrets.token_urlsafe(32)
        self.used = False
        self.result: asyncio.Future[str] = asyncio.get_running_loop().create_future()
        self.redirect = ""

    async def receive(self, request: web.Request) -> web.Response:
        # Do not let a hostile web page submit a callback through CORS/DNS rebinding.
        expected_host = URL(self.redirect).raw_authority
        if (
            request.headers.get("Host") != expected_host
            or "Origin" in request.headers
            or len(request.query_string) > 4096
        ):
            return web.Response(status=400, text="Invalid sign-in callback")
        if self.used or self.result.done():
            return web.Response(status=410, text="Sign-in callback already used")
        query = request.query
        if (
            any(len(query.getall(k)) != 1 for k in query)
            or set(query) - {"code", "state", "iss", "error", "error_description", "error_uri"}
            or not isinstance(query.get("state"), str)
            or not query["state"].isascii()
            or not secrets.compare_digest(query["state"], self.state)
        ):
            return web.Response(status=400, text="Invalid sign-in callback")
        # A matching state is consumed even when consent/issuer validation fails.
        self.used = True
        issuer = query.get("iss")
        if (
            (issuer is not None and issuer != self.issuer)
            or (self.require_iss and issuer is None)
            or ("error" in query)
            or not query.get("code")
            or len(query["code"]) > 2048
            or any(ord(c) < 33 or ord(c) > 126 for c in query["code"])
        ):
            self.result.set_exception(AuthenticationError("OAuth sign-in rejected"))
            return web.Response(status=400, text="Sign-in was not completed")
        self.result.set_result(query["code"])
        return web.Response(
            text="Sign-in received. You can close this window.",
            headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
        )

    @asynccontextmanager
    async def listen(self, port: int) -> AsyncIterator["Callback"]:
        app = web.Application(client_max_size=4096)
        app.router.add_get("/oauth/callback", self.receive, allow_head=False)
        runner = web.AppRunner(app, access_log=None, shutdown_timeout=1, max_line_size=8190)
        try:
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", port, reuse_address=False)
            await site.start()
            self.redirect = "http://127.0.0.1:" + str(runner.addresses[0][1]) + "/oauth/callback"
            yield self
        finally:
            # Retrieve a rejected callback even if the caller is cancelled before wait().
            if self.result.done() and not self.result.cancelled():
                self.result.exception()
            else:
                self.result.cancel()
            await runner.cleanup()

    async def wait(self, seconds: float) -> str:
        async with asyncio.timeout(seconds):
            return await asyncio.shield(self.result)


class OAuthFlow:
    def __init__(self, profile: dict[str, Any], resource_http: SafeHTTP) -> None:
        self.discovery = Discovery(profile, resource_http)
        self.auth: dict[str, Any] = profile["authentication"]

    def grant(
        self, response: dict[str, Any], previous_refresh: str | None = None
    ) -> dict[str, Any]:
        require(
            isinstance(response.get("token_type"), str)
            and response["token_type"].lower() == "bearer",
            "OAuth bearer token required",
        )
        token = checked_secret(header_value(response.get("access_token")))
        refresh = response.get("refresh_token", previous_refresh)
        if refresh is not None:
            checked_secret(header_value(refresh))
        expiry = response.get("expires_in")
        if not isinstance(expiry, int) or isinstance(expiry, bool) or not 0 < expiry <= 31536000:
            raise AuthenticationError("OAuth token expiry required")
        scope = response.get("scope", " ".join(self.auth["scopes"]))
        require(isinstance(scope, str), "Invalid OAuth token scope")
        # Never silently retain a grant with different permissions from the approved profile.
        require(set(scope.split()) == set(self.auth["scopes"]), "OAuth token scope mismatch")
        if "resource" in response:
            require(
                response["resource"] == self.discovery.resource, "OAuth token resource mismatch"
            )
        return {
            "access_token": token,
            "refresh_token": refresh,
            "expires_at": int(time.time()) + expiry,
            "issuer": self.auth["issuer"],
            "resource": self.discovery.resource,
            "scopes": self.auth["scopes"],
        }

    async def exchange(
        self, endpoint: str, fields: dict[str, str], previous_refresh: str | None = None
    ) -> dict[str, Any]:
        require(
            self.auth["client_id"] is not None, "OAuth requires a pre-registered public client_id"
        )
        fields = {
            **fields,
            "client_id": self.auth["client_id"],
            "resource": self.discovery.resource,
        }
        async with self.discovery.http.open(
            "POST",
            self.discovery.destination(endpoint),
            headers={"Accept": "application/json"},
            form=fields,
        ) as response:
            if response.status in (400, 401):
                # RFC 6749 section 5.2: an invalid/expired/revoked grant needs a new sign-in.
                raise GrantRejected("OAuth grant rejected; sign in again")
            require(response.status == 200, "OAuth token service unavailable; retry later")
            require(response.content_type == "application/json", "Invalid OAuth token response")
            return self.grant(
                object_json(await self.discovery.http.read(response)), previous_refresh
            )

    async def signin(
        self, open_authorization: Callable[[str], Awaitable[None]], *, seconds: float = 180
    ) -> dict[str, Any]:
        """Only an explicit operator command may supply the browser/GUI opener."""
        require(
            self.auth["client_id"] is not None, "OAuth requires a pre-registered public client_id"
        )
        async with asyncio.timeout(seconds):
            metadata = await self.discovery.discover()
            callback = Callback(self.auth["issuer"], metadata["require_iss"])
            verifier, challenge = pkce()
            async with callback.listen(self.auth["callback_port"]):
                url = URL(metadata["authorization_endpoint"]).with_query(
                    {
                        "response_type": "code",
                        "client_id": self.auth["client_id"],
                        "redirect_uri": callback.redirect,
                        "state": callback.state,
                        "code_challenge": challenge,
                        "code_challenge_method": "S256",
                        "scope": " ".join(self.auth["scopes"]),
                        "resource": self.discovery.resource,
                    }
                )
                await open_authorization(str(url))
                code = await callback.wait(seconds)
                return await self.exchange(
                    metadata["token_endpoint"],
                    {
                        "grant_type": "authorization_code",
                        "code": code,
                        "redirect_uri": callback.redirect,
                        "code_verifier": verifier,
                    },
                )

    def checked_binding(self, grant: object) -> None:
        require(
            isinstance(grant, dict)
            and grant.get("issuer") == self.auth["issuer"]
            and grant.get("resource") == self.discovery.resource
            and grant.get("scopes") == self.auth["scopes"],
            "OAuth stored grant binding mismatch",
        )

    async def refresh(self, grant: dict[str, Any]) -> dict[str, Any]:
        self.checked_binding(grant)
        refresh = checked_secret(header_value(grant.get("refresh_token")))
        metadata = await self.discovery.discover()
        return await self.exchange(
            metadata["token_endpoint"],
            {"grant_type": "refresh_token", "refresh_token": refresh},
            refresh,
        )

    async def revoke(self, grant: dict[str, Any]) -> None:
        self.checked_binding(grant)
        metadata = await self.discovery.discover()
        endpoint = metadata.get("revocation_endpoint")
        if endpoint is None or self.auth["client_id"] is None:
            raise AuthenticationError("OAuth remote revocation unsupported; revoke at the provider")
        token = checked_secret(
            header_value(grant.get("refresh_token") or grant.get("access_token"))
        )
        async with self.discovery.http.open(
            "POST", endpoint, form={"token": token, "client_id": self.auth["client_id"]}
        ) as response:
            require(
                response.status == 200, "OAuth remote revocation failed; revoke at the provider"
            )
