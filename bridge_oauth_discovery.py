"""Bounded MCP OAuth discovery. Metadata never grants network or scope permission."""

from collections.abc import Iterable
import json
import re
from typing import Any, NoReturn
from urllib.request import parse_http_list

from bridge_auth_policy import AuthenticationError, checked_authentication, require
from bridge_http import SafeHTTP, checked_url

PARAMETER = re.compile(
    r'([a-zA-Z_][a-zA-Z_0-9-]*)=(?:"((?:[^"\\\x00-\x1f]|\\[\x20-\x7e])*)"|([\x21\x23-\x2b\x2d-\x3b\x3d\x3f-\x5b\x5d-\x7e]+))\Z'
)


def challenge(headers: Iterable[str]) -> dict[str, str]:
    """Select one Bearer challenge, rejecting ambiguous/duplicate parameters."""
    result, active, seen = {}, False, False
    for header in headers:
        require(isinstance(header, str) and len(header) <= 8192, "Invalid OAuth challenge")
        require(all(32 <= ord(c) <= 126 for c in header), "Invalid OAuth challenge")
        for part in parse_http_list(header):
            scheme = re.match(r"^([a-zA-Z][a-zA-Z0-9_-]*)\s+", part)
            if scheme:
                active = scheme[1].lower() == "bearer"
                part = part[scheme.end() :]
                if active:
                    require(not seen, "Ambiguous OAuth challenge")
                    seen = True
            elif part.lower() == "bearer":
                require(not seen, "Ambiguous OAuth challenge")
                seen, active = True, True
                continue
            if not active:
                continue
            match = PARAMETER.fullmatch(part)
            if match is None:
                raise AuthenticationError("Invalid OAuth challenge")
            name = match[1].lower()
            require(name not in result, "Ambiguous OAuth challenge")
            value = match[2] if match[2] is not None else match[3]
            result[name] = re.sub(r"\\(.)", r"\1", value)
    return result


def object_json(text: str) -> dict[str, Any]:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in items:
            require(key not in result, "Ambiguous OAuth response")
            result[key] = value
        return result

    def constant(_: str) -> NoReturn:
        raise AuthenticationError("Invalid OAuth response")

    try:
        value = json.loads(text, object_pairs_hook=pairs, parse_constant=constant)
    except (ValueError, RecursionError):
        raise AuthenticationError("Invalid OAuth response") from None
    if not isinstance(value, dict):
        raise AuthenticationError("Invalid OAuth response")
    return value


def string_list(value: Any) -> list[str]:
    require(
        isinstance(value, list)
        and len(value) <= 128
        and all(isinstance(v, str) and 0 < len(v) <= 2048 for v in value),
        "Invalid OAuth metadata",
    )
    require(len(set(value)) == len(value), "Invalid OAuth metadata")
    return list(value)


class Discovery:
    def __init__(self, profile: dict[str, Any], resource_http: SafeHTTP) -> None:
        self.profile, self.auth = profile, profile["authentication"]
        checked_authentication(self.auth)
        require(self.auth["type"] == "oauth")
        self.resource = str(checked_url(profile["endpoint"], resource_http.internal_origins))
        self.origin = str(checked_url(self.resource, resource_http.internal_origins).origin())
        self.resource_http = resource_http
        self.http = SafeHTTP(
            internal_origins=self.auth["internal_origins"],
            max_bytes=min(65536, resource_http.max_bytes),
            seconds=resource_http.seconds,
        )

    def destination(self, value: object) -> str:
        url = checked_url(value, self.http.internal_origins)
        require(str(url.origin()) in self.auth["allowed_origins"], "OAuth destination denied")
        require(not url.query_string, "OAuth endpoint query denied")
        return str(url)

    async def document(self, http: SafeHTTP, url: str) -> dict[str, Any] | None:
        async with http.open("GET", url, headers={"Accept": "application/json"}) as response:
            if response.status in (404, 405):
                return None
            require(response.status == 200, "OAuth metadata unavailable")
            require(response.content_type == "application/json", "Invalid OAuth metadata")
            return object_json(await http.read(response))

    async def discover(self) -> dict[str, Any]:
        async with self.resource_http.open("GET", self.resource) as response:
            require(response.status in (200, 401, 403, 405), "OAuth resource unavailable")
            values = challenge(response.headers.getall("WWW-Authenticate", []))
        requested = values.get("scope")
        if requested is not None:
            require(
                bool(requested.split()) and set(requested.split()) <= set(self.auth["scopes"]),
                "OAuth scope requires operator approval",
            )
        resource_url = checked_url(self.resource, self.resource_http.internal_origins)
        advertised = values.get("resource_metadata")
        if advertised is not None:
            metadata_url = checked_url(advertised, self.resource_http.internal_origins)
            require(
                str(metadata_url.origin()) == self.origin, "OAuth resource metadata origin denied"
            )
            candidates = [str(metadata_url)]
        else:
            path = resource_url.raw_path.rstrip("/")
            query = "?" + resource_url.raw_query_string if resource_url.raw_query_string else ""
            candidates = list(
                dict.fromkeys(
                    [
                        self.origin + "/.well-known/oauth-protected-resource" + path + query,
                        self.origin + "/.well-known/oauth-protected-resource",
                    ]
                )
            )
        resource = None
        for url in candidates:
            resource = await self.document(self.resource_http, url)
            if resource is not None:
                break
        if resource is None:
            raise AuthenticationError("OAuth resource metadata unavailable")
        require(resource.get("resource") == self.resource, "OAuth resource mismatch")
        require(
            self.auth["issuer"] in string_list(resource.get("authorization_servers")),
            "OAuth issuer mismatch",
        )
        if "scopes_supported" in resource:
            string_list(resource["scopes_supported"])
        issuer = checked_url(self.auth["issuer"], self.http.internal_origins)
        origin, path = str(issuer.origin()), issuer.raw_path.rstrip("/")
        # RFC 8414 insertion, OIDC insertion, then OIDC appending; deduplicate roots.
        paths = [
            origin + "/.well-known/oauth-authorization-server" + path,
            origin + "/.well-known/openid-configuration" + path,
            origin + path + "/.well-known/openid-configuration",
        ]
        server = None
        for url in dict.fromkeys(paths):
            server = await self.document(self.http, self.destination(url))
            if server is not None:
                break
        if server is None:
            raise AuthenticationError("OAuth authorization metadata unavailable")
        require(server.get("issuer") == self.auth["issuer"], "OAuth issuer mismatch")
        require(
            "S256" in string_list(server.get("code_challenge_methods_supported")),
            "OAuth PKCE S256 required",
        )
        require(
            "code" in string_list(server.get("response_types_supported")),
            "OAuth authorization code required",
        )
        require(
            "none"
            in string_list(
                server.get("token_endpoint_auth_methods_supported", ["client_secret_basic"])
            ),
            "OAuth public client unsupported",
        )
        if "grant_types_supported" in server:
            require(
                "authorization_code" in string_list(server["grant_types_supported"]),
                "OAuth authorization code required",
            )
        if "scopes_supported" in server:
            require(
                set(self.auth["scopes"]) <= set(string_list(server["scopes_supported"])),
                "OAuth configured scope unsupported",
            )
        result: dict[str, Any] = {
            "authorization_endpoint": self.destination(server.get("authorization_endpoint")),
            "token_endpoint": self.destination(server.get("token_endpoint")),
        }
        if "revocation_endpoint" in server:
            result["revocation_endpoint"] = self.destination(server["revocation_endpoint"])
        require(
            type(server.get("authorization_response_iss_parameter_supported", False)) is bool,
            "Invalid OAuth metadata",
        )
        result["require_iss"] = server.get("authorization_response_iss_parameter_supported", False)
        return result
