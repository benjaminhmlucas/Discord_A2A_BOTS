"""Operator-owned MCP authentication policy; one reference and header-validation path."""

import re
from typing import Any

from bridge_credentials import checked_reference
from bridge_http import CapabilityError, checked_url

HEADER = re.compile(r"(?:X-[A-Za-z0-9-]{1,48}|Api-Key)\Z", re.I)
SCOPE = re.compile(r"[\x21\x23-\x5b\x5d-\x7e]{1,128}\Z")


class AuthenticationError(CapabilityError):
    """Static, credential-free messages only."""


def require(condition: object, message: str = "Invalid MCP authentication configuration") -> None:
    if not condition:
        raise AuthenticationError(message)


def header_value(value: object) -> str:
    require(
        isinstance(value, str) and bool(value) and all(33 <= ord(c) <= 126 for c in value),
        "Invalid MCP credential header",
    )
    return str(value)


def checked_authentication(auth: Any) -> None:
    require(isinstance(auth, dict))
    kind = auth.get("type")
    if kind == "none":
        require(set(auth) == {"type"})
    elif kind == "bearer":
        require(set(auth) == {"type", "credential"})
        checked_reference(auth["credential"])
    elif kind == "headers":
        require(set(auth) == {"type", "credentials"})
        refs = auth["credentials"]
        require(isinstance(refs, dict) and 1 <= len(refs) <= 8)
        require(
            all(
                isinstance(k, str)
                and HEADER.fullmatch(k)
                and not k.lower().startswith(("x-forwarded-", "x-real-", "x-http-method-"))
                for k in refs
            )
        )
        require(len({k.lower() for k in refs}) == len(refs))
        for reference in refs.values():
            checked_reference(reference)
    else:
        require(kind == "oauth")
        require(
            set(auth)
            == {
                "type",
                "credential",
                "issuer",
                "client_id",
                "scopes",
                "allowed_origins",
                "internal_origins",
                "callback_port",
            }
        )
        checked_reference(auth["credential"])
        require(
            auth["credential"]["source"] == "native",
            "Interactive OAuth requires native credential storage; environment references are externally managed",
        )
        require(
            auth["client_id"] is None
            or isinstance(auth["client_id"], str)
            and 0 < len(auth["client_id"]) <= 1024
            and all(33 <= ord(c) <= 126 for c in auth["client_id"])
        )
        require(type(auth["callback_port"]) is int and 0 <= auth["callback_port"] <= 65535)
        scopes = auth["scopes"]
        require(
            isinstance(scopes, list)
            and len(scopes) <= 16
            and all(isinstance(s, str) and SCOPE.fullmatch(s) for s in scopes)
        )
        require(len(set(scopes)) == len(scopes))
        allowed, internal = auth["allowed_origins"], auth["internal_origins"]
        require(isinstance(allowed, list) and isinstance(internal, list))
        for origins in (allowed, internal):
            require(len(origins) <= 8)
            for origin in origins:
                url = checked_url(origin, internal)
                require(str(url.origin()) == origin)
            require(len(set(origins)) == len(origins))
        require(bool(allowed) and set(internal) <= set(allowed))
        issuer = checked_url(auth["issuer"], internal)
        require(not issuer.query_string and str(issuer.origin()) in allowed)


def references(profile: dict[str, Any]) -> dict[str, dict[str, str]]:
    """Every credential reference of one validated profile, keyed by reference name."""
    if profile["transport"] == "stdio":
        refs = list(profile["credentials"].values())
    else:
        auth = profile["authentication"]
        checked_authentication(auth)
        refs = {
            "none": [],
            "headers": list(auth.get("credentials", {}).values()),
        }.get(auth["type"], [auth.get("credential")])
    result: dict[str, dict[str, str]] = {}
    for reference in refs:
        checked_reference(reference)
        # One name means one stored value; two slots sharing it would be ambiguous.
        require(reference["name"] not in result, "Duplicate MCP credential reference")
        result[reference["name"]] = reference
    return result
