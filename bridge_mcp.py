"""Explicit read-only MCP calls; no provider configuration or server capabilities imported."""

import asyncio
import json
import secrets
from contextlib import suppress
from collections.abc import Mapping
from typing import Any, cast

import aiohttp

from bridge_http import CapabilityError, SafeHTTP
from bridge_mcp_schema import validate

PROTOCOL = "2026-07-28"
PROTOCOL_2025 = "2025-11-25"
META = {
    "io.modelcontextprotocol/protocolVersion": PROTOCOL,
    "io.modelcontextprotocol/clientInfo": {"name": "botbridge", "version": "1.0.0"},
    "io.modelcontextprotocol/clientCapabilities": {},
}


def response_result(value: object, identity: int) -> dict[str, Any] | None:
    if not isinstance(value, dict) or value.get("jsonrpc") != "2.0":
        raise CapabilityError("Invalid MCP response")
    if "method" in value:
        if "id" in value:
            raise CapabilityError("MCP server requests denied")
        return None  # Bounded notifications are data, never instructions.
    if (
        type(value.get("id")) is not int
        or value["id"] != identity
        or "error" in value
        or not isinstance(value.get("result"), dict)
    ):
        raise CapabilityError("MCP request failed")
    return cast(dict[str, Any], value["result"])


class AuthorizationRejected(CapabilityError):
    """The server refused the presented credential (HTTP 401)."""

    def __init__(self, message: str, *, authorization: str | None = None) -> None:
        super().__init__(message)
        self.authorization = authorization  # Never included in the diagnostic/args.


class MCPClient:
    def __init__(
        self,
        http: SafeHTTP,
        destination: str,
        authentication: Mapping[str, str] | None = None,
        *,
        protocol: str = PROTOCOL,
        secrets: set[str] | None = None,
    ) -> None:
        self.http, self.destination = http, destination
        # Pre-validated authentication headers from the shared authentication API.
        self.authentication = dict(authentication or {})
        if protocol not in (PROTOCOL, PROTOCOL_2025):
            raise CapabilityError("Unsupported MCP protocol")
        self.protocol = protocol
        self.session: str | None = None
        self.cancelled_request: int | None = None
        self.secrets = set() if secrets is None else secrets

    def headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": self.protocol,
        }
        headers.update(self.authentication)
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        return headers

    async def rpc(
        self, method: str, params: dict[str, Any], identity: int | None
    ) -> dict[str, Any]:
        try:
            return await self.exchange(method, params, identity)
        except (asyncio.CancelledError, asyncio.TimeoutError):
            if self.protocol == PROTOCOL_2025 and identity is not None and method != "initialize":
                self.cancelled_request = identity
            raise

    async def exchange(
        self, method: str, params: dict[str, Any], identity: int | None
    ) -> dict[str, Any]:
        headers = self.headers()
        headers["Mcp-Method"] = method
        if method == "tools/call":
            headers["Mcp-Name"] = params["name"]
        body: dict[str, Any] = {
            "jsonrpc": "2.0",
            "method": method,
            "params": {**params, "_meta": META} if self.protocol == PROTOCOL else params,
        }
        if identity is not None:
            body["id"] = identity
        async with self.http.open("POST", self.destination, headers=headers, body=body) as reply:
            # Never follow a credential-bearing redirect, even to another approved origin.
            if reply.status == 401:
                raise AuthorizationRejected(
                    "MCP server rejected the credential; rotate it or sign in again",
                    authorization=headers.get("Authorization"),
                )
            if identity is None:
                if reply.status != 202:
                    raise CapabilityError("MCP notification failed")
                return {}
            if reply.status != 200:
                raise CapabilityError("MCP request failed")
            if method == "initialize":
                session = reply.headers.get("Mcp-Session-Id")
                if session:
                    self.secrets.add(session)
                    if len(session) > 256 or any(ord(c) < 33 or ord(c) > 126 for c in session):
                        raise CapabilityError("Invalid MCP session")
                    self.session = session
            try:
                if reply.content_type == "application/json":
                    text = await self.http.read(reply)
                    result = response_result(json.loads(text), identity)
                    if result is None:
                        raise CapabilityError("Missing MCP response")
                    return result
                if reply.content_type != "text/event-stream":
                    raise CapabilityError("Unsupported MCP response type")
                return await self.sse_result(reply, identity)
            except (json.JSONDecodeError, RecursionError):
                raise CapabilityError("Invalid MCP response") from None

    async def sse_result(self, reply: aiohttp.ClientResponse, identity: int) -> dict[str, Any]:
        # Incremental, bounded request-scoped SSE; no resumption or server-initiated RPC.
        data: list[str] = []
        async for line in self.http.lines(reply):
            if line.startswith("data:"):
                value = line[5:]
                data.append(value[1:] if value.startswith(" ") else value)
            elif line == "":
                text = "\n".join(data)
                data.clear()
                if text:
                    result = response_result(json.loads(text), identity)
                    if result is not None:
                        return result
        # An event without its terminating blank line is not dispatched (SSE semantics).
        raise CapabilityError("Missing MCP response")

    async def connect(self) -> None:
        if self.protocol == PROTOCOL_2025:
            result = await self.rpc(
                "initialize",
                {
                    "protocolVersion": self.protocol,
                    "capabilities": {},
                    "clientInfo": {"name": "botbridge", "version": "1.0.0"},
                },
                secrets.randbits(53),
            )
            if result.get("protocolVersion") != self.protocol:
                raise CapabilityError("MCP protocol mismatch")
            await self.rpc("notifications/initialized", {}, None)

    async def disconnect(self) -> None:
        try:
            # One cleanup deadline covers cancellation signalling and optional DELETE.
            with suppress(aiohttp.ClientError, OSError, asyncio.TimeoutError, CapabilityError):
                async with asyncio.timeout(2):
                    if self.cancelled_request is not None:
                        with suppress(aiohttp.ClientError, OSError, CapabilityError):
                            await self.rpc(
                                "notifications/cancelled",
                                {"requestId": self.cancelled_request},
                                None,
                            )
                    if self.session:
                        async with self.http.open(
                            "DELETE", self.destination, headers=self.headers()
                        ):
                            pass
        finally:
            self.session = None
            self.cancelled_request = None

    async def discover(self) -> list[dict[str, Any]]:
        tools: list[dict[str, Any]] = []
        cursor = None
        for _ in range(3):
            result = await self.rpc(
                "tools/list", {"cursor": cursor} if cursor else {}, secrets.randbits(53)
            )
            page = result.get("tools")
            if not isinstance(page, list) or any(not isinstance(t, dict) for t in page):
                raise CapabilityError("Invalid MCP tool list")
            tools.extend(page)
            names = [t.get("name") for t in tools]
            if len(names) > 256 or any(
                not isinstance(n, str) or not n or len(n) > 128 for n in names
            ):
                raise CapabilityError("Invalid MCP tool names")
            if len(set(names)) != len(names):
                raise CapabilityError("Ambiguous MCP tool")
            cursor = result.get("nextCursor")
            if cursor is None:
                return tools
            if not isinstance(cursor, str) or not cursor or len(cursor) > 2048:
                raise CapabilityError("Invalid MCP discovery cursor")
        raise CapabilityError("MCP discovery limit reached")

    async def tool_call(self, name: str, arguments: dict[str, Any]) -> str:
        # Descriptions, annotations and server instructions cannot add tools or permissions.
        cursor, definition = None, None
        for _ in range(3):
            result = await self.rpc(
                "tools/list", {"cursor": cursor} if cursor else {}, secrets.randbits(53)
            )
            tools = result.get("tools")
            if not isinstance(tools, list) or any(not isinstance(t, dict) for t in tools):
                raise CapabilityError("Invalid MCP tool list")
            matches = [tool for tool in tools if tool.get("name") == name]
            if len(matches) > 1:
                raise CapabilityError("Ambiguous MCP tool")
            if matches:
                definition = matches[0]
                break
            cursor = result.get("nextCursor")
            if not isinstance(cursor, str) or not cursor or len(cursor) > 2048:
                raise CapabilityError("Configured MCP tool unavailable")
        if definition is None:
            raise CapabilityError("MCP discovery limit reached")
        # Server hints may veto an operator-approved tool, never grant permissions.
        annotations = definition.get("annotations", {})
        if not isinstance(annotations, dict) or any(
            key in annotations and type(annotations[key]) is not bool
            for key in ("readOnlyHint", "destructiveHint")
        ):
            raise CapabilityError("Invalid MCP tool annotations")
        if annotations.get("readOnlyHint") is False or annotations.get("destructiveHint") is True:
            raise CapabilityError("MCP tool declares write or destructive behavior")
        # Header-mirroring schema extensions need a separate reviewed implementation.
        # Fail closed rather than sending arguments with incomplete protocol headers.
        if '"x-mcp-header"' in json.dumps(definition.get("inputSchema", {})):
            raise CapabilityError("MCP header schema unsupported")
        validate(arguments, definition.get("inputSchema", {}))
        result = await self.rpc(
            "tools/call", {"name": name, "arguments": arguments}, secrets.randbits(53)
        )
        if result.get("isError") or "inputRequests" in result:
            raise CapabilityError("MCP tool failed")
        content = result.get("content")
        if not isinstance(content, list) or not content:
            raise CapabilityError("MCP tool returned no text")
        if any(
            not isinstance(c, dict) or c.get("type") != "text" or not isinstance(c.get("text"), str)
            for c in content
        ):
            raise CapabilityError("Unsupported MCP tool content")
        return "\n".join(c["text"] for c in content)
