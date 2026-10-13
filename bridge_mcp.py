"""Explicit read-only MCP calls; no provider configuration or server capabilities imported."""

import asyncio
import json
import re
from contextlib import suppress
from typing import Any, cast

import aiohttp

from bridge_http import CapabilityError, SafeHTTP

PROTOCOL = "2026-07-28"
LEGACY_PROTOCOL = "2025-11-25"
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


class MCPClient:
    def __init__(
        self,
        http: SafeHTTP,
        destination: str,
        authorization: str | None = None,
        *,
        protocol: str = PROTOCOL,
        secrets: set[str] | None = None,
    ) -> None:
        self.http, self.destination, self.authorization = http, destination, authorization
        if protocol not in (PROTOCOL, LEGACY_PROTOCOL):
            raise CapabilityError("Unsupported MCP protocol")
        self.protocol = protocol
        self.session: str | None = None
        self.secrets = set() if secrets is None else secrets

    def headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json, text/event-stream",
            "MCP-Protocol-Version": self.protocol,
        }
        if self.authorization:
            headers["Authorization"] = "Bearer " + self.authorization
        if self.session:
            headers["Mcp-Session-Id"] = self.session
        return headers

    async def rpc(
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
            text = await self.http.read(reply)
            try:
                if reply.content_type == "application/json":
                    result = response_result(json.loads(text), identity)
                    if result is None:
                        raise CapabilityError("Missing MCP response")
                    return result
                if reply.content_type != "text/event-stream":
                    raise CapabilityError("Unsupported MCP response type")
                result = None
                # Request-scoped SSE only. No resumption, GET sessions or server-initiated RPC.
                for event in re.split(r"\r?\n\r?\n", text):
                    lines = [
                        line[5:].lstrip(" ")
                        for line in event.splitlines()
                        if line.startswith("data:")
                    ]
                    if not lines:
                        continue
                    current = response_result(json.loads("\n".join(lines)), identity)
                    if current is not None:
                        if result is not None:
                            raise CapabilityError("Duplicate MCP response")
                        result = current
                if result is None:
                    raise CapabilityError("Missing MCP response")
                return result
            except (json.JSONDecodeError, RecursionError):
                raise CapabilityError("Invalid MCP response") from None

    async def call(self, name: str, arguments: dict[str, Any]) -> str:
        try:
            if self.protocol == LEGACY_PROTOCOL:
                result = await self.rpc(
                    "initialize",
                    {
                        "protocolVersion": self.protocol,
                        "capabilities": {},
                        "clientInfo": {"name": "botbridge", "version": "1.0.0"},
                    },
                    0,
                )
                if result.get("protocolVersion") != self.protocol:
                    raise CapabilityError("MCP protocol mismatch")
                await self.rpc("notifications/initialized", {}, None)
            return await self.tool_call(name, arguments)
        finally:
            if self.session:
                # Session cleanup is best effort and cannot mask the operation's result/error.
                with suppress(aiohttp.ClientError, OSError, asyncio.TimeoutError, CapabilityError):
                    async with asyncio.timeout(2):
                        async with self.http.open(
                            "DELETE", self.destination, headers=self.headers()
                        ):
                            pass
                self.session = None

    async def tool_call(self, name: str, arguments: dict[str, Any]) -> str:
        # Descriptions, annotations and server instructions cannot add tools or permissions.
        cursor, definition = None, None
        for page in range(3):
            result = await self.rpc("tools/list", {"cursor": cursor} if cursor else {}, page + 1)
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
        # Header-mirroring schema extensions need a separate reviewed implementation.
        # Fail closed rather than sending arguments with incomplete protocol headers.
        if '"x-mcp-header"' in json.dumps(definition.get("inputSchema", {})):
            raise CapabilityError("MCP header schema unsupported")
        result = await self.rpc("tools/call", {"name": name, "arguments": arguments}, 4)
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
