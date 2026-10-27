"""Owned, bounded local MCP subprocesses; no shell or ambient connector imports."""

import asyncio
from contextlib import suppress
import json
import os
from pathlib import Path
import signal
import sys
from typing import Any, cast

from bridge_http import CapabilityError, SafeHTTP
from bridge_mcp import MCPClient, PROTOCOL_2025, response_result
from scripts.console_windows import creation_flags

ROOT = Path(__file__).resolve().parent
MAX_MESSAGE = 524288
BASE_ENV = {"SYSTEMROOT", "WINDIR", "TEMP", "TMP", "LANG", "LC_ALL"}
WINDOWS = os.name == "nt"


def child_environment(profile: dict[str, Any], credentials: dict[str, str]) -> dict[str, str]:
    """Credentials were resolved from this profile's approved references only."""
    env = {k: v for k, v in os.environ.items() if k.upper() in BASE_ENV}
    env.update(profile["environment"])
    env.update(credentials)
    # Preserve only this explicit diagnostic switch and our own Node hiding preload.
    env["BOTBRIDGE_SHOW_CONSOLE"] = "1" if os.environ.get("BOTBRIDGE_SHOW_CONSOLE") == "1" else "0"
    env["NODE_OPTIONS"] = "--require=" + json.dumps(str(ROOT / "scripts/hidden_windows.cjs"))
    env["PYTHONUTF8"] = "1"
    return env


class StdioClient(MCPClient):
    def __init__(
        self, profile: dict[str, Any], credentials: dict[str, str], secrets: set[str]
    ) -> None:
        super().__init__(SafeHTTP(), "", protocol=PROTOCOL_2025, secrets=secrets)
        self.profile, self.credentials = profile, credentials
        self.process: asyncio.subprocess.Process | None = None
        self.stderr_task: asyncio.Task[None] | None = None

    async def drain_stderr(self, reader: asyncio.StreamReader) -> None:
        total = 0
        while chunk := await reader.read(4096):
            total += len(chunk)
            if total > 65536:
                raise CapabilityError("MCP stderr limit exceeded")

    def check_stderr(self) -> None:
        task = cast(asyncio.Task[None], self.stderr_task)
        if task.done():
            task.result()

    async def connect(self) -> None:
        env = child_environment(self.profile, self.credentials)
        self.process = await asyncio.create_subprocess_exec(
            sys.executable,
            "-I",
            str(ROOT / "scripts/mcp_host.py"),
            self.profile["command"],
            *self.profile["arguments"],
            cwd=self.profile["cwd"],
            env=env,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            limit=MAX_MESSAGE + 1,
            start_new_session=os.name != "nt",
            creationflags=creation_flags(env=env),
        )
        self.stderr_task = asyncio.create_task(
            self.drain_stderr(cast(asyncio.StreamReader, self.process.stderr))
        )
        await super().connect()

    async def rpc(
        self, method: str, params: dict[str, Any], identity: int | None
    ) -> dict[str, Any]:
        try:
            self.check_stderr()
            body: dict[str, Any] = {"jsonrpc": "2.0", "method": method, "params": params}
            if identity is not None:
                body["id"] = identity
            data = json.dumps(body, allow_nan=False).encode("utf-8")
            if len(data) > MAX_MESSAGE:
                raise CapabilityError("MCP request too large")
            process = cast(asyncio.subprocess.Process, self.process)
            writer = cast(asyncio.StreamWriter, process.stdin)
            writer.write(data + b"\n")
            await writer.drain()
            if identity is None:
                return {}
            total = 0
            while True:
                raw = await cast(asyncio.StreamReader, process.stdout).readline()
                total += len(raw)
                if total > MAX_MESSAGE or not raw.endswith(b"\n"):
                    raise CapabilityError("Invalid or oversized MCP stdio response")
                self.check_stderr()
                result = response_result(json.loads(raw.decode("utf-8")), identity)
                if result is not None:
                    return result
        except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as exc:
            if isinstance(exc, CapabilityError):
                raise
            raise CapabilityError("Invalid MCP stdio response") from None
        except (asyncio.CancelledError, asyncio.TimeoutError):
            if identity is not None and method != "initialize":
                self.cancelled_request = identity
            raise

    async def disconnect(self) -> None:
        process = self.process
        try:
            if process is not None:
                if self.cancelled_request is not None:
                    with suppress(OSError, CapabilityError, asyncio.TimeoutError):
                        async with asyncio.timeout(0.2):
                            await self.rpc(
                                "notifications/cancelled",
                                {"requestId": self.cancelled_request},
                                None,
                            )
        finally:
            try:
                if process is not None:
                    # A second cancellation cannot skip the actual synchronous kill.
                    with suppress(ProcessLookupError):
                        if WINDOWS:
                            if process.returncode is None:
                                process.kill()
                        else:
                            getattr(os, "killpg")(process.pid, getattr(signal, "SIGKILL"))
                    async with asyncio.timeout(1):
                        await process.wait()
            finally:
                if self.stderr_task is not None:
                    self.stderr_task.cancel()
                    with suppress(asyncio.CancelledError, CapabilityError):
                        await self.stderr_task
                if process is None or process.returncode is not None:
                    self.process = None
                self.stderr_task = None
                self.cancelled_request = None
