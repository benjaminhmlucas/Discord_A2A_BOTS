"""Bounded provider calls; authentication never enters URLs or prompts."""

import asyncio
import json
import os
import tempfile
from pathlib import Path

import aiohttp

from bridge_contracts import ProviderError
from bridge_settings import ROOT, local_path, local_settings, config_path
import shutil

_settings = local_settings()
_node = Path(shutil.which(_settings["node_executable"]) or _settings["node_executable"])
NODE = str(_node if _node.is_absolute() else ROOT / _node)
CODEX = str(local_path("codex_cli"))
CLAUDE = str(local_path("claude_cli"))
MEMORY = str(local_path("memory_dir"))


def secret(name):
    value = os.environ.get(name)
    if isinstance(value, str) and value.strip():
        return value
    if os.name == "nt":
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
                value = winreg.QueryValueEx(key, name)[0]
                if isinstance(value, str) and value.strip():
                    return value
        except OSError:
            pass
    raise RuntimeError(f"Missing credential: {name}")


def child_env():
    # Codex auth uses its own auth store. Bot/provider/webhook secrets are not inherited.
    allow = {
        "SYSTEMROOT",
        "WINDIR",
        "PATH",
        "PATHEXT",
        "TEMP",
        "TMP",
        "USERPROFILE",
        "APPDATA",
        "LOCALAPPDATA",
        "PROGRAMDATA",
        "COMSPEC",
        "HOMEDRIVE",
        "HOMEPATH",
        "CODEX_HOME",
        "HTTP_PROXY",
        "HTTPS_PROXY",
        "NO_PROXY",
        "SSL_CERT_FILE",
        "SSL_CERT_DIR",
        "NODE_EXTRA_CA_CERTS",
    }
    return {k: v for k, v in os.environ.items() if k.upper() in allow}


async def kill_tree(proc):
    if proc.returncode is not None:
        return
    if os.name == "nt":
        killer = await asyncio.create_subprocess_exec(
            "taskkill",
            "/PID",
            str(proc.pid),
            "/T",
            "/F",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(killer.wait(), 10)
    else:
        proc.kill()
    await asyncio.wait_for(proc.wait(), 10)


async def codex(prompt, work=False):
    config = json.loads(config_path(ROOT).read_text(encoding="utf-8"))
    runtime = ROOT / "chat_runtime"
    runtime.mkdir(exist_ok=True)
    # No user config, plugins, MCP servers, shared memory instructions, or default tools in public chat.
    cmd = [
        NODE,
        CODEX,
        "exec",
        "--strict-config",
        "--ignore-user-config",
        "--ignore-rules",
        "--ephemeral",
        "--skip-git-repo-check",
        "--sandbox",
        "workspace-write" if work else "read-only",
        "-C",
        MEMORY if work else str(runtime),
        "-c",
        'approval_policy="never"',
        "-c",
        'web_search="disabled"',
        "-c",
        "features.apps=false",
        "-c",
        "features.plugins=false",
        "-c",
        "features.multi_agent=false",
        "-c",
        "features.browser_use=false",
        "-c",
        "features.computer_use=false",
        "-c",
        "features.image_generation=false",
    ]
    if config.get("codex_model"):
        cmd += ["-m", config["codex_model"]]
    cmd += ["-c", "model_reasoning_effort=" + json.dumps(config["codex_reasoning_effort"])]
    if not work:
        cmd += [
            "-c",
            "features.shell_tool=false",
            "-c",
            "features.unified_exec=false",
            "-c",
            "features.tool_search=false",
            "-c",
            "project_doc_max_bytes=0",
            "-c",
            'developer_instructions="Reply as a text-only '
            'Discord assistant. Never read local files, invoke tools, or alter shared memory."',
        ]
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as f:
        output = Path(f.name)
    cmd += ["-o", str(output), "-"]
    proc = None
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
            cwd=MEMORY if work else runtime,
            env=child_env(),
        )
        await asyncio.wait_for(proc.communicate(prompt.encode("utf-8")), 225)
        if proc.returncode:
            raise ProviderError(f"CodexExit{proc.returncode}")
        reply = output.read_text(encoding="utf-8").strip()
        if not reply:
            raise ProviderError("EmptyCodexResponse")
        return reply
    finally:
        if proc and proc.returncode is None:
            await asyncio.shield(kill_tree(proc))
        output.unlink(missing_ok=True)


class Gemini:
    def __init__(self, model):
        self.model = model
        self.key = secret("GEMINI_API_KEY")

    async def __call__(self, prompt, work=False):
        if work:
            raise ValueError("Gemini bridge does not execute local work")
        url = (
            f"https://generativelanguage.googleapis.com/v1beta/models/{self.model}:generateContent"
        )
        payload = {"contents": [{"role": "user", "parts": [{"text": prompt}]}]}
        timeout = aiohttp.ClientTimeout(total=45, connect=10)
        async with asyncio.timeout(150):
            async with aiohttp.ClientSession(timeout=timeout) as session:
                attempt = 0
                while True:
                    try:
                        async with session.post(
                            url, headers={"x-goog-api-key": self.key}, json=payload
                        ) as resp:
                            if resp.status in (429, 500, 502, 503, 504) and attempt < 2:
                                await resp.read()
                                await asyncio.sleep(2**attempt)
                                attempt += 1
                                continue
                            if resp.status != 200:
                                raise ProviderError(f"GeminiHTTP{resp.status}")
                            result = await resp.json()
                            candidates = result.get("candidates") or []
                            parts = (
                                candidates[0].get("content", {}).get("parts", [])
                                if candidates
                                else []
                            )
                            text = "\n".join(
                                p.get("text", "") for p in parts if not p.get("thought")
                            ).strip()
                            if not text:
                                raise ProviderError("GeminiEmptyContent")
                            return text
                    except (aiohttp.ClientError, asyncio.TimeoutError):
                        if attempt == 2:
                            raise
                        await asyncio.sleep(2**attempt)
                        attempt += 1


async def claude(prompt, work=False):
    if work:
        raise ValueError("Claude bridge does not execute local work")
    # Public replies use subscription OAuth, without inherited tools, hooks or MCP servers.
    args = [
        "--tools",
        "",
        "--permission-mode",
        "dontAsk",
        "--setting-sources",
        "",
        "--strict-mcp-config",
        "--mcp-config",
        '{"mcpServers":{}}',
        "--disable-slash-commands",
        "--no-session-persistence",
        "--no-chrome",
        "--system-prompt",
        "Reply as ClaudeBot, a text-only Discord assistant. "
        "Use only the supplied conversation and context. Never invoke tools or read local files.",
    ]
    env = child_env()
    env["CLAUDE_CODE_OAUTH_TOKEN"] = secret("CLAUDE_CODE_OAUTH_TOKEN")
    proc = await asyncio.create_subprocess_exec(
        NODE,
        CLAUDE,
        "-p",
        "--output-format",
        "json",
        *args,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
        cwd=ROOT / "chat_runtime",
        env=env,
    )
    try:
        stdout, _ = await asyncio.wait_for(proc.communicate(prompt.encode("utf-8")), 120)
        if proc.returncode:
            raise ProviderError(f"ClaudeExit{proc.returncode}")
        result = json.loads(stdout.decode("utf-8"))
        if result.get("is_error"):
            raise ProviderError("ClaudeBackendError")
        reply = result.get("result", "").strip()
        if not reply:
            raise ProviderError("EmptyClaudeResponse")
        return reply
    finally:
        if proc.returncode is None:
            await asyncio.shield(kill_tree(proc))
