import asyncio
import json
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import bridge_providers as providers


def test_secret_sources_and_missing():
    with patch.object(
        providers, "os", SimpleNamespace(name="posix", environ={"SYNTHETIC": "fixture"})
    ):
        assert providers.secret("SYNTHETIC") == "fixture"
        with pytest.raises(RuntimeError, match="Missing credential"):
            providers.secret("ABSENT")
    registry = MagicMock()
    registry.QueryValueEx.return_value = ("registry-fixture", 1)
    with (
        patch.dict(sys.modules, winreg=registry),
        patch.object(providers, "os", SimpleNamespace(name="nt", environ={})),
    ):
        assert providers.secret("SYNTHETIC") == "registry-fixture"
        registry.OpenKey.side_effect = OSError("unavailable")
        with pytest.raises(RuntimeError, match="Missing credential"):
            providers.secret("SYNTHETIC")


def test_child_environment_boundary():
    with patch.object(
        providers,
        "os",
        SimpleNamespace(
            environ={
                "PATH": "fixture",
                "temp": "fixture",
                "CODEXBOT_TOKEN": "private",
                "CLAUDE_CODE_OAUTH_TOKEN": "private",
                "UNRELATED": "private",
            }
        ),
    ):
        assert providers.child_env() == {"PATH": "fixture", "temp": "fixture"}


@pytest.mark.parametrize("value", ["", " \t\n", 7, None])
def test_blank_or_non_string_credentials_fail_closed(value):
    registry = MagicMock()
    registry.QueryValueEx.return_value = (value, 1)
    with (
        patch.dict(sys.modules, winreg=registry),
        patch.object(providers, "os", SimpleNamespace(name="nt", environ={"SYNTHETIC": " "})),
    ):
        with pytest.raises(RuntimeError, match="Missing credential"):
            providers.secret("SYNTHETIC")


@pytest.mark.parametrize("platform,done", [("nt", False), ("posix", False), ("nt", True)])
def test_kill_tree(platform, done):
    proc = SimpleNamespace(
        pid=42, returncode=0 if done else None, wait=AsyncMock(), kill=MagicMock()
    )
    killer = SimpleNamespace(wait=AsyncMock())
    with (
        patch.object(providers, "os", SimpleNamespace(name=platform)),
        patch.object(
            providers.asyncio, "create_subprocess_exec", AsyncMock(return_value=killer)
        ) as spawn,
    ):
        asyncio.run(providers.kill_tree(proc))
        assert proc.wait.await_count == (0 if done else 1)
        assert spawn.await_count == (1 if platform == "nt" and not done else 0)
        assert proc.kill.call_count == (1 if platform == "posix" and not done else 0)


@pytest.mark.parametrize(
    "work,model,outcome",
    [
        (False, "", "ok"),
        (True, "synthetic-model", "ok"),
        (False, "", "empty"),
        (False, "", "exit"),
        (False, "", "timeout"),
        (False, "", "spawn"),
    ],
)
def test_codex_cli_contract_and_cleanup(tmp_path, work, model, outcome):
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"codex_model": model, "codex_reasoning_effort": "high"}))
    proc = SimpleNamespace(pid=42, returncode=None, communicate=None)
    commands = []

    async def spawn(*args, **kwargs):
        commands.append((args, kwargs))
        if outcome == "spawn":
            raise OSError("spawn failed")
        output = Path(args[args.index("-o") + 1])

        async def communicate(data):
            assert data == b"first line\nsecond line"
            if outcome == "timeout":
                raise asyncio.TimeoutError()
            output.write_text("" if outcome == "empty" else "synthetic reply", encoding="utf-8")
            proc.returncode = 4 if outcome == "exit" else 0
            return b"", b""

        proc.communicate = communicate
        return proc

    with (
        patch.object(providers, "ROOT", tmp_path),
        patch.object(providers, "config_path", return_value=config),
        patch.object(providers, "MEMORY", str(tmp_path)),
        patch.object(providers.asyncio, "create_subprocess_exec", side_effect=spawn),
        patch.object(providers, "kill_tree", AsyncMock()) as kill,
    ):
        if outcome == "ok":
            assert (
                asyncio.run(providers.codex("first line\nsecond line", work)) == "synthetic reply"
            )
        else:
            with pytest.raises((RuntimeError, OSError, asyncio.TimeoutError)):
                asyncio.run(providers.codex("first line\nsecond line", work))
        args, kwargs = commands[0]
        assert ("workspace-write" in args) == work
        assert ("features.shell_tool=false" in args) == (not work)
        assert ("-m" in args) == bool(model)
        assert kwargs["stdin"] == asyncio.subprocess.PIPE
        assert kwargs["cwd"] == (str(tmp_path) if work else tmp_path / "chat_runtime")
        assert kill.await_count == (1 if outcome == "timeout" else 0)
        assert not Path(args[args.index("-o") + 1]).exists()


class Response:
    def __init__(self, status=200, result=None):
        self.status = status
        self.result = (
            result
            if result is not None
            else {
                "candidates": [
                    {
                        "content": {
                            "parts": [
                                {"thought": True, "text": "hidden reasoning"},
                                {"text": "visible reply"},
                            ]
                        }
                    }
                ]
            }
        )
        self.read = AsyncMock()

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False

    async def json(self):
        return self.result


def test_provider_error_rejects_sensitive_or_unbounded_codes():
    for value in (
        "Authorization: synthetic-secret",
        "GeminiHTTP999",
        "ClaudeExit" + "1" * 11,
        "GeminiHTTP429\nsecret",
    ):
        with pytest.raises(ValueError, match="Invalid provider error code"):
            providers.ProviderError(value)
    assert providers.ProviderError("GeminiHTTP429").code == "GeminiHTTP429"


class Session:
    def __init__(self, replies):
        self.post = MagicMock(side_effect=replies)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        return False


@pytest.mark.parametrize("status", [429, 503])
def test_exhausted_transient_gemini_status_is_retained(status):
    session = Session([Response(status), Response(status), Response(status)])
    with (
        patch.object(providers, "secret", return_value="synthetic-key"),
        patch.object(providers.aiohttp, "ClientSession", return_value=session),
        patch.object(providers.asyncio, "sleep", AsyncMock()),
    ):
        with pytest.raises(providers.ProviderError, match=f"GeminiHTTP{status}"):
            asyncio.run(providers.Gemini("synthetic-model")("fixture"))
    assert session.post.call_count == 3


@pytest.mark.parametrize(
    "mode",
    [
        "ok",
        "retry",
        "error",
        "blocked",
        "connection_retry",
        "connection_fail",
        "timeout_retry",
        "timeout_fail",
        "work",
    ],
)
def test_gemini_contract(mode):
    if mode == "retry":
        replies = [Response(429), Response(503), Response()]
    elif mode == "error":
        replies = [Response(403)]
    elif mode == "blocked":
        replies = [Response(result={"candidates": []})]
    elif mode.startswith("connection"):
        replies = [providers.aiohttp.ClientError("synthetic network error")] * (
            3 if mode.endswith("fail") else 2
        ) + [Response()]
    elif mode.startswith("timeout"):
        replies = [asyncio.TimeoutError()] * (3 if mode.endswith("fail") else 1) + [Response()]
    else:
        replies = [Response()]
    session = Session(replies)
    with (
        patch.object(providers, "secret", return_value="synthetic-key"),
        patch.object(providers.aiohttp, "ClientSession", return_value=session),
        patch.object(providers.asyncio, "sleep", AsyncMock()),
    ):
        provider = providers.Gemini("synthetic-model")
        if mode in ("error", "blocked", "connection_fail", "timeout_fail", "work"):
            with pytest.raises(
                (RuntimeError, ValueError, providers.aiohttp.ClientError, asyncio.TimeoutError)
            ):
                asyncio.run(provider("fixture", mode == "work"))
        else:
            assert asyncio.run(provider("fixture")) == "visible reply"
        if mode != "work":
            args, kwargs = session.post.call_args
            assert "synthetic-key" not in args[0]
            assert kwargs["headers"] == {"x-goog-api-key": "synthetic-key"}


@pytest.mark.parametrize("mode", ["ok", "error", "empty", "exit", "timeout", "work"])
def test_claude_contract_and_cleanup(mode):
    result = {"result": "" if mode == "empty" else "synthetic reply", "is_error": mode == "error"}
    proc = SimpleNamespace(
        returncode=None if mode == "timeout" else 3 if mode == "exit" else 0,
        communicate=AsyncMock(
            side_effect=asyncio.TimeoutError() if mode == "timeout" else None,
            return_value=(json.dumps(result).encode(), b""),
        ),
    )
    with (
        patch.object(providers, "secret", return_value="synthetic-oauth"),
        patch.object(
            providers.asyncio, "create_subprocess_exec", AsyncMock(return_value=proc)
        ) as spawn,
        patch.object(providers, "kill_tree", AsyncMock()) as kill,
    ):
        if mode == "ok":
            assert asyncio.run(providers.claude("first\nsecond")) == "synthetic reply"
        else:
            with pytest.raises((RuntimeError, ValueError, asyncio.TimeoutError)):
                asyncio.run(providers.claude("first\nsecond", mode == "work"))
        if mode != "work":
            args, kwargs = spawn.call_args
            assert args[args.index("--tools") + 1] == ""
            assert "--strict-mcp-config" in args and "--no-session-persistence" in args
            assert kwargs["env"]["CLAUDE_CODE_OAUTH_TOKEN"] == "synthetic-oauth"
            proc.communicate.assert_awaited_once_with(b"first\nsecond")
        assert kill.await_count == (1 if mode == "timeout" else 0)
