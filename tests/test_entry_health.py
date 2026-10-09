import asyncio
import json
import os
import runpy
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from test_bridge import C, A
import bridge_bot as bot
import bridge_health as health
import bridge_privacy
import bridge_providers
import bridge_runtime
import bridge_windows
import preflight
from test_setup import module

ROOT = Path(__file__).resolve().parent.parent
initialize = module("initialize_entry", "initialize.py")


@pytest.mark.parametrize(
    "name,identity",
    [("codexbot.py", C), ("claudebot.py", 103), ("AntigravityBot/antigravitybot.py", A)],
)
def test_launchers_only_select_configured_identity(name, identity):
    with patch.object(bot, "main") as main:
        runpy.run_path(str(ROOT / name), run_name="__main__")
        main.assert_called_once_with(identity)
        main.reset_mock()
        runpy.run_path(str(ROOT / name), run_name="library_import")
        main.assert_not_called()


@pytest.mark.parametrize(
    "identity,login_failure", [(C, False), (A, False), (103, False), (C, True)]
)
def test_bot_lifecycle_and_callback_delegation(tmp_path, identity, login_failure):
    (tmp_path / "runtime_state").mkdir()
    client = MagicMock()
    callbacks = {}
    client.event.side_effect = lambda fn: callbacks.setdefault(fn.__name__, fn)
    if login_failure:
        client.run.side_effect = bot.discord.LoginFailure("synthetic credential rejection")
    engine = SimpleNamespace(health={}, ready=AsyncMock())
    with (
        patch.object(bot, "ROOT", tmp_path),
        patch.object(
            bot,
            "load_config",
            return_value={"enabled_bots": [C, A, 103], "gemini_model": "synthetic"},
        ),
        patch.object(bot, "protect_process") as protect,
        patch.object(bot, "secret", return_value="synthetic-token"),
        patch.object(bot.discord, "Client", return_value=client),
        patch.object(bot, "Bridge", return_value=engine),
        patch.object(bot, "Gemini", return_value=AsyncMock()),
        patch.object(bot, "append_line") as append,
        patch.object(bot, "dispatch", AsyncMock()) as dispatch,
    ):
        if login_failure:
            with pytest.raises(SystemExit) as stopped:
                bot.main(identity)
            assert stopped.value.code == 78
            assert append.called
        else:
            bot.main(identity)
            asyncio.run(callbacks["on_ready"]())
            asyncio.run(callbacks["on_message"]("fixture"))
            asyncio.run(callbacks["on_error"]("fixture_event"))
            engine.ready.assert_awaited_once()
            dispatch.assert_awaited_once_with(engine, "fixture")
        protect.assert_called_once_with(tmp_path / f"bot_{identity}.lock")
        data = json.loads((tmp_path / f"runtime_state/health_{identity}.json").read_text())
        assert data["ready"] is False and data["timestamp"] == 0


def test_disabled_bot_never_reads_credential_or_starts_client():
    with (
        patch.object(bot, "load_config", return_value={"enabled_bots": [A]}),
        patch.object(bot, "secret") as secret,
        patch.object(bot, "protect_process") as protect,
    ):
        with pytest.raises(SystemExit) as stopped:
            bot.main(C)
        assert stopped.value.code == 75
        secret.assert_not_called()
        protect.assert_not_called()


@pytest.mark.parametrize("ids", [[C], [A], [103], [C, A, 103]])
def test_preflight_enabled_provider_credentials_only(tmp_path, ids):
    node, codex, claude, public = (tmp_path / n for n in ("node", "codex", "claude", "public.md"))
    for path in (node, codex, claude, public):
        path.write_text("synthetic fixture")
    config = {"enabled_bots": ids, "public_context_file": public.name}
    with (
        patch.object(preflight, "ROOT", tmp_path),
        patch.object(preflight, "NODE", str(node)),
        patch.object(preflight, "CODEX", str(codex)),
        patch.object(preflight, "CLAUDE", str(claude)),
        patch.object(preflight, "load_config", return_value=config),
        patch.object(preflight, "Privacy") as privacy,
        patch.object(preflight, "secret", return_value="synthetic") as secret,
    ):
        preflight.main()
        expected = {
            C: ["CODEXBOT_TOKEN"],
            A: ["ANTIGRAVITYBOT_TOKEN", "GEMINI_API_KEY"],
            103: ["CLAUDEBOT_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"],
        }
        assert [call.args[0] for call in secret.call_args_list] == [
            key for identity in ids for key in expected[identity]
        ]
        privacy.return_value.refresh.assert_called_once()
    with (
        patch.object(bridge_runtime, "ROOT", tmp_path),
        patch.object(bridge_runtime, "load_config", return_value=config),
        patch.object(bridge_providers, "NODE", str(node)),
        patch.object(bridge_providers, "CODEX", str(codex)),
        patch.object(bridge_providers, "CLAUDE", str(claude)),
        patch.object(bridge_providers, "secret", return_value="synthetic"),
        patch.object(bridge_privacy, "Privacy"),
    ):
        runpy.run_path(str(ROOT / "preflight.py"), run_name="__main__")


@pytest.mark.parametrize("missing", ["node", "codex", "claude", "public.md"])
def test_preflight_missing_file_is_an_explicit_error(tmp_path, missing):
    paths = {name: tmp_path / name for name in ("node", "codex", "claude", "public.md")}
    for name, path in paths.items():
        if name != missing:
            path.write_text("synthetic")
    config = {"enabled_bots": [C, A, 103], "public_context_file": "public.md"}
    with (
        patch.object(preflight, "ROOT", tmp_path),
        patch.object(preflight, "NODE", str(paths["node"])),
        patch.object(preflight, "CODEX", str(paths["codex"])),
        patch.object(preflight, "CLAUDE", str(paths["claude"])),
        patch.object(preflight, "load_config", return_value=config),
        patch.object(preflight, "Privacy"),
        patch.object(preflight, "secret", return_value="synthetic"),
    ):
        with pytest.raises(RuntimeError, match="unavailable"):
            preflight.main()


def health_fixture(root):
    data = json.loads((ROOT / "tests/fixtures/bridge_config.json").read_text())
    (root / "bridge_config.json").write_text(json.dumps(data))
    (root / "runtime_state").mkdir()
    for identity in (C, A):
        (root / f"runtime_state/health_{identity}.json").write_text(
            json.dumps({"ready": True, "timestamp": time.time()})
        )
    (root / "log_management_state.json").write_text(
        '{"status":"ok","errors":[],"inventory_complete":true}'
    )
    module = root / ".pm2/modules/pm2-logrotate/node_modules/pm2-logrotate/app.js"
    module.parent.mkdir(parents=True)
    module.write_text("str === true || str === 'true'; str === false || str === 'false'")
    return module


@pytest.mark.parametrize(
    "mode",
    [
        "healthy",
        "provider_error",
        "missing_bot",
        "missing_log_manager",
        "stale_log_manager",
        "log_errors",
        "budget_failed",
        "inventory_partial",
        "bad_module",
        "missing_module",
        "low_disk",
    ],
)
def test_health_diagnostics(tmp_path, mode):
    module = health_fixture(tmp_path)
    if mode == "provider_error":
        path = tmp_path / f"runtime_state/health_{C}.json"
        data = json.loads(path.read_text())
        data["last_error"] = "SyntheticFailure"
        path.write_text(json.dumps(data))
    elif mode == "missing_bot":
        (tmp_path / f"runtime_state/health_{C}.json").unlink()
    elif mode == "missing_log_manager":
        (tmp_path / "log_management_state.json").unlink()
    elif mode == "stale_log_manager":
        os.utime(tmp_path / "log_management_state.json", (time.time() - 30,) * 2)
    elif mode == "log_errors":
        (tmp_path / "log_management_state.json").write_text('{"errors":["synthetic"]}')
    elif mode == "budget_failed":
        (tmp_path / "log_management_state.json").write_text('{"errors":[],"status":"error"}')
    elif mode == "inventory_partial":
        (tmp_path / "log_management_state.json").write_text(
            '{"errors":[],"status":"ok","inventory_complete":false}'
        )
    elif mode == "bad_module":
        module.write_text("unpatched fixture")
    elif mode == "missing_module":
        module.unlink()
    with (
        patch.dict(os.environ, PM2_HOME=str(tmp_path / ".pm2")),
        patch.object(
            health.shutil,
            "disk_usage",
            return_value=SimpleNamespace(free=0 if mode == "low_disk" else 3_000_000_000),
        ),
    ):
        report = health.inspect(tmp_path)
    assert (report["status"] == "ok") == (mode == "healthy")


def test_health_loop_changes_errors_and_recovery(tmp_path):
    reports = [
        {"status": "ok", "failures": []},
        {"status": "ok", "failures": []},
        ValueError("synthetic"),
        {"status": "ok", "failures": []},
    ]
    sleeps = [0]

    def sleep(_):
        sleeps[0] += 1
        if sleeps[0] == 4:
            raise KeyboardInterrupt()

    with (
        patch.object(health, "ROOT", tmp_path),
        patch.object(health, "protect_process"),
        patch.object(health, "inspect", side_effect=reports),
        patch.object(health, "append_line") as append,
        patch.object(health.time, "sleep", side_effect=sleep),
    ):
        with pytest.raises(KeyboardInterrupt):
            health.main()
        assert append.call_count == 3
        assert (
            json.loads((tmp_path / "runtime_state/setup_health.json").read_text())["status"] == "ok"
        )
    with patch.object(bridge_windows, "protect_process", side_effect=KeyboardInterrupt()):
        with pytest.raises(KeyboardInterrupt):
            runpy.run_path(str(ROOT / "bridge_health.py"), run_name="__main__")


def test_initializer_cli_and_help_entry():
    args = SimpleNamespace(
        owner_id=201, channel_id=301, codex_id=101, antigravity_id=102, claude_id=103
    )
    with (
        patch.object(initialize.argparse.ArgumentParser, "parse_args", return_value=args),
        patch.object(initialize, "initialize") as create,
    ):
        initialize.main()
        create.assert_called_once_with(**vars(args))
    with patch.object(sys, "argv", ["initialize.py", "--help"]):
        with pytest.raises(SystemExit) as stopped:
            runpy.run_path(str(ROOT / "initialize.py"), run_name="__main__")
        assert stopped.value.code == 0
