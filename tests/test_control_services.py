"""Service control, health, redacted logs and recovery through the real management paths.

The PM2 status entry is replaced by a real child process that prints a fixed snapshot,
so no daemon or bot is started. Management commands go through scripts/manage.py.
"""

import json
from pathlib import Path
import subprocess
import sys
import time
from unittest.mock import patch

import pytest

import test_bridge  # noqa: F401  # Installs the identity fixture before health imports.
import bridge_control_services as services
from bridge_control_setup import Platform
from bridge_errors import CapabilityError
from test_control_config import configured

SECRET = "synthetic-control-log-secret-0b8e"


def settings(store, **values):
    snapshot = store.snapshot()
    data = {**snapshot["settings"], **values}
    store.save("local_settings.json", data, snapshot["revisions"]["local_settings.json"])


def status_entry(store, output, code=0):
    entry = store.root / "scripts/recover_pm2.cjs"
    entry.parent.mkdir(exist_ok=True)
    # Python stands in for Node here: a real process prints the status snapshot.
    entry.write_text(
        f"import sys\nsys.stdout.write({json.dumps(output)!r})\nsys.exit({code})\n",
        encoding="utf-8",
    )


def test_pm2_status_is_read_only_filtered_and_fails_closed(tmp_path):
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    from bridge_control_config import ControlConfig

    assert services.services(ControlConfig(fresh)) == {"available": False}
    (tmp_path / "installed").mkdir()
    store = configured(tmp_path / "installed")
    assert services.services(store) == {"available": False}
    settings(store, node_executable=sys.executable)
    (store.root / "tools/pm2").mkdir(parents=True)
    rows = [
        {"name": "codexbot", "pid": 42, "status": "online", "restarts": 1, "uptime": 1700},
        {"name": "unrelated", "pid": 7, "status": "online", "restarts": 0, "uptime": 1},
    ]
    status_entry(store, {"daemon": True, "services": rows})
    assert services.services(store) == {"available": True, "daemon": True, "services": rows[:1]}
    status_entry(store, {"daemon": False, "services": []}, code=1)
    assert services.services(store) == {"available": False, "daemon": False, "services": []}
    status_entry(store, "not json")
    assert services.services(store) == {"available": False}
    status_entry(store, {"daemon": True, "services": [{"name": "codexbot"}]})
    assert services.services(store) == {"available": False}


def test_service_actions_use_manage_with_scoped_arguments(tmp_path):
    store = configured(tmp_path)
    calls = []

    def recorded(action, root, pm2_args=(), console=None):
        calls.append((action, root, list(pm2_args), console))

    with patch.object(services, "manage", recorded):
        services.control(store, "start", "codexbot", True)
        services.control(store, "stop", "claudebot")
        services.control(store, "restart", "botbridge-health")
        assert services.control(store, "start-all", None) == {"action": "start-all", "name": None}
        for args in (("start", "unknown"), ("delete", "codexbot"), ("kill", "codexbot")):
            with pytest.raises(CapabilityError, match="Unknown service action"):
                services.control(store, *args)
        with pytest.raises(CapabilityError, match="console"):
            services.control(store, "start", "codexbot", "1")
    root = store.root
    assert calls == [
        ("pm2", root, ["start", str(root / "ecosystem.config.js"), "--only", "codexbot"], True),
        ("pm2", root, ["stop", "claudebot"], False),
        ("pm2", root, ["restart", "botbridge-health"], False),
        ("start", root, [], False),
    ]

    def failed(*args, **kwargs):
        raise subprocess.CalledProcessError(1, "pm2")

    with patch.object(services, "manage", failed), pytest.raises(CapabilityError, match="PM2"):
        services.control(store, "stop", "codexbot")
    # The real management path refuses to act without this checkout's venv: it never
    # falls back to a global PM2 or starts anything.
    with pytest.raises(RuntimeError, match="Create the checkout venv"):
        services.control(store, "stop", "codexbot")


def test_console_choice_reaches_only_the_management_command(tmp_path):
    from scripts import manage as management

    store = configured(tmp_path)
    seen = []
    with patch.object(management, "run", lambda command, root, env, timeout=120: seen.append(env)):
        (store.root / ".venv/Scripts").mkdir(parents=True)
        (store.root / ".venv/Scripts/python.exe").write_text("")
        settings(store, node_executable=sys.executable, pm2_cli=sys.executable)
        services.control(store, "stop", "codexbot", False)
        services.control(store, "start", "codexbot", True)
    assert [env["BOTBRIDGE_SHOW_CONSOLE"] for env in seen] == ["0", "1"]
    assert all(env["PM2_HOME"] == str(store.root / ".pm2") for env in seen)


def test_logs_are_bounded_and_redacted(tmp_path):
    store = configured(tmp_path)
    logs = store.root / ".pm2/logs"
    logs.mkdir(parents=True, exist_ok=True)
    (logs / "codexbot-out.log").write_text("x" * 40000 + "\nconnected " + SECRET + "\n")
    (logs / "codexbot-error.log").write_text("error line\n")
    (store.root / "bridge_health.log").write_bytes(b"Health ok\n")
    with patch(
        "bridge_control_config.legacy", lambda name: SECRET if name == "CODEXBOT_TOKEN" else None
    ):
        result = services.logs(store, "codexbot")
    assert SECRET not in result["text"] and "connected" in result["text"]
    assert "error line" in result["text"] and len(result["text"]) < 34000
    assert services.logs(store, "health") == {"name": "health", "text": "Health ok\n"}
    assert services.logs(store, "recovery") == {"name": "recovery", "text": None}
    with pytest.raises(CapabilityError, match="Unknown log"):
        services.logs(store, "../../secrets")


BOUNDARY = "synthetic-boundary-credential-" + "q" * 40


def fragments(text, value):
    return [value[i:] for i in range(1, len(value) - 6)] + [value[:i] for i in range(7, len(value))]


@pytest.mark.parametrize("earlier", [0, 200000])
def test_log_tail_never_shows_part_of_a_value_crossing_the_cut(tmp_path, earlier):
    store = configured(tmp_path)
    path = store.root / ".pm2/logs/codexbot-out.log"
    path.parent.mkdir(parents=True, exist_ok=True)
    # The displayed tail starts 20 characters before the end of the credential's line.
    padding = b"x" * (services.LOG_BYTES - 21)
    path.write_bytes(b"y\n" * (earlier // 2) + BOUNDARY.encode() + b"\n" + padding)
    with patch(
        "bridge_control_config.legacy",
        lambda name: BOUNDARY if name == "CODEXBOT_TOKEN" else None,
    ):
        assert store.redact(BOUNDARY) == "[private]"
        text = services.logs(store, "codexbot")["text"]
    # Redacted over the whole window first, so the cut lands outside the placeholder.
    assert text.endswith("[private]\n" + padding.decode())
    assert not any(part in text for part in fragments(text, BOUNDARY))


def test_log_lines_cut_by_the_read_window_are_dropped_whole(tmp_path):
    store = configured(tmp_path)
    logs = store.root / ".pm2/logs"
    logs.mkdir(parents=True, exist_ok=True)
    window = services.LOG_BYTES + services.LOG_CONTEXT
    # One line longer than the whole read window: its visible part is never returned.
    (logs / "codexbot-out.log").write_bytes(BOUNDARY.encode() + b"z" * window)
    # A single redacted line longer than the display is cut from its end.
    (logs / "codexbot-error.log").write_bytes(b"w" * (services.LOG_BYTES + 10))
    with patch("bridge_control_config.legacy", lambda name: None):
        text = services.logs(store, "codexbot")["text"]
    assert text == "\n" + "w" * services.LOG_BYTES


def test_health_recovery_and_maintenance(tmp_path):
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    from bridge_control_config import ControlConfig

    unavailable = services.health(ControlConfig(fresh))
    assert unavailable["current"] == {"status": "unavailable", "failures": [], "bots": []}
    assert unavailable["monitor"] is None and unavailable["recovery"]["state"] is None
    (tmp_path / "installed").mkdir()
    store = configured(tmp_path / "installed")
    state = store.root / "runtime_state"
    for identity in (101, 102, 103):
        (state / f"health_{identity}.json").write_text(
            json.dumps({"timestamp": time.time(), "ready": identity != 103, "last_error": None})
        )
    (state / "setup_health.json").write_text(json.dumps({"status": "ok", "failures": []}))
    report = services.health(store)
    assert {bot["bot_id"] for bot in report["current"]["bots"]} == {"101", "102", "103"}
    assert all(bot["age_seconds"] < 60 for bot in report["current"]["bots"])
    assert report["current"]["status"] == "degraded"
    assert report["monitor"] == {"status": "ok", "failures": []}
    assert report["monitor_age_seconds"] < 60
    (state / "setup_health.json").write_text("{")
    assert services.health(store)["monitor"] is None

    assert services.maintenance(store, True)["maintenance"] is True
    assert (store.root / ".pm2/recovery.disabled").is_file()
    (store.root / ".pm2/recovery_state.json").write_text(json.dumps({"status": "ok"}))
    current = services.maintenance(store, False)
    assert current["maintenance"] is False and current["state"] == {
        "status": "ok",
        "recovered": None,
    }
    assert services.maintenance(store, False)["maintenance"] is False
    with pytest.raises(CapabilityError, match="maintenance"):
        services.maintenance(store, "yes")


def test_recovery_task_adapter_validates_names_and_reports_exit_status(tmp_path):
    store = configured(tmp_path)
    windows = Platform("nt")
    with pytest.raises(CapabilityError, match="Windows only"):
        services.recovery_task(store, "status", "BotBridge-Test", platform=Platform("posix"))
    for task in ("bad name", "x;Remove-Item", 7, "a" * 65, "", "caf\u00e9", "a\u0660", "a\n"):
        with pytest.raises(CapabilityError, match="task name"):
            services.recovery_task(store, "status", task, platform=windows)
    with pytest.raises(CapabilityError, match="Unknown recovery action"):
        services.recovery_task(store, "start", "BotBridge-Test", platform=windows)
    commands, codes = [], []

    def ran(command, **options):
        commands.append(command)
        code = codes.pop(0)
        if isinstance(code, Exception):
            raise code
        return subprocess.CompletedProcess(command, code)

    with patch.object(services.subprocess, "run", ran):
        codes[:] = [0, 3, 1, subprocess.TimeoutExpired("x", 1)]
        for expected in (True, False, None, None):
            result = services.recovery_task(store, "status", "BotBridge-Test", platform=windows)
            assert result == {"task": "BotBridge-Test", "installed": expected}
        codes[:] = [0, 0, 1]
        node = Path(sys.executable)
        installed = services.recovery_task(store, "install", "BotBridge-Test", node, windows)
        assert installed == {"task": "BotBridge-Test", "installed": True}
        removed = services.recovery_task(store, "remove", "BotBridge-Test", platform=windows)
        assert removed == {"task": "BotBridge-Test", "installed": False}
        with pytest.raises(CapabilityError, match="change failed"):
            services.recovery_task(store, "remove", "BotBridge-Test", platform=windows)
    install = commands[4]
    assert install[install.index("-File") + 1] == str(store.root / "scripts/install_recovery.ps1")
    assert install[install.index("-TaskName") + 1] == "BotBridge-Test"
    assert install[install.index("-NodePath") + 1] == str(node)
    assert "Unregister-ScheduledTask -TaskName 'BotBridge-Test'" in commands[5][-1]
    with patch.object(services.subprocess, "run", ran):
        codes[:] = [0]
        settings(store, node_executable=sys.executable)
        services.recovery_task(store, "install", "BotBridge-Test", platform=windows)
    assert commands[-1][commands[-1].index("-NodePath") + 1] == str(Path(sys.executable))
