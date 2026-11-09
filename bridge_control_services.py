"""Service control, health, logs and recovery over the existing management paths.

PM2 commands go through scripts/manage.py with this checkout's PM2_HOME and scoped
preloader, the same as scripts/pm2.ps1. Status uses the recovery entry's read-only
mode, which never starts a daemon. Logs are bounded and redacted before display.
"""

import json
import os
from pathlib import Path
import re
import subprocess
import time

from bridge_errors import CapabilityError
from bridge_control_setup import Platform, node_path
from scripts.console_windows import creation_flags
from scripts.manage import manage

SERVICES = ("codexbot", "antigravitybot", "claudebot", "botbridge-log-manager", "botbridge-health")
TASK_NAME = re.compile(r"[A-Za-z0-9_-]{1,64}")
LOG_BYTES = 32768
# Read and redacted ahead of the displayed tail, so a credential or private value that
# crosses the display boundary is matched whole and only cut after redaction. Far above
# the largest storable credential (bridge_credentials.MAX_SECRET_BYTES).
LOG_CONTEXT = 65536
STATUS_FIELDS = ("name", "pid", "status", "restarts", "uptime")


def services(store):
    root = store.root
    entry = root / "scripts/recover_pm2.cjs"
    try:
        node = node_path(root, store.snapshot()["settings"])
    except (OSError, ValueError):
        return {"available": False}
    if not entry.is_file() or not node.is_file() or not (root / "tools/pm2").is_dir():
        return {"available": False}
    try:
        result = subprocess.run(
            [str(node), str(entry), "--status"],
            cwd=root,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=60,
            creationflags=creation_flags(),
        )
        data = json.loads(result.stdout.decode("utf-8"))
        rows = [
            {key: row[key] for key in STATUS_FIELDS}
            for row in data["services"]
            if row["name"] in SERVICES
        ]
        return {
            "available": result.returncode == 0,
            "daemon": data["daemon"] is True,
            "services": rows,
        }
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError):
        return {"available": False}


def control(store, action, name, console=False):
    """Explicit start/stop/restart of one ecosystem service, or the full start procedure."""
    root = store.root
    if type(console) is not bool:
        raise CapabilityError("Invalid troubleshooting console choice")
    if action == "start-all":
        arguments = None
    elif name not in SERVICES or action not in ("start", "stop", "restart"):
        raise CapabilityError("Unknown service action")
    elif action == "start":
        # The ecosystem is loaded here, so the console choice applies to this start.
        arguments = ["start", str(root / "ecosystem.config.js"), "--only", name]
    else:
        arguments = [action, name]
    try:
        if arguments is None:
            manage("start", root, console=console)
        else:
            manage("pm2", root, arguments, console=console)
    except (subprocess.SubprocessError, OSError):
        raise CapabilityError("PM2 command failed; check the service logs") from None
    return {"action": action, "name": name}


def tail(path):
    """The end of a log, starting at a complete line, with LOG_CONTEXT extra bytes."""
    try:
        with Path(path).open("rb") as source:
            start = max(0, source.seek(0, os.SEEK_END) - LOG_BYTES - LOG_CONTEXT)
            source.seek(start)
            data = source.read(LOG_BYTES + LOG_CONTEXT)
    except OSError:
        return None
    if start:
        # The line cut by the read offset is dropped whole, never redacted in part.
        cut = data.find(b"\n")
        data = data[cut + 1 :] if cut >= 0 else b""
    return data.decode("utf-8", "replace")


def shown(text):
    """The last LOG_BYTES characters of already-redacted text, from a line start."""
    if len(text) <= LOG_BYTES:
        return text
    text = text[-LOG_BYTES:]
    cut = text.find("\n")
    return text[cut + 1 :] if cut >= 0 else text


def logs(store, name):
    root = store.root
    if name in SERVICES:
        paths = [root / f".pm2/logs/{name}-out.log", root / f".pm2/logs/{name}-error.log"]
    elif name == "health":
        paths = [root / "bridge_health.log"]
    elif name == "recovery":
        paths = [root / ".pm2/recovery.log"]
    else:
        raise CapabilityError("Unknown log")
    found = [text for text in map(tail, paths) if text is not None]
    if not found:
        return {"name": name, "text": None}
    # Known credentials and private values are redacted over the whole window first;
    # the displayed tail is cut from the redacted text, so no partial value survives.
    redact = store.redactor()
    return {"name": name, "text": "\n".join(shown(redact(text)) for text in found)}


def age(path):
    try:
        return round(time.time() - Path(path).stat().st_mtime, 1)
    except OSError:
        return None


def health(store):
    root = store.root
    try:
        # The health monitor module reads this checkout's identities at import time;
        # a fresh clone without local configuration reports health as unavailable.
        from bridge_health import inspect

        current = inspect(root)
    except (OSError, ValueError, KeyError, TypeError, RuntimeError):
        current = {"status": "unavailable", "failures": [], "bots": []}
    for bot in current["bots"]:
        bot["bot_id"] = str(bot["bot_id"])
        bot["age_seconds"] = age(root / f"runtime_state/health_{bot['bot_id']}.json")
    try:
        monitor = json.loads((root / "runtime_state/setup_health.json").read_text("utf-8"))
        monitor = {"status": monitor["status"], "failures": monitor["failures"]}
    except (OSError, ValueError, KeyError, TypeError):
        monitor = None
    return {
        "current": {key: current[key] for key in ("status", "failures", "bots")},
        "monitor": monitor,
        "monitor_age_seconds": age(root / "runtime_state/setup_health.json"),
        "recovery": recovery(store),
    }


def recovery(store):
    home = store.root / ".pm2"
    try:
        state = json.loads((home / "recovery_state.json").read_text("utf-8"))
        state = {"status": state["status"], "recovered": state.get("recovered")}
    except (OSError, ValueError, KeyError, TypeError):
        state = None
    return {
        "maintenance": (home / "recovery.disabled").exists(),
        "state": state,
        "state_age_seconds": age(home / "recovery_state.json"),
    }


def maintenance(store, enabled):
    """The recovery supervisor's documented pause file."""
    if type(enabled) is not bool:
        raise CapabilityError("Invalid maintenance choice")
    home = store.root / ".pm2"
    marker = home / "recovery.disabled"
    if enabled:
        home.mkdir(exist_ok=True)
        marker.write_text("maintenance from local control\n", encoding="utf-8")
    else:
        marker.unlink(missing_ok=True)
    return recovery(store)


def recovery_task(store, action, task, node=None, platform=None):
    """Windows Task Scheduler adapter for the shipped recovery installer."""
    platform = platform or Platform()
    if not platform.windows:
        raise CapabilityError("Recovery tasks are available on Windows only")
    # The name reaches PowerShell -Command text, so only ASCII word characters pass.
    if not isinstance(task, str) or not TASK_NAME.fullmatch(task):
        raise CapabilityError("Use a task name of letters, numbers, - and _")
    if action not in ("status", "install", "remove"):
        raise CapabilityError("Unknown recovery action")
    root = store.root
    shell = Path(os.environ.get("SYSTEMROOT", "C:/Windows")) / (
        "System32/WindowsPowerShell/v1.0/powershell.exe"
    )
    prefix = [str(shell), "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass"]
    if action == "install":
        node = node or node_path(root, store.snapshot()["settings"])
        script = str(root / "scripts/install_recovery.ps1")
        command = [*prefix, "-File", script, "-NodePath", str(node), "-TaskName", task]
    elif action == "remove":
        command = [
            *prefix,
            "-Command",
            f"Unregister-ScheduledTask -TaskName '{task}' -Confirm:$false",
        ]
    else:
        command = [
            *prefix,
            "-Command",
            f"if (Get-ScheduledTask -TaskName '{task}' -ErrorAction SilentlyContinue) {{ exit 0 }} else {{ exit 3 }}",
        ]
    try:
        code = subprocess.run(
            command,
            cwd=root,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=60,
            creationflags=creation_flags(),
        ).returncode
    except (OSError, subprocess.TimeoutExpired):
        code = None
    if action == "status":
        return {"task": task, "installed": code == 0 if code in (0, 3) else None}
    if code != 0:
        raise CapabilityError("Recovery task change failed")
    return {"task": task, "installed": action == "install"}
