"""First-run checklist, provider status and diagnostics over the existing setup paths.

Results carry states and fixed guidance only: never credential values or command
output. Operating-system differences stay behind Platform. Nothing here starts bots.
"""

import asyncio
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

import aiohttp

from bridge_errors import CapabilityError
from bridge_health_io import write_health
from bridge_runtime_credentials import NAMES, RuntimeCredentials, legacy, native_names
from scripts.console_windows import creation_flags
from scripts.manage import run

# README pins the same versions; tests keep them in agreement.
CLIS = {
    "codex": ("tools/codex-cli", "@openai/codex", "0.159.3", ("login", "status")),
    "claude": ("tools/claude-cli", "@anthropic-ai/claude-code", "2.1.112", ("auth", "status")),
}
REQUIRED = {
    "codex": ("CODEXBOT_TOKEN",),
    "antigravity": ("ANTIGRAVITYBOT_TOKEN", "GEMINI_API_KEY"),
    "claude": ("CLAUDEBOT_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"),
}
TOKENS = {
    "codex": "CODEXBOT_TOKEN",
    "antigravity": "ANTIGRAVITYBOT_TOKEN",
    "claude": "CLAUDEBOT_TOKEN",
}
DISCORD = "https://discord.com/api/v10"
GEMINI = "https://generativelanguage.googleapis.com/v1beta"
AGENT = "DiscordBot (https://github.com/benjaminhmlucas/Discord_A2A_BOTS, 1.0)"
TEST_MESSAGE = "BotBridge local control test message. No reply is expected."
# Runs inside the checkout venv: compares installed distributions with exact pins.
PINS = """
import sys
from importlib import metadata
bad = 0
for line in open(sys.argv[1], encoding="utf-8"):
    spec, _, marker = line.split("#")[0].strip().partition(";")
    if not spec or marker and marker.split("==")[1].strip().strip("'\\"") != sys.platform:
        continue
    name, _, pinned = spec.strip().partition("==")
    try:
        bad += metadata.version(name) != pinned
    except metadata.PackageNotFoundError:
        bad += 1
sys.exit(1 if bad else 0)
"""


class Platform:
    """The one place for operating-system specific setup paths and commands."""

    def __init__(self, name=None):
        self.windows = (os.name if name is None else name) == "nt"

    def venv_python(self, root):
        return Path(root) / (".venv/Scripts/python.exe" if self.windows else ".venv/bin/python")

    def npm(self, node):
        node = Path(node)
        if self.windows:
            return node.parent / "node_modules/npm/bin/npm-cli.js"
        return node.parent.parent / "lib/node_modules/npm/bin/npm-cli.js"

    def setup_command(self):
        if self.windows:
            return "py -3.11 scripts/manage.py setup"
        return "python3.11 -m venv .venv && .venv/bin/python -m pip install -r requirements.txt"


def quiet(command, cwd, timeout=60, env=None):
    """Exit status only. Output may hold account names and is never returned."""
    try:
        return subprocess.run(
            [str(part) for part in command],
            cwd=cwd,
            env=env,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=timeout,
            creationflags=creation_flags(),
        ).returncode
    except (OSError, subprocess.TimeoutExpired):
        return None


def local(root, value):
    path = Path(value)
    return path if path.is_absolute() else Path(root) / path


def node_path(root, settings):
    found = shutil.which(settings["node_executable"]) or settings["node_executable"]
    return local(root, found)


def roles(config):
    return {
        role: identity in config["enabled_bots"] for role, identity in config["bot_ids"].items()
    }


def credential_state(root, config, settings, name):
    if name in native_names(settings):
        state = RuntimeCredentials(config, root).status(name)["state"]
        return {"state": state, "source": "native"}
    return {"state": "set" if legacy(name) else "not_set", "source": "environment"}


def resolve(root, config, settings, name):
    if name in native_names(settings):
        return RuntimeCredentials(config, root).optional(name)
    return legacy(name)


def verified(root):
    try:
        data = json.loads((Path(root) / "runtime_state/control_verified.json").read_text("utf-8"))
        return {name: data[name] for name in NAMES if isinstance(data.get(name), (int, float))}
    except (OSError, ValueError, AttributeError):
        return {}


def mark_verified(root, name):
    data = verified(root)
    data[name] = time.time()
    (Path(root) / "runtime_state").mkdir(exist_ok=True)
    write_health(Path(root) / "runtime_state/control_verified.json", data)


def checklist(store, platform=None):
    platform = platform or Platform()
    root = store.root
    python = platform.venv_python(root)
    steps = []

    def step(key, ok, fix, needed=True):
        state = "ok" if ok else "action" if needed else "not_needed"
        steps.append({"id": key, "state": state, "fix": fix})

    step("venv", python.is_file(), {"command": platform.setup_command()})
    pins = python.is_file() and quiet([python, "-c", PINS, root / "requirements.txt"], root) == 0
    step("dependencies", pins, {"command": platform.setup_command()})
    try:
        snapshot = store.snapshot()
    except (OSError, ValueError):
        step("identities", False, {"screen": "Setup"})
        return {"steps": steps, "ready": False}
    step("identities", True, {"screen": "Discord"})
    config, settings = snapshot["config"], snapshot["settings"]
    enabled = roles(config)
    step("node", node_path(root, settings).is_file(), {"command": "Install Node.js 24"})
    step("pm2", local(root, settings["pm2_cli"]).is_file(), {"action": "install_pm2"})
    for role in CLIS:
        present = local(root, settings[role + "_cli"]).is_file()
        step(role + "_cli", present, {"action": "install_" + role}, enabled[role])
    for role, names in REQUIRED.items():
        for name in names:
            state = credential_state(root, config, settings, name)["state"]
            step(name, state == "set", {"screen": "Credentials"}, enabled[role])
    ready = all(item["state"] != "action" for item in steps)
    steps.append({"id": "preflight", "state": "not_run", "fix": {"action": "preflight"}})
    return {"steps": steps, "ready": ready}


def install(store, target, platform=None):
    """Explicit pinned installs, identical to the README commands."""
    platform = platform or Platform()
    root = store.root
    settings = store.snapshot()["settings"]
    node = node_path(root, settings)
    npm = platform.npm(node)
    if not node.is_file() or not npm.is_file():
        raise CapabilityError("Install Node.js with npm before installing tools")
    if target == "pm2":
        prefix = root / "tools/pm2"
        prefix.mkdir(parents=True, exist_ok=True)
        for name in ("package.json", "package-lock.json"):
            shutil.copyfile(root / "dependencies/pm2" / name, prefix / name)
        command = [node, npm, "ci", "--prefix", prefix]
    elif target in CLIS:
        folder, package, version, _ = CLIS[target]
        command = [node, npm, "install", "--prefix", root / folder, package + "@" + version]
    else:
        raise CapabilityError("Unknown installation")
    try:
        run(command, root, os.environ.copy(), timeout=600)
    except (subprocess.SubprocessError, OSError):
        raise CapabilityError("Installation failed; check Node, npm and network access") from None
    return {"installed": target}


def preflight(store, platform=None):
    platform = platform or Platform()
    root = store.root
    python, script = platform.venv_python(root), root / "preflight.py"
    if not python.is_file() or not script.is_file():
        return {"preflight": "unavailable"}
    code = quiet([python, script], root, timeout=120)
    return {"preflight": "passed" if code == 0 else "failed"}


def providers(store):
    snapshot = store.snapshot()
    root, config, settings = store.root, snapshot["config"], snapshot["settings"]
    enabled = roles(config)
    stamps = verified(root)
    result = {}
    for role, names in REQUIRED.items():
        entry = {
            "enabled": enabled[role],
            "credentials": {
                name: {
                    **credential_state(root, config, settings, name),
                    "verified": stamps.get(name),
                }
                for name in names
            },
        }
        if role in CLIS:
            folder, package, version, _ = CLIS[role]
            entry["pinned"] = version
            entry["installed"] = None
            try:
                metadata = local(root, folder) / "node_modules" / package / "package.json"
                entry["installed"] = json.loads(metadata.read_text("utf-8"))["version"]
            except (OSError, ValueError, KeyError, TypeError):
                pass
        result[role] = entry
    result["codex"]["model"] = config.get("codex_model")
    result["codex"]["reasoning_effort"] = config.get("codex_reasoning_effort")
    result["antigravity"]["model"] = config.get("gemini_model")
    return {"providers": result}


def login_status(store, role):
    """Provider CLI login state, using the CLI's own status command."""
    if role not in CLIS:
        raise CapabilityError("Unknown provider")
    settings = store.snapshot()["settings"]
    root = store.root
    cli = local(root, settings[role + "_cli"])
    if not cli.is_file():
        return {"login": "not_installed"}
    code = quiet([node_path(root, settings), cli, *CLIS[role][3]], root)
    return {"login": "signed_in" if code == 0 else "not_signed_in" if code else "unavailable"}


async def http_check(method, url, headers, body=None):
    timeout = aiohttp.ClientTimeout(total=15)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.request(method, url, headers=headers, json=body) as response:
                return response.status, (await response.json()) if response.status == 200 else None
    except (aiohttp.ClientError, asyncio.TimeoutError, ValueError):
        return None, None


async def verify(store, name, discord=DISCORD, gemini=GEMINI):
    """Credential checks without generation: Discord identity and Gemini model metadata."""
    snapshot = await asyncio.to_thread(store.snapshot)
    config, settings = snapshot["config"], snapshot["settings"]
    if name not in (*TOKENS.values(), "GEMINI_API_KEY"):
        raise CapabilityError("This credential has no connectivity check")
    value = await asyncio.to_thread(resolve, store.root, config, settings, name)
    if value is None:
        return {"name": name, "check": "not_set"}
    if name == "GEMINI_API_KEY":
        url = gemini + "/models/" + str(config["gemini_model"])
        status, _ = await http_check("GET", url, {"x-goog-api-key": value})
        ok = status == 200
    else:
        role = next(role for role, token in TOKENS.items() if token == name)
        headers = {"Authorization": "Bot " + value, "User-Agent": AGENT}
        status, body = await http_check("GET", discord + "/users/@me", headers)
        # The token must belong to the configured identity, compared as decimal text.
        ok = isinstance(body, dict) and str(body.get("id")) == str(config["bot_ids"][role])
    if ok:
        await asyncio.to_thread(mark_verified, store.root, name)
    return {"name": name, "check": "passed" if ok else "failed"}


async def send_test_message(store, role, confirmed, discord=DISCORD):
    """Opt-in REST post to the configured channel. Opens no gateway session."""
    if confirmed is not True:
        raise CapabilityError("Confirm the test message before sending")
    if role not in TOKENS:
        raise CapabilityError("Unknown bot")
    snapshot = await asyncio.to_thread(store.snapshot)
    config, settings = snapshot["config"], snapshot["settings"]
    value = await asyncio.to_thread(resolve, store.root, config, settings, TOKENS[role])
    if value is None:
        raise CapabilityError("Save this bot's token first")
    url = discord + "/channels/" + str(config["channel_id"]) + "/messages"
    headers = {"Authorization": "Bot " + value, "User-Agent": AGENT}
    body = {"content": TEST_MESSAGE, "allowed_mentions": {"parse": []}}
    status, _ = await http_check("POST", url, headers, body)
    return {"sent": status == 200}
