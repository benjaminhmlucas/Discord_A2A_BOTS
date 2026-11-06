"""Setup checklist, installs, preflight and provider checks against real configuration."""

import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
from unittest.mock import patch

from aiohttp import web
import pytest

import bridge_control_setup as setup
from bridge_credentials import CredentialStore
from bridge_errors import CapabilityError
from test_control_config import configured
from test_runtime_credentials import Backend

ROOT = Path(__file__).resolve().parent.parent
TOKEN = "synthetic-control-setup-token-51c2"
KEY = "synthetic-control-setup-gemini-9d0e"


def environment(**values):
    """Synthetic legacy environment; the real process/User registry is never read."""
    return patch.object(setup, "legacy", lambda name: values.get(name))


class FakeVenv(setup.Platform):
    """Points the checkout venv at this interpreter; everything else is the real adapter."""

    def __init__(self, python=sys.executable, npm=None):
        super().__init__()
        self.python, self.npm_path = Path(python), npm

    def venv_python(self, root):
        return self.python

    def npm(self, node):
        return self.npm_path or super().npm(node)


def settings(store, **values):
    snapshot = store.snapshot()
    data = {**snapshot["settings"], **values}
    store.save("local_settings.json", data, snapshot["revisions"]["local_settings.json"])


def roster(store, enabled):
    snapshot = store.snapshot()
    config = snapshot["config"]
    config["enabled_bots"] = enabled
    store.save("bridge_config.json", config, snapshot["revisions"]["bridge_config.json"])


def test_platform_adapter_paths_and_quiet_exit_status(tmp_path):
    windows, posix = setup.Platform("nt"), setup.Platform("posix")
    assert windows.venv_python(tmp_path) == tmp_path / ".venv/Scripts/python.exe"
    assert posix.venv_python(tmp_path) == tmp_path / ".venv/bin/python"
    node = tmp_path / "bin" / "node"
    assert windows.npm(node) == tmp_path / "bin/node_modules/npm/bin/npm-cli.js"
    assert posix.npm(node) == tmp_path / "lib/node_modules/npm/bin/npm-cli.js"
    assert "manage.py setup" in windows.setup_command()
    assert "requirements.txt" in posix.setup_command()
    assert setup.Platform().windows is (os.name == "nt")
    assert (
        setup.quiet([sys.executable, "-c", "print('private'); raise SystemExit(3)"], tmp_path) == 3
    )
    assert setup.quiet([tmp_path / "missing-executable"], tmp_path) is None
    assert setup.quiet([sys.executable, "-c", "import time; time.sleep(5)"], tmp_path, 0.2) is None


def test_readme_documents_the_same_pinned_cli_versions():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for folder, package, version, _ in setup.CLIS.values():
        assert f"npm install --prefix {folder} {package}@{version}" in readme


def test_checklist_fresh_clone_then_configured_steps(tmp_path):
    fresh = tmp_path / "fresh"
    fresh.mkdir()
    from bridge_control_config import ControlConfig

    status = setup.checklist(ControlConfig(fresh), FakeVenv(fresh / "missing-python"))
    assert [(s["id"], s["state"]) for s in status["steps"]] == [
        ("venv", "action"),
        ("dependencies", "action"),
        ("identities", "action"),
    ]
    assert status["ready"] is False and status["steps"][2]["fix"] == {"screen": "Setup"}

    (tmp_path / "installed").mkdir()
    store = configured(tmp_path / "installed")
    root = store.root
    import importlib.metadata

    pinned = importlib.metadata.version("aiohttp")
    other = "linux" if sys.platform != "linux" else "win32"
    (root / "requirements.txt").write_text(
        f"# comment\naiohttp=={pinned}\nabsent-package==1; sys_platform == '{other}'\n",
        encoding="utf-8",
    )
    settings(store, node_executable=sys.executable)
    with environment():
        status = setup.checklist(store, FakeVenv())
    states = {s["id"]: s["state"] for s in status["steps"]}
    assert states["venv"] == states["dependencies"] == states["node"] == "ok"
    assert states["pm2"] == states["codex_cli"] == states["CODEXBOT_TOKEN"] == "action"
    assert states["preflight"] == "not_run" and status["ready"] is False

    for folder in (
        "tools/pm2/node_modules/pm2/bin",
        "tools/codex-cli/node_modules/@openai/codex/bin",
    ):
        (root / folder).mkdir(parents=True)
    (root / "tools/pm2/node_modules/pm2/bin/pm2").write_text("", encoding="utf-8")
    (root / "tools/codex-cli/node_modules/@openai/codex/bin/codex.js").write_text("")
    (root / "requirements.txt").write_text("absent-package==1\n", encoding="utf-8")
    roster(store, [101])
    with environment(CODEXBOT_TOKEN=TOKEN):
        status = setup.checklist(store, FakeVenv())
    states = {s["id"]: s["state"] for s in status["steps"]}
    assert states["dependencies"] == "action"
    assert states["pm2"] == states["codex_cli"] == states["CODEXBOT_TOKEN"] == "ok"
    assert states["claude_cli"] == states["GEMINI_API_KEY"] == "not_needed"
    assert TOKEN not in json.dumps(status)
    (root / "requirements.txt").write_text(f"aiohttp=={pinned}\n", encoding="utf-8")
    with environment(CODEXBOT_TOKEN=TOKEN):
        assert setup.checklist(store, FakeVenv())["ready"] is True


def test_native_selected_credentials_report_store_state(tmp_path):
    store = configured(tmp_path)
    # Selecting a native reference makes saves scan that store; keep it in memory so the
    # test never depends on the host having a native credential service.
    with patch.object(CredentialStore, "_backend", return_value=Backend()):
        settings(store, runtime_credentials=["CODEXBOT_TOKEN"])
        snapshot = store.snapshot()

    class Native:
        def __init__(self, config, root):
            assert root == store.root

        def status(self, name):
            return {"state": "set"}

        def optional(self, name):
            return TOKEN

    with patch.object(setup, "RuntimeCredentials", Native), environment():
        args = (store.root, snapshot["config"], snapshot["settings"])
        assert setup.credential_state(*args, "CODEXBOT_TOKEN") == {
            "state": "set",
            "source": "native",
        }
        assert setup.credential_state(*args, "GEMINI_API_KEY") == {
            "state": "not_set",
            "source": "environment",
        }
        assert setup.resolve(*args, "CODEXBOT_TOKEN") == TOKEN
        assert setup.resolve(*args, "GEMINI_API_KEY") is None


def test_pinned_installs_use_readme_commands(tmp_path):
    store = configured(tmp_path)
    root = store.root
    (root / "dependencies/pm2").mkdir(parents=True)
    for name in ("package.json", "package-lock.json"):
        (root / "dependencies/pm2" / name).write_bytes(
            (ROOT / "dependencies/pm2" / name).read_bytes()
        )
    settings(store, node_executable=sys.executable)
    with pytest.raises(CapabilityError, match="Install Node.js"):
        setup.install(store, "pm2", FakeVenv(npm=tmp_path / "missing-npm.js"))
    npm = tmp_path / "npm-cli.js"
    npm.write_text("", encoding="utf-8")
    calls = []
    with patch.object(
        setup, "run", lambda command, cwd, env, timeout: calls.append((command, timeout))
    ):
        assert setup.install(store, "pm2", FakeVenv(npm=npm)) == {"installed": "pm2"}
        assert setup.install(store, "claude", FakeVenv(npm=npm)) == {"installed": "claude"}
        with pytest.raises(CapabilityError, match="Unknown installation"):
            setup.install(store, "other", FakeVenv(npm=npm))
    node = Path(sys.executable)
    assert calls == [
        ([node, npm, "ci", "--prefix", root / "tools/pm2"], 600),
        (
            [
                node,
                npm,
                "install",
                "--prefix",
                root / "tools/claude-cli",
                "@anthropic-ai/claude-code@2.1.112",
            ],
            600,
        ),
    ]
    assert (root / "tools/pm2/package-lock.json").read_bytes() == (
        ROOT / "dependencies/pm2/package-lock.json"
    ).read_bytes()

    def failed(command, cwd, env, timeout):
        raise subprocess.CalledProcessError(1, command)

    with (
        patch.object(setup, "run", failed),
        pytest.raises(CapabilityError, match="Installation failed"),
    ):
        setup.install(store, "codex", FakeVenv(npm=npm))


def test_preflight_reports_only_its_exit_status(tmp_path):
    store = configured(tmp_path)
    assert setup.preflight(store, FakeVenv(tmp_path / "missing")) == {"preflight": "unavailable"}
    assert setup.preflight(store) == {"preflight": "unavailable"}
    script = store.root / "preflight.py"
    script.write_text("print('private detail'); raise SystemExit(0)\n", encoding="utf-8")
    assert setup.preflight(store, FakeVenv()) == {"preflight": "passed"}
    script.write_text("raise SystemExit(1)\n", encoding="utf-8")
    assert setup.preflight(store, FakeVenv()) == {"preflight": "failed"}


def test_provider_status_versions_and_cli_login_state(tmp_path):
    store = configured(tmp_path)
    root = store.root
    package = root / "tools/codex-cli/node_modules/@openai/codex/package.json"
    package.parent.mkdir(parents=True)
    package.write_text(json.dumps({"version": "0.159.3"}), encoding="utf-8")
    broken = root / "tools/claude-cli/node_modules/@anthropic-ai/claude-code/package.json"
    broken.parent.mkdir(parents=True)
    broken.write_text("{", encoding="utf-8")
    setup.mark_verified(root, "GEMINI_API_KEY")
    with environment(GEMINI_API_KEY=KEY):
        data = setup.providers(store)["providers"]
    assert data["codex"]["installed"] == data["codex"]["pinned"] == "0.159.3"
    assert data["claude"]["installed"] is None and data["claude"]["pinned"] == "2.1.112"
    gemini = data["antigravity"]["credentials"]["GEMINI_API_KEY"]
    assert gemini["state"] == "set" and gemini["source"] == "environment"
    assert isinstance(gemini["verified"], float)
    assert data["antigravity"]["credentials"]["ANTIGRAVITYBOT_TOKEN"]["verified"] is None
    assert "model" in data["codex"] and "reasoning_effort" in data["codex"]
    assert KEY not in json.dumps(data)
    (root / "runtime_state/control_verified.json").write_text("[]", encoding="utf-8")
    assert setup.verified(root) == {}

    with pytest.raises(CapabilityError, match="Unknown provider"):
        setup.login_status(store, "antigravity")
    assert setup.login_status(store, "codex") == {"login": "not_installed"}
    cli = tmp_path / "status.py"
    cli.write_text(
        "import sys; print('account@example.invalid'); sys.exit(sys.argv[1:] != ['login', 'status'])\n"
    )
    settings(store, node_executable=sys.executable, codex_cli=str(cli), claude_cli=str(cli))
    assert setup.login_status(store, "codex") == {"login": "signed_in"}
    assert setup.login_status(store, "claude") == {"login": "not_signed_in"}
    with patch.object(setup, "quiet", lambda *args, **kwargs: None):
        assert setup.login_status(store, "codex") == {"login": "unavailable"}


class FakeAPIs:
    """Loopback Discord and Gemini endpoints that check the presented credentials."""

    def __init__(self):
        self.posts = []

    async def __aenter__(self):
        app = web.Application()
        app.router.add_get("/discord/users/@me", self.me)
        app.router.add_post("/discord/channels/{channel}/messages", self.message)
        app.router.add_get("/gemini/models/{model}", self.model)
        self.runner = web.AppRunner(app, access_log=None)
        await self.runner.setup()
        await web.TCPSite(self.runner, "127.0.0.1", 0).start()
        origin = "http://127.0.0.1:" + str(self.runner.addresses[0][1])
        self.discord, self.gemini = origin + "/discord", origin + "/gemini"
        return self

    async def __aexit__(self, *args):
        await self.runner.cleanup()

    async def me(self, request):
        assert request.headers["User-Agent"].startswith("DiscordBot (")
        if request.headers.get("Authorization") != "Bot " + TOKEN:
            return web.json_response({"message": "401: Unauthorized"}, status=401)
        return web.json_response({"id": "101", "username": "fixture"})

    async def message(self, request):
        if request.headers.get("Authorization") != "Bot " + TOKEN:
            return web.Response(status=403)
        self.posts.append((request.match_info["channel"], await request.json()))
        return web.json_response({"id": "1"})

    async def model(self, request):
        ok = request.headers.get("x-goog-api-key") == KEY
        return web.json_response({"name": request.match_info["model"]}, status=200 if ok else 403)


def test_credential_checks_and_opt_in_message_never_return_values(tmp_path):
    store = configured(tmp_path)

    async def scenario():
        async with FakeAPIs() as apis:
            urls = {"discord": apis.discord, "gemini": apis.gemini}
            with environment():
                assert await setup.verify(store, "CODEXBOT_TOKEN", **urls) == {
                    "name": "CODEXBOT_TOKEN",
                    "check": "not_set",
                }
            with environment(CODEXBOT_TOKEN=TOKEN, ANTIGRAVITYBOT_TOKEN=TOKEN, GEMINI_API_KEY=KEY):
                passed = await setup.verify(store, "CODEXBOT_TOKEN", **urls)
                assert passed == {"name": "CODEXBOT_TOKEN", "check": "passed"}
                assert await setup.verify(store, "GEMINI_API_KEY", **urls) == {
                    "name": "GEMINI_API_KEY",
                    "check": "passed",
                }
                # A valid token for a different configured identity does not verify.
                assert (await setup.verify(store, "ANTIGRAVITYBOT_TOKEN", **urls))[
                    "check"
                ] == "failed"
                with pytest.raises(CapabilityError, match="no connectivity check"):
                    await setup.verify(store, "CLAUDE_CODE_OAUTH_TOKEN", **urls)
                closed = {"discord": "http://127.0.0.1:9", "gemini": "http://127.0.0.1:9"}
                assert (await setup.verify(store, "CODEXBOT_TOKEN", **closed))["check"] == "failed"
                with pytest.raises(CapabilityError, match="Confirm"):
                    await setup.send_test_message(store, "codex", False, apis.discord)
                with pytest.raises(CapabilityError, match="Unknown bot"):
                    await setup.send_test_message(store, "nobody", True, apis.discord)
                with pytest.raises(CapabilityError, match="Save this"):
                    await setup.send_test_message(store, "claude", True, apis.discord)
                sent = await setup.send_test_message(store, "codex", True, apis.discord)
                assert sent == {"sent": True}
            with environment(GEMINI_API_KEY="wrong", CODEXBOT_TOKEN="wrong"):
                assert (await setup.verify(store, "GEMINI_API_KEY", **urls))["check"] == "failed"
                assert await setup.send_test_message(store, "codex", True, apis.discord) == {
                    "sent": False
                }
            assert apis.posts == [
                ("301", {"content": setup.TEST_MESSAGE, "allowed_mentions": {"parse": []}})
            ]
            stamps = setup.verified(store.root)
            assert set(stamps) == {"CODEXBOT_TOKEN", "GEMINI_API_KEY"}
            text = (store.root / "runtime_state/control_verified.json").read_text()
            assert TOKEN not in text and KEY not in text

    asyncio.run(scenario())
