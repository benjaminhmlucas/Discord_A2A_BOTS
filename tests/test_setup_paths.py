import json
import os
import runpy
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from test_setup import module, release, logrotate

ROOT = Path(__file__).resolve().parent.parent
manage = module("manage_setup", "scripts/manage.py")


def installation(root, absolute=False):
    for name in (".venv/Scripts/python.exe", "node", "tools/pm2/pm2.js"):
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("synthetic fixture")
    settings = {
        "node_executable": str(root / "node") if absolute else "node",
        "pm2_cli": str(root / "tools/pm2/pm2.js") if absolute else "tools/pm2/pm2.js",
    }
    (root / "local_settings.json").write_text(json.dumps(settings))


def test_setup_subprocesses_receive_scoped_paths_and_stop_on_failures(tmp_path):
    proc = MagicMock()
    proc.__enter__.return_value = proc
    proc.wait.return_value = 0
    with patch.object(manage.subprocess, "Popen", return_value=proc) as run:
        manage.manage("setup", tmp_path)
        assert run.call_count == 3
        for call in run.call_args_list:
            assert call.kwargs["cwd"] == tmp_path.resolve()
            assert call.kwargs["env"]["PM2_HOME"] == str(tmp_path.resolve() / ".pm2")
            assert call.kwargs["start_new_session"] == (os.name != "nt")
            assert not call.kwargs.get("shell", False)


@pytest.mark.parametrize("outcome", ["success", "failure", "timeout"])
def test_manage_run_exit_and_deadline_contract(tmp_path, outcome):
    proc = MagicMock()
    proc.__enter__.return_value = proc
    proc.wait.side_effect = (
        subprocess.TimeoutExpired(["synthetic"], 0.1) if outcome == "timeout" else None
    )
    proc.wait.return_value = 1 if outcome == "failure" else 0
    with (
        patch.object(manage.subprocess, "Popen", return_value=proc),
        patch.object(manage, "stop_command") as stop,
    ):
        if outcome == "success":
            assert manage.run(["synthetic"], tmp_path, {}, timeout=0.1).returncode == 0
        else:
            expected = (
                subprocess.TimeoutExpired if outcome == "timeout" else subprocess.CalledProcessError
            )
            with pytest.raises(expected):
                manage.run(["synthetic"], tmp_path, {}, timeout=0.1)
        assert stop.call_count == (1 if outcome == "timeout" else 0)


@pytest.mark.parametrize(
    "mode",
    [
        "already_done",
        "windows_done",
        "windows_fallback",
        "windows_error",
        "windows_timeout",
        "posix_done",
        "posix_race",
    ],
)
def test_manage_cleanup_targets_only_the_owned_live_command(mode):
    proc = MagicMock(pid=42)
    proc.poll.side_effect = (
        [0]
        if mode == "already_done"
        else [None, None if mode in ("windows_fallback", "windows_error", "windows_timeout") else 0]
    )
    platform = "posix" if mode.startswith("posix") else "nt"
    failure = (
        OSError("synthetic")
        if mode == "windows_error"
        else subprocess.TimeoutExpired(["synthetic"], 10)
        if mode == "windows_timeout"
        else None
    )
    with (
        patch.object(
            manage,
            "os",
            SimpleNamespace(
                name=platform,
                environ={},
                killpg=MagicMock(
                    side_effect=ProcessLookupError() if mode == "posix_race" else None
                ),
            ),
        ) as operating,
        patch.object(manage, "signal", SimpleNamespace(SIGKILL=9)),
        patch.object(manage.subprocess, "run", side_effect=failure) as kill,
    ):
        manage.stop_command(proc)
        if mode == "already_done":
            kill.assert_not_called()
            proc.wait.assert_not_called()
        elif platform == "nt":
            assert kill.call_args.args[0][-4:] == ["/PID", "42", "/T", "/F"]
            assert kill.call_args.kwargs["timeout"] == 10
        else:
            operating.killpg.assert_called_once_with(42, manage.signal.SIGKILL)
        assert proc.kill.call_count == (
            1 if mode in ("windows_fallback", "windows_error", "windows_timeout") else 0
        )


@pytest.mark.parametrize(
    "action,index", [("setup", i) for i in range(3)] + [("start", i) for i in range(7)]
)
def test_each_setup_and_start_failure_aborts_before_later_steps(tmp_path, action, index):
    installation(tmp_path)
    attempts = []

    def fail(command, root, env):
        attempts.append(command)
        if len(attempts) == index + 1:
            raise subprocess.CalledProcessError(1, ["synthetic-command"])

    with (
        patch.object(manage, "run", side_effect=fail),
        patch.object(manage.shutil, "which", return_value=None),
    ):
        with pytest.raises(subprocess.CalledProcessError):
            manage.manage(action, tmp_path)
    assert len(attempts) == index + 1
    if action == "start" and index < 6:
        assert not any("ecosystem.config.js" in str(arg) for command in attempts for arg in command)


@pytest.mark.parametrize("absolute", [False, True])
def test_start_complete_order_no_shell_and_no_automatic_save(tmp_path, absolute):
    installation(tmp_path, absolute)
    with (
        patch.object(manage, "run") as run,
        patch.object(
            manage.shutil, "which", return_value=str(tmp_path / "node") if absolute else None
        ),
    ):
        manage.manage("start", tmp_path)
        commands = [call.args[0] for call in run.call_args_list]
        assert len(commands) == 7
        assert commands[0][-1] == tmp_path / "preflight.py"
        assert commands[-1][-2:] == ["start", tmp_path / "ecosystem.config.js"]
        assert not any("save" in command for command in commands)
        assert all(
            call.args[2]["PM2_HOME"] == str(tmp_path / ".pm2") for call in run.call_args_list
        )


@pytest.mark.parametrize(
    "arguments,expected",
    [
        ([], "0"),
        (["list"], "0"),
        (["restart", "synthetic"], "1"),
        (["--silent", "stop", "synthetic"], "1"),
        (["-s", "--no-color", "save"], "1"),
        (["--silent", "list"], "0"),
        (["--namespace", "stop", "list"], "0"),
        (["--namespace=stop", "restart", "synthetic"], "1"),
        (["--watch", "--name", "stop", "list"], "0"),
        (["--watch", "path", "restart", "synthetic"], "1"),
        (["--watch"], "0"),
        (["--name"], "0"),
        (["--unknown", "stop"], "0"),
        (["--", "stop", "synthetic"], "1"),
        (["--"], "0"),
    ],
)
def test_manage_metadata_mode_is_limited_to_operations(tmp_path, arguments, expected):
    installation(tmp_path)
    with (
        patch.dict(os.environ, {"BOTBRIDGE_PM2_METADATA_ONLY": "0"}),
        patch.object(manage, "run") as run,
        patch.object(manage.shutil, "which", return_value=None),
    ):
        manage.manage("pm2", tmp_path, arguments)
    assert run.call_args.args[2]["BOTBRIDGE_PM2_METADATA_ONLY"] == expected
    assert run.call_args.args[0][-len(arguments) :] == arguments if arguments else True


def test_start_requires_python_node_and_pm2(tmp_path):
    with pytest.raises(ValueError):
        manage.manage("unrecognized", tmp_path)
    with pytest.raises(RuntimeError, match="venv"):
        manage.manage("start", tmp_path)
    installation(tmp_path)
    with patch.object(manage, "run"), patch.object(manage.shutil, "which", return_value=None):
        (tmp_path / "node").unlink()
        with pytest.raises(RuntimeError, match="Node"):
            manage.manage("start", tmp_path)
        (tmp_path / "node").write_text("fixture")
        (tmp_path / "tools/pm2/pm2.js").unlink()
        with pytest.raises(RuntimeError, match="Node"):
            manage.manage("start", tmp_path)


def test_manager_cli_dispatch_and_help():
    with (
        patch.object(
            manage.argparse.ArgumentParser,
            "parse_args",
            return_value=SimpleNamespace(action="setup", pm2_args=[]),
        ),
        patch.object(manage, "manage") as call,
    ):
        manage.main()
        call.assert_called_once_with("setup", pm2_args=[])
    with patch.object(sys, "argv", ["manage.py", "--help"]):
        with pytest.raises(SystemExit) as stopped:
            runpy.run_path(str(ROOT / "scripts/manage.py"), run_name="__main__")
        assert stopped.value.code == 0


def test_pm2_commands_always_use_the_namespace_preload(tmp_path):
    installation(tmp_path)
    with (
        patch.object(manage, "run") as run,
        patch.object(manage.shutil, "which", return_value=None),
    ):
        manage.manage("pm2", tmp_path, ["list"])
        assert run.call_count == 1
        command, root, env = run.call_args.args
        assert command[-1] == "list"
        assert env["NODE_OPTIONS"] == "--require=" + json.dumps(
            str(tmp_path / "scripts/pm2_namespace.cjs")
        )


@pytest.mark.parametrize(
    "name,reason",
    [
        ("bridge_config.json", "private/local file"),
        ("auth.json", "private/local file"),
        (".env.production", "credential/process configuration"),
        ("dump.pm2.bak", "credential/process configuration"),
        ("fixture.log.1", "runtime/credential/archive file"),
        ("fixture.zip", "runtime/credential/archive file"),
        ("ordinary.md", None),
        (".env.example", None),
        ("tests/fixtures/bridge_config.json", None),
    ],
)
def test_release_path_classes(name, reason):
    assert release.check_path(Path(name)) == reason


@pytest.mark.parametrize("kind", ["empty", "oversize", "binary", "unicode", "symlink", "clean"])
def test_release_tree_errors_are_findings(tmp_path, kind):
    file = tmp_path / "fixture.txt"
    if kind == "oversize":
        file.write_bytes(b"x" * 2_000_001)
    elif kind == "binary":
        file.write_bytes(b"\0fixture")
    elif kind == "unicode":
        file.write_bytes(b"\xfffixture")
    elif kind != "empty":
        file.write_text("synthetic fixture")
    with patch.object(Path, "is_symlink", return_value=kind == "symlink"):
        count, failures = release.scan(tmp_path)
    assert bool(failures) == (kind != "clean")
    assert count == (0 if kind == "empty" else 1)


def test_release_git_file_list_and_skipped_cache_directories(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "fixture.txt").write_text("fixture")
    with patch.object(
        release.subprocess, "run", return_value=SimpleNamespace(stdout=b"fixture.txt\0\0")
    ):
        assert release.scan(tmp_path) == (1, [])
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__/fixture.pyc").write_text("fixture")
    (tmp_path / "fixture.pyc").write_text("fixture")
    original_exists = Path.exists
    with patch.object(
        Path, "exists", lambda path: False if path.name == ".git" else original_exists(path)
    ):
        assert release.scan(tmp_path) == (1, [])


@pytest.mark.parametrize(
    "names,code", [(b"README.md\0", 0), (b"bridge_config.json\0", 1), (b"", 1)]
)
def test_release_cli_exit_contract(names, code):
    original_exists = Path.exists
    with (
        patch.object(
            Path, "exists", lambda path: True if path.name == ".git" else original_exists(path)
        ),
        patch.object(subprocess, "run", return_value=SimpleNamespace(stdout=names)),
    ):
        with pytest.raises(SystemExit) as stopped:
            runpy.run_path(str(ROOT / "scripts/check_release.py"), run_name="__main__")
        assert stopped.value.code == code


def test_logrotate_unrecognized_parser_existing_backup_and_cli(tmp_path):
    (tmp_path / "package.json").write_text('{"version":"3.0.0"}')
    path = tmp_path / "app.js"
    path.write_text("unexpected source")
    with pytest.raises(RuntimeError, match="Unrecognized"):
        logrotate.patch(tmp_path)
    old = "const parseBool = (str, defaultVal = false) => {\n  return str.toLowerCase() === 'true';\n};\n"
    path.write_text(old)
    (tmp_path / "app.js.bak").write_text("earlier preserved fixture")
    logrotate.patch(tmp_path)
    assert (tmp_path / "app.js.bak").read_text() == "earlier preserved fixture"
    original_read = Path.read_text

    def read(path, *args, **kwargs):
        if path.name == "package.json":
            return '{"version":"3.0.0"}'
        if path.name == "app.js":
            return logrotate.FIX
        return original_read(path, *args, **kwargs)

    with patch.object(Path, "read_text", read):
        runpy.run_path(str(ROOT / "scripts/fix_logrotate.py"), run_name="__main__")
