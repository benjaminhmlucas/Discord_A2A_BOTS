import ctypes
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from test_bridge import C, A, Author, Channel, Message
import botbridge_common as common
import botbridge_logging as logging
import bridge_privacy as privacy
import bridge_runtime as runtime
import bridge_settings as settings
import bridge_state as state
import bridge_windows as windows


def test_chunking_boundaries():
    assert common.chunk_message("") == [""]
    assert common.chunk_message("a" * 2200 + "\n" + "b" * 2200) == [
        "a" * 1900,
        "a" * 300,
        "b" * 1900,
        "b" * 300,
    ]
    assert common.chunk_message("a" * 600 + "\n" + "b" * 600, 1000) == ["a" * 600, "b" * 600]
    assert common.chunk_message(" " * 3000) == []


def test_logging_bytes_rotation_record_limit_cache_and_close(tmp_path):
    path = tmp_path / "fixture.log"
    logging.append_line(path, "one", max_bytes=128, backups=1)
    logging.append_line(path, "two", max_bytes=128, backups=1)
    assert path.read_bytes() == b"one\ntwo\n"
    logging.append_line(path, "\u03b1" * 400, max_bytes=128, backups=1)
    assert path.stat().st_size <= 128 and path.with_suffix(".log.1").exists()
    assert path.read_text().startswith("[log entry truncated]")
    handler = logging._handlers[(str(path.resolve()), 128, 1)]
    handler.delay = False
    logging.append_line(path, "x" * 126, max_bytes=128, backups=1)
    logging.close_handlers()
    logging.close_handlers()
    assert not logging._handlers


@pytest.mark.parametrize("size,backups", [(127, 1), (128, 0)])
def test_logging_invalid_limits(tmp_path, size, backups):
    with pytest.raises(ValueError):
        logging.append_line(tmp_path / "fixture.log", "x", size, backups)


def test_logging_error_preserves_exception():
    handler = logging._StrictRotatingHandler("unused.log", delay=True)
    try:
        raise OSError("synthetic write failure")
    except OSError:
        with pytest.raises(OSError, match="synthetic write"):
            handler.handleError(None)


@pytest.mark.parametrize(
    "mode",
    ["ok", "duplicate", "mutex_failure", "job_failure", "limit_failure", "assign_failure", "posix"],
)
def test_windows_process_protection_contract(mode):
    kernel = MagicMock()
    kernel.CreateMutexW.return_value = 0 if mode == "mutex_failure" else 10
    kernel.CreateJobObjectW.return_value = 0 if mode == "job_failure" else 20
    kernel.SetInformationJobObject.return_value = 0 if mode == "limit_failure" else 1
    kernel.AssignProcessToJobObject.return_value = 0 if mode == "assign_failure" else 1
    kernel.GetCurrentProcess.return_value = 42
    fake_os = SimpleNamespace(name="posix" if mode == "posix" else "nt", path=os.path)
    handles = []
    with (
        patch.object(windows, "os", fake_os),
        patch.object(windows, "_handles", handles),
        patch.object(ctypes, "WinDLL", return_value=kernel, create=True),
        patch.object(
            ctypes, "get_last_error", return_value=183 if mode == "duplicate" else 5, create=True
        ),
        patch.object(
            ctypes, "WinError", return_value=OSError("synthetic native error"), create=True
        ),
    ):
        if mode == "duplicate":
            with pytest.raises(SystemExit) as error:
                windows.protect_process("synthetic-lock")
            assert error.value.code == 75
        elif mode.endswith("failure"):
            with pytest.raises(OSError):
                windows.protect_process("synthetic-lock")
        else:
            windows.protect_process("synthetic-lock")
            assert handles == ([] if mode == "posix" else [10, 20])
            if mode == "ok":
                pointer = kernel.SetInformationJobObject.call_args.args[2]
                assert (
                    ctypes.cast(
                        pointer, ctypes.POINTER(windows.EXTENDED)
                    ).contents.BasicLimitInformation.LimitFlags
                    == 0x2000
                )


def test_settings_missing_and_invalid_identity(tmp_path):
    path = tmp_path / "config.json"
    with patch.object(settings, "config_path", return_value=path):
        with pytest.raises(RuntimeError, match="initialize"):
            settings.read_identity_config()
        for ids in (
            {"codex": 101, "antigravity": 101, "claude": 103},
            {"codex": 0, "antigravity": 102, "claude": 103},
        ):
            path.write_text(json.dumps({"bot_ids": ids}))
            with pytest.raises(ValueError):
                settings.read_identity_config()


def test_settings_paths_local_overrides_and_fallback(tmp_path):
    example = {"memory_dir": "private_memory"}
    (tmp_path / "local_settings.example.json").write_text(json.dumps(example))
    with patch.object(settings, "ROOT", tmp_path):
        assert settings.local_settings() == example
        assert settings.local_path("memory_dir") == tmp_path / "private_memory"
        local = {"memory_dir": str(tmp_path / "other")}
        (tmp_path / "local_settings.json").write_text(json.dumps(local))
        assert settings.local_settings() == local
        assert settings.local_path("memory_dir") == tmp_path / "other"
        with patch.dict(os.environ, BOTBRIDGE_CONFIG_FILE="synthetic-config.json"):
            assert settings.config_path(tmp_path) == Path("synthetic-config.json")
            assert (
                settings.config_path(tmp_path / "separate")
                == tmp_path / "separate/bridge_config.json"
            )
        with patch.dict(os.environ, {}, clear=True):
            assert settings.config_path(tmp_path) == tmp_path / "bridge_config.json"


def test_privacy_empty_sources_symlinks_empty_markers_and_bad_input(tmp_path):
    p = privacy.Privacy(tmp_path)
    with pytest.raises(RuntimeError, match="unavailable"):
        p.refresh()
    file = tmp_path / "fixture.md"
    file.write_text("<!--PRIVATE:START-->   <!--PRIVATE:END-->")
    p.refresh()
    assert p.refresh() == ()
    assert p.filter("harmless") == "harmless"
    with pytest.raises(RuntimeError, match="Malformed private text"):
        p.filter("<!--PRIVATE:END-->")
    with patch.object(Path, "is_symlink", return_value=True):
        with pytest.raises(RuntimeError, match="symlink"):
            p.refresh()


@pytest.mark.parametrize(
    "change",
    [
        {"bot_ids": {"codex": 11, "antigravity": 12, "claude": 13}},
        {"owner_id": 0},
        {"channel_id": 0},
        {"allowed_user_ids": []},
        {"allowed_user_ids": [0]},
        {"enabled_bots": [C, C]},
        {"enabled_bots": []},
        {"enabled_bots": [999]},
        {"queue_capacity": 0},
        {"queue_capacity": "bad"},
        {"max_turns": 16},
    ],
)
def test_config_validation(tmp_path, change):
    config = json.loads((Path(__file__).parent / "fixtures/bridge_config.json").read_text())
    config.update(change)
    (tmp_path / "bridge_config.json").write_text(json.dumps(config))
    with pytest.raises(ValueError):
        runtime.load_config(tmp_path)


def test_state_invalid_transitions_claims_and_root_lookup(tmp_path):
    config = json.loads((Path(__file__).parent / "fixtures/bridge_config.json").read_text())
    database = state.State(tmp_path / "state.sqlite3", config)
    message = Message(1, "topic", Channel())
    with pytest.raises(RuntimeError, match="Unknown"):
        database.root_message("absent")
    sid, _ = database.start(message, C, 3)
    assert database.root_message(sid) == 1
    for identity, target in ((A, C), (C, C), (C, 999)):
        with pytest.raises(RuntimeError):
            database.advance(sid, identity, target)
    with pytest.raises(RuntimeError):
        database.advance("absent", C, A)
    assert database.claim(message, C) is None
    marker = database.advance(sid, C, A)
    bot_message = Message(2, marker, message.channel, Author(C, True))
    assert database.claim(bot_message, 103) is None
    bot_message.author = Author(103, True)
    assert database.claim(bot_message, A) is None
    bot_message.content = marker.replace(":2]", ":99]")
    assert database.claim(bot_message, A) is None
    database.fail(sid)
    with pytest.raises(RuntimeError):
        database.advance(sid, C, A)
