import json
import os
import runpy
import stat
import sys
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
import log_manager as manager


def config(root):
    return {
        "aggregate_limit_bytes": 1000,
        "cleanup_trigger_bytes": 800,
        "cleanup_target_bytes": 600,
        "max_active_file_bytes": 400,
        "active_tail_bytes": 100,
        "archive_max_age_days": 14,
        "interval_seconds": 1,
        "state_file": str(root / "state.json"),
        "scopes": [{"directory": str(root), "include_transcripts": True}],
    }


def log(root, name, size, old=False):
    path = root / name
    path.write_bytes(b"x\n" * (size // 2) + b"x" * (size % 2))
    if old:
        os.utime(path, (time.time() - 15 * 86400,) * 2)
    return path


@pytest.mark.parametrize(
    "change",
    [
        {},
        {"cleanup_target_bytes": 900},
        {"active_tail_bytes": 0},
        {"active_tail_bytes": 401},
        {"max_active_file_bytes": 600},
        {"interval_seconds": 0},
        {"interval_seconds": 61},
    ],
)
def test_config_limits(tmp_path, change):
    data = config(tmp_path)
    data.update(change)
    path = tmp_path / "config.json"
    path.write_text(json.dumps(data))
    if change:
        with pytest.raises(ValueError):
            manager.load_config(path)
    else:
        assert manager.load_config(path) == data


def test_scoped_inventory_preserves_unrelated_files_and_deduplicates(tmp_path):
    for name in (
        "a.log",
        "a.log.1",
        "a.log.gz",
        "incoming.md",
        "incoming.md.1",
        "codex_incoming.md",
        "codex_discord_log.md",
        "source.py",
        "secret.json",
    ):
        log(tmp_path, name, 20)
    (tmp_path / "subdirectory").mkdir()
    log(tmp_path / "subdirectory", "unrelated.log", 20)
    data = config(tmp_path)
    data["scopes"].append(data["scopes"][0])
    items = manager.inventory(data)
    assert len(items) == 7
    assert len({i["path"] for i in items}) == 7
    assert not any("source.py" in i["path"] or "subdirectory" in i["path"] for i in items)
    data["scopes"] = [{"directory": str(tmp_path), "include_transcripts": False}]
    assert len(manager.inventory(data)) == 3


def test_inventory_concurrent_missing_symlink_reparse_and_bad_parent(tmp_path):
    entry = MagicMock()
    entry.name = "fixture.log"
    with patch.object(Path, "iterdir", return_value=[entry]):
        entry.lstat.side_effect = FileNotFoundError()
        assert manager.inventory(config(tmp_path)) == []
        entry.lstat.side_effect = None
        entry.lstat.return_value = SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0x400)
        entry.is_symlink.return_value = False
        assert manager.inventory(config(tmp_path)) == []
        entry.lstat.return_value = SimpleNamespace(st_mode=stat.S_IFREG, st_file_attributes=0)
        entry.is_symlink.return_value = True
        assert manager.inventory(config(tmp_path)) == []
        entry.is_symlink.return_value = False
        entry.name = "fixture.log"
        entry.parent.resolve.return_value = tmp_path / "outside"
        with pytest.raises(ValueError, match="Unexpected"):
            manager.inventory(config(tmp_path))
        errors = []
        assert manager.inventory(config(tmp_path), errors) == []
        assert errors[0]["error"] == "ValueError"


def test_inventory_denied_entry_does_not_block_other_cleanup(tmp_path):
    denied = log(tmp_path, "denied.log", 20)
    good = log(tmp_path, "good.log", 500)
    original = Path.lstat

    def lstat(path):
        if path == denied:
            raise PermissionError("synthetic metadata denial")
        return original(path)

    with patch.object(Path, "lstat", lstat):
        with pytest.raises(PermissionError):
            manager.inventory(config(tmp_path))
        state = manager.enforce(config(tmp_path))
    assert good.stat().st_size <= 100
    assert denied.stat().st_size == 20
    assert state["status"] == "error" and state["inventory_complete"] is False
    assert all(error["path"] == str(denied) for error in state["errors"])
    assert manager.enforce(config(tmp_path))["inventory_complete"] is True


def test_inventory_denied_or_missing_scope_continues_other_scopes(tmp_path):
    good = log(tmp_path, "good.log", 500)
    data = config(tmp_path)
    data["scopes"].insert(0, {"directory": str(tmp_path / "missing")})
    with pytest.raises(FileNotFoundError):
        manager.inventory(data)
    state = manager.enforce(data)
    assert good.stat().st_size <= 100
    assert state["status"] == "error" and not state["inventory_complete"]


def test_checked_path_rejects_changed_identity(tmp_path):
    path = log(tmp_path, "a.log", 20)
    item = {"path": str(path), "scope": str(tmp_path)}
    assert manager._checked_path(item) == path
    with pytest.raises(ValueError):
        manager._checked_path({"path": str(path), "scope": str(tmp_path / "other")})
    with patch.object(Path, "is_symlink", return_value=True):
        with pytest.raises(ValueError):
            manager._checked_path(item)
    with pytest.raises(ValueError):
        manager._checked_path({"path": str(tmp_path), "scope": str(tmp_path.parent)})


def test_trim_tail_line_boundaries_empty_and_no_newline(tmp_path):
    path = log(tmp_path, "a.log", 20)
    item = manager.inventory(config(tmp_path))[0]
    assert manager.trim_tail(item, 40) == 0
    assert manager.trim_tail(item, 9) >= 11
    assert path.stat().st_size <= 9
    path.write_bytes(b"x" * 20)
    assert manager.trim_tail(item, 10) == 10
    assert path.read_bytes() == b"x" * 10
    assert manager.trim_tail(item, 0) == 10
    assert path.stat().st_size == 0


def test_age_and_oversize_cleanup(tmp_path):
    log(tmp_path, "large.log", 500)
    old = log(tmp_path, "old.log.1", 20, old=True)
    protected = log(tmp_path, "source.py", 2000)
    state = manager.enforce(config(tmp_path))
    assert state["status"] == "ok" and state["current_bytes"] <= 100
    assert not old.exists() and protected.stat().st_size == 2000
    assert {a["action"] for a in state["actions"]} == {"trim_oversize", "expire_archive"}


@pytest.mark.parametrize("archives", [True, False])
def test_aggregate_cleanup(tmp_path, archives):
    for n in range(3):
        log(tmp_path, f"{n}.log" + (".1" if archives else ""), 380)
    state = manager.enforce(config(tmp_path))
    assert state["status"] == "ok" and state["current_bytes"] <= 600
    assert state["cleanup_required"]
    assert any(
        a["action"] == ("prune_archive" if archives else "trim_budget") for a in state["actions"]
    )


@pytest.mark.parametrize(
    "exception", [OSError("synthetic failure"), FileNotFoundError("concurrent removal")]
)
def test_oversize_and_expiry_races(tmp_path, exception):
    log(tmp_path, "oversize.log", 500)
    log(tmp_path, "old.log.1", 20, old=True)
    with (
        patch.object(manager, "trim_tail", side_effect=exception),
        patch.object(Path, "unlink", side_effect=exception),
    ):
        state = manager.enforce(config(tmp_path))
    assert bool(state["errors"]) == (type(exception) is OSError)


@pytest.mark.parametrize(
    "exception", [OSError("synthetic failure"), FileNotFoundError("concurrent removal")]
)
def test_budget_archive_races(tmp_path, exception):
    for n in range(3):
        log(tmp_path, f"{n}.log.1", 400)
    with patch.object(Path, "unlink", side_effect=exception):
        state = manager.enforce(config(tmp_path))
    assert (
        state["status"] == "error"
    )  # Fixture leaves files present; final rescan detects overshoot.
    assert bool(state["errors"]) == (type(exception) is OSError)


@pytest.mark.parametrize(
    "exception", [OSError("synthetic failure"), FileNotFoundError("concurrent removal")]
)
def test_budget_active_races(tmp_path, exception):
    for n in range(3):
        log(tmp_path, f"{n}.log", 380)
    with patch.object(manager, "trim_tail", side_effect=exception):
        state = manager.enforce(config(tmp_path))
    assert state["status"] == "error"
    assert bool(state["errors"]) == (type(exception) is OSError)


def test_state_write_bounded_and_atomic(tmp_path):
    data = config(tmp_path)
    manager.save_state(data, {"status": "ok"})
    assert json.loads((tmp_path / "state.json").read_text()) == {"status": "ok"}
    assert not (tmp_path / "state.json.tmp").exists()
    with pytest.raises(ValueError, match="size bound"):
        manager.save_state(data, {"huge": "x" * 140000})


@pytest.mark.parametrize("error", [False, True])
def test_main_once_exit_contract(tmp_path, error):
    if error:
        for n in range(3):
            log(tmp_path, f"{n}.log.1", 400)
    path = tmp_path / "config.json"
    path.write_text(json.dumps(config(tmp_path)))
    args = ["log_manager.py", "--config", str(path), "--once"]
    with patch.object(sys, "argv", args):
        if error:
            with patch.object(Path, "unlink", side_effect=OSError("synthetic failure")):
                assert manager.main() == 1
        else:
            assert manager.main() == 0
            with pytest.raises(SystemExit) as stopped:
                runpy.run_path(str(Path(manager.__file__)), run_name="__main__")
            assert stopped.value.code == 0


def test_manager_loop_change_only_errors_and_recovery(tmp_path):
    clock, calls = [0], [0]

    def enforce(_):
        n = calls[0]
        calls[0] += 1
        clock[0] = [0, 1, 2, 3, 4, 70, 140, 141][n]
        if n in (3, 4, 5):
            raise OSError("synthetic scan failure")
        errors = [{"path": "fixture.log", "error": "OSError"}] if n in (1, 2, 6) else []
        return {
            "errors": errors,
            "action_count": int(n == 0),
            "status": "error" if errors else "ok",
            "current_bytes": 0,
        }

    def sleep(_):
        if calls[0] >= 8:
            raise KeyboardInterrupt()

    with (
        patch.object(sys, "argv", ["log_manager.py", "--config", "synthetic"]),
        patch.object(manager, "load_config", return_value=config(tmp_path)),
        patch.object(manager, "enforce", side_effect=enforce),
        patch.object(manager, "save_state") as save,
        patch.object(manager.time, "sleep", side_effect=sleep),
        patch.object(manager.time, "monotonic", side_effect=lambda: clock[0]),
    ):
        with pytest.raises(KeyboardInterrupt):
            manager.main()
        assert save.call_count == 5
