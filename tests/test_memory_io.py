"""Native filesystem behavior plus injected OS failures; production guards remain real."""

import os
import json
import ctypes
import sqlite3
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest

import bridge_memory_io as io
from bridge_http import CapabilityError
from test_memory import populate, memory_config


class PosixAdapter:
    """Translate POSIX directory descriptors to actual files on the opposite test host."""

    name = "posix"
    O_DIRECTORY = 0
    O_NOFOLLOW = 0

    def __init__(self, *, mismatch=False):
        self.directories = {}
        self.mismatch = mismatch
        self.counter = 100000

    def __getattr__(self, name):
        return getattr(os, name)

    def path(self, path, descriptor):
        return self.directories[descriptor] / path if descriptor is not None else Path(path)

    def open(self, path, flags, mode=0o600, *, dir_fd=None):
        target = self.path(path, dir_fd)
        if target.is_dir():
            self.counter += 1
            self.directories[self.counter] = target
            return self.counter
        return os.open(target, flags, mode)

    def fstat(self, descriptor):
        if descriptor in self.directories:
            value = self.directories[descriptor].stat()
            return SimpleNamespace(st_dev=-1, st_ino=value.st_ino) if self.mismatch else value
        return os.fstat(descriptor)

    def close(self, descriptor):
        self.directories.pop(descriptor)

    def fsync(self, descriptor):
        if descriptor not in self.directories:
            os.fsync(descriptor)

    def replace(self, source, destination, *, src_dir_fd=None, dst_dir_fd=None):
        os.replace(self.path(source, src_dir_fd), self.path(destination, dst_dir_fd))

    def unlink(self, path, *, dir_fd=None):
        os.unlink(self.path(path, dir_fd))


class Function:
    def __init__(self, callback):
        self.callback = callback

    def __call__(self, *args):
        return self.callback(*args)


class Kernel:
    """Win32 API adapter; native Windows integration independently proves actual pins."""

    def __init__(self, failure=None):
        self.closed = []
        self.CreateFileW = Function(
            lambda *args: ctypes.c_void_p(-1).value if failure == "open" else 42
        )

        def attributes(handle, mode, output, size):
            output[0] = 0x410 if failure == "reparse" else 0 if failure == "file" else 0x10
            return failure != "attributes"

        self.GetFileInformationByHandleEx = Function(attributes)
        self.CloseHandle = Function(lambda handle: self.closed.append(handle))


def store_for(tmp_path):
    root = tmp_path / "memory"
    populate(root)
    files = memory_config(root)["memory"]["files"]
    return root, files, io.MemoryStore(root, files)


def test_both_directory_driver_paths_use_actual_bytes(tmp_path):
    root, files, store = store_for(tmp_path)
    (root / "nested").mkdir()
    (root / "nested/note.md").write_bytes(b"old")
    adapter = PosixAdapter()
    with patch.object(io, "os", adapter):
        assert store.read("nested/note.md") == b"old"
        store.atomic("nested/note.md", b"new")
        assert store.read("nested/note.md") == b"new"
    assert not adapter.directories
    with (
        patch.object(io, "os", PosixAdapter(mismatch=True)),
        pytest.raises(CapabilityError, match="root changed"),
    ):
        with store.parent("notes.md"):
            pass
    kernel = Kernel()
    driver = SimpleNamespace(**{**vars(os), "name": "nt"})
    with patch.object(io, "os", driver), patch.object(io, "windows_api", return_value=kernel):
        assert store.read("notes.md") == b"Initial notes."
        store.atomic("notes.md", b"windows adapter")
    assert kernel.closed and (root / "notes.md").read_bytes() == b"windows adapter"


@pytest.mark.parametrize(
    "failure,error",
    [
        ("open", OSError),
        ("attributes", OSError),
        ("reparse", CapabilityError),
        ("file", CapabilityError),
    ],
)
def test_directory_pin_failure_never_returns_a_file(tmp_path, failure, error):
    root, _, store = store_for(tmp_path)
    kernel = Kernel(failure)
    driver = SimpleNamespace(**{**vars(os), "name": "nt"})
    with patch.object(io, "os", driver), patch.object(io, "windows_api", return_value=kernel):
        with pytest.raises(error):
            store.read("notes.md")
    assert kernel.closed == ([] if failure == "open" else [42])


def test_windows_api_signatures_without_requiring_windows_on_linux():
    kernel = Kernel()
    with patch.object(ctypes, "WinDLL", return_value=kernel, create=True):
        assert io.windows_api() is kernel
    assert (
        len(kernel.CreateFileW.argtypes) == 7
        and len(kernel.GetFileInformationByHandleEx.argtypes) == 4
    )


def test_atomic_retry_cleanup_and_regular_file_guards(tmp_path):
    root, _, store = store_for(tmp_path)
    native_replace = os.replace
    attempts = []

    def transient(*args, **kwargs):
        attempts.append(True)
        if len(attempts) < 3:
            raise PermissionError("synthetic sharing failure")
        return native_replace(*args, **kwargs)

    with patch.object(os, "replace", transient):
        store.atomic("notes.md", b"eventual")
    assert len(attempts) == 3 and (root / "notes.md").read_bytes() == b"eventual"
    with patch.object(os, "replace", side_effect=PermissionError("persistent")):
        with pytest.raises(PermissionError):
            store.atomic("notes.md", b"refused")
    assert not list(root.glob(".memory-*.tmp"))
    assert (root / "notes.md").read_bytes() == b"eventual"
    with pytest.raises(CapabilityError):
        store.read(".")
    with pytest.raises(CapabilityError):
        store.path("../outside.md")
    with pytest.raises(FileNotFoundError):
        store.read("missing.md")
    with pytest.raises(CapabilityError):
        io.MemoryStore(None, {}).read("x.md")
    with pytest.raises(CapabilityError):
        io.MemoryStore(None, {}).pending()
    with pytest.raises(CapabilityError):
        io.MemoryStore(None, {}).backup_texts()


def pending_record(root, files):
    before = (root / "notes.md").read_bytes()
    return {
        "id": "a" * 32,
        "alias": "notes",
        "path": "notes.md",
        "before": before.decode(),
        "before_hash": io.digest(before),
        "after_hash": io.digest(b"after"),
        "write": "replace",
    }


def test_recovery_record_validation_conflicts_and_prewrite_recovery(tmp_path):
    root, files, store = store_for(tmp_path)
    with store.lock():
        pass
    record = pending_record(root, files)
    pending = root / io.CONTROL / "pending.json"
    for value in [
        [],
        {},
        {**record, "alias": []},
        {**record, "alias": "unknown"},
        {**record, "path": "../outside.md"},
        {**record, "write": None},
        {**record, "before": 1},
        {**record, "before_hash": "f" * 64},
        {**record, "id": 1},
        {**record, "id": "x" * 32},
        {**record, "after_hash": 1},
        {**record, "after_hash": "f"},
        {**record, "after_hash": "z" * 64},
    ]:
        pending.write_text(json.dumps(value), encoding="utf-8")
        with pytest.raises(CapabilityError):
            store.pending()
    pending.write_text(json.dumps(record), encoding="utf-8")
    with pytest.raises(CapabilityError, match="recovery required"):
        store.commit("notes", record["before_hash"], b"after")
    with pytest.raises(CapabilityError, match="unavailable"):
        store.recover("b" * 32)
    (root / "notes.md").write_bytes(b"external")
    with pytest.raises(CapabilityError, match="conflict"):
        store.recover(record["id"])
    (root / "notes.md").write_bytes(record["before"].encode())
    store.recover(record["id"])
    assert (root / "notes.md").read_bytes() == record["before"].encode()


def test_scoped_write_policy_capacity_and_real_sqlite_lock(tmp_path):
    root, files, store = store_for(tmp_path)
    before = (root / "notes.md").read_bytes()
    with store.lock():
        with pytest.raises(sqlite3.OperationalError):
            with io.MemoryStore(root, files).lock():
                pass
    for name in ("AGENTS.md", "LIVE_STATE.md", "SESSION_LOG.md"):
        (root / name).write_text("Shared protocol file")
    with pytest.raises(CapabilityError, match="Shared-memory"):
        store.commit("notes", io.digest(before), b"after")
    for name in ("AGENTS.md", "LIVE_STATE.md", "SESSION_LOG.md"):
        (root / name).unlink()
    files["notes"]["write"] = None
    with pytest.raises(CapabilityError, match="policy denied"):
        store.commit("notes", io.digest(before), b"after")
    files["notes"]["write"] = "append"
    with pytest.raises(CapabilityError, match="policy denied"):
        store.commit("notes", io.digest(before), b"bad append")
    with pytest.raises(CapabilityError, match="too large"):
        store.commit("notes", io.digest(before), before + b"x" * 65537)
    files["notes"]["write"] = "replace"
    for index in range(64):
        (root / io.CONTROL / f"receipt-{index}.json").write_text("{}")
    with pytest.raises(CapabilityError, match="capacity"):
        store.commit("notes", io.digest(before), b"after")
    for index in range(65):
        (root / io.CONTROL / f"backup-{index}.md").write_text("archive")
    with pytest.raises(CapabilityError, match="backup limit"):
        store.backup_texts()
    (root / io.CONTROL / "audit.jsonl").write_bytes(b"x" * 1048001)
    with pytest.raises(CapabilityError, match="audit capacity"):
        store.audit(pending_record(root, files), "prepared")


def test_external_edit_during_durable_preparation_is_not_overwritten(tmp_path):
    root, _, store = store_for(tmp_path)
    before = (root / "notes.md").read_bytes()
    actual = os.replace

    def external(source, destination, **options):
        actual(source, destination, **options)
        if str(destination).endswith("pending.json"):
            (root / "notes.md").write_bytes(b"external edit")

    with (
        patch.object(os, "replace", external),
        pytest.raises(CapabilityError, match="revision conflict"),
    ):
        store.commit("notes", io.digest(before), b"new")
    assert (root / "notes.md").read_bytes() == b"external edit"
    assert store.pending() is not None
