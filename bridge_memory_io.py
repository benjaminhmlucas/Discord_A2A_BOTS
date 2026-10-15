"""Bounded memory files and serialized atomic note transactions with durable recovery."""

import hashlib
import json
import os
import secrets
import sqlite3
import stat
import time
import ctypes
from ctypes import wintypes
from contextlib import contextmanager
from pathlib import Path
from collections.abc import Iterator
from typing import Any

from bridge_http import CapabilityError

CONTROL = ".botbridge-memory"
MAX_BYTES = 65536


def windows_api() -> Any:
    api = getattr(ctypes, "WinDLL")("kernel32", use_last_error=True)
    api.CreateFileW.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPVOID,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HANDLE,
    ]
    api.CreateFileW.restype = wintypes.HANDLE
    api.GetFileInformationByHandleEx.argtypes = [
        wintypes.HANDLE,
        ctypes.c_int,
        wintypes.LPVOID,
        wintypes.DWORD,
    ]
    api.GetFileInformationByHandleEx.restype = wintypes.BOOL
    api.CloseHandle.argtypes = [wintypes.HANDLE]
    api.CloseHandle.restype = wintypes.BOOL
    return api


def digest(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


class MemoryStore:
    def __init__(self, root: Path | None, files: dict[str, dict[str, Any]]) -> None:
        self.root, self.files = root, files

    @contextmanager
    def parent(self, relative: str) -> Iterator[int | None]:
        target = self.path(relative, missing=True)
        handles = []
        if os.name == "nt":
            api = windows_api()
            try:
                for directory in (*reversed(target.parent.parents), target.parent):
                    # No FILE_SHARE_DELETE: directory names cannot be replaced while in use.
                    handle = api.CreateFileW(
                        str(directory), 0x80000000, 3, None, 3, 0x2200000, None
                    )
                    if handle == wintypes.HANDLE(-1).value:
                        raise OSError("Memory directory could not be pinned")
                    handles.append(handle)
                    attributes = (wintypes.DWORD * 2)()
                    if not api.GetFileInformationByHandleEx(
                        handle, 9, attributes, ctypes.sizeof(attributes)
                    ):
                        raise OSError("Memory directory attributes unavailable")
                    if attributes[0] & 0x400 or not attributes[0] & 0x10:
                        raise CapabilityError("Memory directory denied")
                self.path(relative, missing=True)
                yield None
            finally:
                for handle in reversed(handles):
                    api.CloseHandle(handle)
        else:
            root = self.path(".")
            flags = os.O_RDONLY | getattr(os, "O_DIRECTORY") | getattr(os, "O_NOFOLLOW")
            try:
                descriptor = os.open(root, flags)
                handles.append(descriptor)
                observed = os.fstat(descriptor)
                expected = root.stat()
                if (observed.st_dev, observed.st_ino) != (expected.st_dev, expected.st_ino):
                    raise CapabilityError("Memory root changed")
                for part in target.parent.relative_to(root).parts:
                    descriptor = os.open(part, flags, dir_fd=descriptor)
                    handles.append(descriptor)
                yield descriptor
            finally:
                for descriptor in reversed(handles):
                    os.close(descriptor)

    def path(self, relative: str, *, missing: bool = False) -> Path:
        if self.root is None:
            raise CapabilityError("Memory root unavailable")
        target = self.root / relative
        if not target.is_relative_to(self.root) or ".." in Path(relative).parts:
            raise CapabilityError("Memory path denied")
        for candidate in (*reversed(target.parents), target):
            try:
                metadata = candidate.lstat()
            except FileNotFoundError:
                if missing and candidate == target:
                    continue
                raise
            if (
                stat.S_ISLNK(metadata.st_mode)
                or getattr(metadata, "st_file_attributes", 0) & 0x400
                or (
                    candidate == target
                    and stat.S_ISREG(metadata.st_mode)
                    and metadata.st_nlink != 1
                )
            ):
                raise CapabilityError("Memory links denied")
        return target

    def read(self, relative: str, limit: int = MAX_BYTES) -> bytes:
        path = self.path(relative)
        before = path.stat()
        if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
            raise CapabilityError("Memory file denied")
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        with self.parent(relative) as directory:
            with os.fdopen(
                os.open(path.name if directory is not None else path, flags, dir_fd=directory), "rb"
            ) as handle:
                opened = os.fstat(handle.fileno())
                if (opened.st_dev, opened.st_ino) != (
                    before.st_dev,
                    before.st_ino,
                ) or opened.st_nlink != 1:
                    raise CapabilityError("Memory file changed before read")
                data = handle.read(limit + 1)
        after = self.path(relative).stat()
        signatures = {
            (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns)
            for s in (before, opened, after)
        }
        if len(data) > limit or len(signatures) != 1:
            raise CapabilityError("Memory changed during read")
        data.decode("utf-8-sig")
        return data

    def atomic(self, relative: str, data: bytes) -> None:
        with self.parent(relative) as directory:
            self.replace_in_directory(relative, data, directory)

    def replace_in_directory(self, relative: str, data: bytes, directory: int | None) -> None:
        target = self.path(relative, missing=True)
        temporary = target.parent / (".memory-" + secrets.token_hex(16) + ".tmp")
        descriptor = os.open(
            temporary.name if directory is not None else temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0),
            0o600,
            dir_fd=directory,
        )
        try:
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(data)
                handle.flush()
                os.fsync(handle.fileno())
            attempt = 0
            while True:
                try:
                    self.path(relative, missing=True)
                    os.replace(
                        temporary.name if directory is not None else temporary,
                        target.name if directory is not None else target,
                        src_dir_fd=directory,
                        dst_dir_fd=directory,
                    )
                    if directory is not None:
                        os.fsync(directory)
                    return
                except PermissionError:
                    attempt += 1
                    if attempt == 3:
                        raise
                    time.sleep(0.02)
        finally:
            try:
                os.unlink(temporary.name if directory is not None else temporary, dir_fd=directory)
            except FileNotFoundError:
                pass

    @contextmanager
    def lock(self) -> Iterator[None]:
        root = self.path(".")
        control = root / CONTROL
        if not control.exists():
            self.path(CONTROL, missing=True)
            control.mkdir(mode=0o700, exist_ok=True)
        self.path(CONTROL)
        database = self.path(CONTROL + "/lock.sqlite3", missing=True)
        with self.parent(CONTROL + "/lock.sqlite3"):
            db = sqlite3.connect(database, timeout=0.25)
            try:
                db.execute("BEGIN IMMEDIATE")
                yield
            finally:
                db.rollback()
                db.close()

    def pending(self) -> dict[str, Any] | None:
        if self.root is None:
            raise CapabilityError("Memory root unavailable")
        control = self.root / CONTROL
        if not control.exists() and not control.is_symlink():
            return None
        self.path(CONTROL)
        path = self.path(CONTROL + "/pending.json", missing=True)
        if not path.exists():
            return None
        value = json.loads(self.read(CONTROL + "/pending.json", 400000))
        if not isinstance(value, dict) or set(value) != {
            "id",
            "alias",
            "path",
            "before",
            "before_hash",
            "after_hash",
            "write",
        }:
            raise CapabilityError("Invalid memory recovery record")
        alias = value["alias"]
        if (
            not isinstance(alias, str)
            or alias not in self.files
            or value["path"] != self.files[alias]["path"]
            or (value["write"] != self.files[alias]["write"] or value["write"] is None)
            or not isinstance(value["before"], str)
            or digest(value["before"].encode()) != value["before_hash"]
            or not isinstance(value["id"], str)
            or len(value["id"]) != 32
            or any(character not in "0123456789abcdef" for character in value["id"])
            or any(
                not isinstance(value[field], str)
                or len(value[field]) != 64
                or any(character not in "0123456789abcdef" for character in value[field])
                for field in ("before_hash", "after_hash")
            )
            or len(value["before"].encode()) > MAX_BYTES
        ):
            raise CapabilityError("Memory recovery policy mismatch")
        return value

    def backup_texts(self) -> tuple[str, ...]:
        if self.root is None:
            raise CapabilityError("Memory root unavailable")
        control = self.root / CONTROL
        if not control.exists() and not control.is_symlink():
            return ()
        self.path(CONTROL)
        backups = sorted(
            path
            for path in control.iterdir()
            if path.name.startswith("backup-") and path.name.endswith(".md")
        )
        if len(backups) > 64:
            raise CapabilityError("Memory backup limit reached")
        return tuple(self.read(CONTROL + "/" + path.name).decode("utf-8-sig") for path in backups)

    def audit(self, record: dict[str, Any], outcome: str) -> None:
        relative = CONTROL + "/audit.jsonl"
        path = self.path(relative, missing=True)
        if path.exists() and path.stat().st_size > 1048000:
            raise CapabilityError("Memory audit capacity reached")
        line = (
            json.dumps(
                {
                    "id": record["id"],
                    "alias": record["alias"],
                    "before": record["before_hash"],
                    "after": record["after_hash"],
                    "at": int(time.time()),
                    "outcome": outcome,
                },
                separators=(",", ":"),
            )
            + "\n"
        )
        flags = (
            os.O_WRONLY
            | os.O_APPEND
            | os.O_CREAT
            | getattr(os, "O_BINARY", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        with self.parent(relative) as directory:
            with os.fdopen(
                os.open(
                    path.name if directory is not None else path, flags, 0o600, dir_fd=directory
                ),
                "ab",
            ) as handle:
                metadata = os.fstat(handle.fileno())
                if metadata.st_nlink != 1 or not stat.S_ISREG(metadata.st_mode):
                    raise CapabilityError("Memory audit file denied")
                handle.write(line.encode())
                handle.flush()
                os.fsync(handle.fileno())

    def commit(self, alias: str, expected: str, after: bytes) -> str:
        self.write_allowed()
        with self.lock():
            if self.pending() is not None:
                raise CapabilityError("Memory recovery required")
            # Shared protocol writes need a separate reviewed policy. Dedicated notes only.
            self.write_allowed()
            definition = self.files[alias]
            relative = definition["path"]
            before = self.read(relative)
            if digest(before) != expected:
                raise CapabilityError("Memory revision conflict")
            if definition["write"] not in ("append", "replace") or (
                definition["write"] == "append" and not after.startswith(before)
            ):
                raise CapabilityError("Memory write policy denied")
            if len(after) > MAX_BYTES:
                raise CapabilityError("Memory file too large")
            control = self.path(CONTROL)
            if (
                sum(
                    path.name.startswith("receipt-") and path.name.endswith(".json")
                    for path in control.iterdir()
                )
                >= 64
            ):
                raise CapabilityError("Memory recovery capacity reached")
            identity = secrets.token_hex(16)
            record = {
                "id": identity,
                "alias": alias,
                "path": relative,
                "before": before.decode("utf-8"),
                "before_hash": expected,
                "after_hash": digest(after),
                "write": definition["write"],
            }
            raw = json.dumps(record, ensure_ascii=False).encode()
            # Retain marker-bearing preimages so the existing privacy scan still knows
            # old private values after a note is replaced.
            self.atomic(CONTROL + "/backup-" + identity + ".md", before)
            self.atomic(CONTROL + "/receipt-" + identity + ".json", raw)
            self.atomic(CONTROL + "/pending.json", raw)
            self.audit(record, "prepared")
            # Recheck after durable preparation, immediately before the atomic update.
            if digest(self.read(relative)) != expected:
                raise CapabilityError("Memory revision conflict")
            self.atomic(relative, after)
            self.audit(record, "committed")
            self.path(CONTROL + "/pending.json").unlink()
            return f"Memory {alias} committed; revision {digest(after)}; receipt {identity}."

    def status(self) -> str:
        record = self.pending()
        if record is None:
            return "Memory: no pending recovery."
        return (
            f"Memory pending receipt {record['id']}; alias {record['alias']}; "
            f"{record['write']}; revision {record['before_hash']} -> {record['after_hash']}.\n"
            "Review this record before /memory recover RECEIPT. Replacement recovery restores "
            "the prior revision; append recovery preserves already appended text."
        )

    def recover(self, identity: str) -> str:
        self.write_allowed()
        with self.lock():
            record = self.pending()
            if record is None or record["id"] != identity:
                raise CapabilityError("Memory recovery unavailable")
            current = self.read(record["path"])
            if digest(current) not in (record["before_hash"], record["after_hash"]):
                raise CapabilityError("Memory recovery conflict")
            if digest(current) == record["after_hash"] and record["write"] == "replace":
                self.atomic(record["path"], record["before"].encode())
            self.audit(record, "recovered")
            self.path(CONTROL + "/pending.json").unlink()
            return f"Memory {record['alias']} recovered; receipt {identity}."

    def write_allowed(self) -> None:
        root = self.path(".")
        if any(
            all(
                (directory / name).is_file()
                for name in ("AGENTS.md", "LIVE_STATE.md", "SESSION_LOG.md")
            )
            for directory in (root, *root.parents)
        ):
            raise CapabilityError("Shared-memory writes unavailable")
