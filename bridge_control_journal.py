"""Durable intent record for the local control window's three-file configuration import.

The previous files are recorded before the first replacement. A process that exits part
way through leaves this record behind; the next configuration reader (the control window
or a bot starting up) rolls every file back to its recorded version under the same lock
before reading. A file changed by someone else since then is a conflict and is left alone.
"""

import base64
import binascii
import hashlib
import json
from pathlib import Path
from typing import Any

from bridge_errors import CapabilityError
from bridge_memory_io import MemoryStore
from bridge_settings import IMPORT_FILES, IMPORT_JOURNAL

FORMAT = "botbridge-control-import-v1"
FILE_LIMIT = 1048576
# Three base64 files of at most FILE_LIMIT bytes each, plus their hashes and keys.
JOURNAL_LIMIT = 4 * 4 * FILE_LIMIT


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


class ImportJournal:
    def __init__(self, storage: MemoryStore) -> None:
        self.storage = storage

    def pending(self) -> bool:
        control = self.storage.path(".") / Path(IMPORT_JOURNAL).parent
        if not control.exists() and not control.is_symlink():
            return False  # No lock was ever taken here, so no import ever started.
        return self.storage.path(IMPORT_JOURNAL, missing=True).exists()

    def begin(self, previous: dict[str, bytes], data: dict[str, bytes]) -> None:
        """Called with the storage lock held, before any configuration file is replaced."""
        record = {
            "format": FORMAT,
            "previous": {name: base64.b64encode(previous[name]).decode() for name in IMPORT_FILES},
            "next": {name: digest(data[name]) for name in IMPORT_FILES},
        }
        # The lock already created the control directory that holds this record.
        self.storage.atomic(IMPORT_JOURNAL, json.dumps(record).encode("utf-8"))

    def finish(self) -> None:
        # Same removal as the memory transaction record. Should a crash ever undo it,
        # recovery restores the previous, consistent files: never a mixed set.
        self.storage.path(IMPORT_JOURNAL).unlink()

    def record(self) -> dict[str, Any]:
        try:
            value = json.loads(self.storage.read(IMPORT_JOURNAL, JOURNAL_LIMIT))
            if (
                not isinstance(value, dict)
                or set(value) != {"format", "previous", "next"}
                or value["format"] != FORMAT
                or set(value["previous"]) != set(IMPORT_FILES)
                or set(value["next"]) != set(IMPORT_FILES)
            ):
                raise ValueError
            previous = {
                name: base64.b64decode(value["previous"][name], validate=True)
                for name in IMPORT_FILES
            }
            expected = {name: value["next"][name] for name in IMPORT_FILES}
            if any(len(data) > FILE_LIMIT for data in previous.values()) or any(
                type(item) is not str for item in expected.values()
            ):
                raise ValueError
        except (ValueError, TypeError, binascii.Error):
            raise CapabilityError(
                "Interrupted configuration import record is unreadable; restore the "
                "configuration files from a backup"
            ) from None
        return {"previous": previous, "next": expected}

    def recover(self) -> bool:
        """Roll an interrupted import back; called with the storage lock held."""
        if not self.pending():
            return False
        record = self.record()
        current = {name: self.storage.read(name, FILE_LIMIT) for name in IMPORT_FILES}
        # Check every file before writing any: each must be its old or its new version.
        for name in IMPORT_FILES:
            if (
                current[name] != record["previous"][name]
                and digest(current[name]) != record["next"][name]
            ):
                raise CapabilityError(
                    "Interrupted configuration import conflicts with a later edit of "
                    f"{name}; resolve it by hand, then delete {IMPORT_JOURNAL}"
                )
        for name in IMPORT_FILES:
            if current[name] != record["previous"][name]:
                self.storage.write_allowed(name)
                self.storage.atomic(name, record["previous"][name])
                if self.storage.read(name, FILE_LIMIT) != record["previous"][name]:
                    raise CapabilityError("Configuration import rollback verification failed")
        self.finish()
        return True


def recover(root: Path) -> bool:
    """Startup recovery for readers outside the control window, such as the bots."""
    storage = MemoryStore(Path(root).resolve(strict=True), {})
    journal = ImportJournal(storage)
    with storage.parent(IMPORT_FILES[0]), storage.lock():
        return journal.recover()
