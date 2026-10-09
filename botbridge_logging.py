"""Size-bounded writers for BotBridge's direct logs and transcripts."""

import threading
from logging.handlers import RotatingFileHandler
from pathlib import Path

MAX_FILE_BYTES = 5 * 1024 * 1024
BACKUP_COUNT = 3
MAX_RECORD_BYTES = 256 * 1024
_handlers = {}
_cache_lock = threading.Lock()


class _StrictRotatingHandler(RotatingFileHandler):
    def _open(self):
        # Disable Windows newline expansion so the byte limit is exact.
        return open(
            self.baseFilename, self.mode, encoding=self.encoding, errors=self.errors, newline=""
        )

    def handleError(self, record):
        # Keep the caller's existing error handling; never print the record on error.
        raise


def append_line(path, text, max_bytes=MAX_FILE_BYTES, backups=BACKUP_COUNT):
    """Append one UTF-8 record, rotating before the exact byte limit is exceeded."""
    if max_bytes < 128 or backups < 1:
        raise ValueError("Invalid bounded-log limits")
    path = Path(path).resolve()
    key = (str(path), max_bytes, backups)
    with _cache_lock:
        handler = _handlers.get(key)
        if handler is None:
            handler = _StrictRotatingHandler(
                path, maxBytes=max_bytes, backupCount=backups, encoding="utf-8", delay=True
            )
            _handlers[key] = handler
    data = str(text).rstrip("\r\n").encode("utf-8")
    record_limit = min(MAX_RECORD_BYTES, max_bytes - 1)
    if len(data) > record_limit:
        marker = b"[log entry truncated] "
        data = marker + data[-(record_limit - len(marker)) :].decode(
            "utf-8", errors="ignore"
        ).encode("utf-8")
    payload = data.decode("utf-8") + "\n"
    handler.acquire()
    try:
        if handler.stream is None:
            handler.stream = handler._open()
        handler.stream.seek(0, 2)
        if handler.stream.tell() + len(data) + 1 > max_bytes:
            handler.doRollover()
            if handler.stream is None:
                handler.stream = handler._open()
        handler.stream.write(payload)
        handler.stream.flush()
    finally:
        handler.release()


def close_handlers():
    with _cache_lock:
        for handler in _handlers.values():
            handler.close()
        _handlers.clear()
