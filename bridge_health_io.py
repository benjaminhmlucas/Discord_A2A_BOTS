"""Atomic health snapshots with bounded retries for Windows sharing conflicts."""

import json
import time
from pathlib import Path


def write_health(path: Path, data: dict[str, object]) -> None:
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(data), encoding="utf-8")
    attempt = 0
    while True:
        try:
            temporary.replace(path)
            return
        except PermissionError:
            attempt += 1
            if attempt == 3:
                raise
            time.sleep(0.02)
