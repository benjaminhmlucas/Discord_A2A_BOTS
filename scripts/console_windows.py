"""Windows console policy shared by provider and management launch paths."""

import ctypes
import os
import subprocess
from collections.abc import Mapping


def creation_flags(*, background: bool = True, env: Mapping[str, str] | None = None) -> int:
    environment = os.environ if env is None else env
    if os.name != "nt" or environment.get("BOTBRIDGE_SHOW_CONSOLE") == "1":
        return 0
    if background or not ctypes.windll.kernel32.GetConsoleWindow():
        return subprocess.CREATE_NO_WINDOW
    return 0
