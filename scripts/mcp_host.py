"""Own a local MCP server tree; on Windows a private job dies with this host."""

import os
import importlib
from pathlib import Path
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
protect_process = importlib.import_module("bridge_windows").protect_process
creation_flags = importlib.import_module("scripts.console_windows").creation_flags


def main():
    protect_process("mcp-host-" + str(os.getpid()))
    try:
        result = subprocess.run(
            sys.argv[1:],
            stdin=sys.stdin,
            stdout=sys.stdout,
            stderr=sys.stderr,
            creationflags=creation_flags(),
            check=False,
        )
        return result.returncode
    except OSError:
        return 1  # Neither argv, environment nor OS error text is public output.


if __name__ == "__main__":
    sys.exit(main())
