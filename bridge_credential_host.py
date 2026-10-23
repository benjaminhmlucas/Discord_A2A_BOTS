"""One bounded Linux credential operation; no interactive or plaintext fallback."""

import json
import sys

from bridge_credentials import LinuxCredentials, checked_secret


def main() -> int:
    try:
        request = json.loads(sys.stdin.buffer.read(16385))
        if (
            not isinstance(request, dict)
            or set(request) != {"key", "value", "remove"}
            or not isinstance(request["key"], str)
            or not request["key"].startswith("BotBridge.MCP/")
            or len(request["key"]) > 256
            or type(request["remove"]) is not bool
        ):
            return 1
        value = request["value"]
        if value is not None:
            checked_secret(value)
        result = LinuxCredentials()._operate_direct(request["key"], value, request["remove"])
        if result is not None:
            checked_secret(result)
        sys.stdout.buffer.write(json.dumps({"value": result}).encode("utf-8"))
        sys.stdout.buffer.flush()
        return 0
    except Exception:
        return 1  # Never print native diagnostics or secrets.


if __name__ == "__main__":
    sys.exit(main())
