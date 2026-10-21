"""A real independent JSON-RPC process used by transport and consumer tests."""

import json
import os
from pathlib import Path
import subprocess
import sys
import time

mode = sys.argv[1]
audit = Path(sys.argv[2])
schema = {
    "type": "object",
    "properties": {
        "payload": {
            "type": "object",
            "properties": {"names": {"type": "array", "items": {"type": "string"}}},
            "required": ["names"],
            "additionalProperties": False,
        }
    },
    "required": ["payload"],
    "additionalProperties": False,
}
if mode == "spawn_child":
    child = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(120)"], stdin=subprocess.DEVNULL
    )
    audit.with_suffix(".pid").write_text(str(child.pid))
if mode == "exit":
    sys.exit(1)
for line in sys.stdin:
    request = json.loads(line)
    method = request["method"]
    with audit.open("a", encoding="utf-8") as output:
        output.write(
            json.dumps(
                {"method": method, "params": request.get("params"), "environment": dict(os.environ)}
            )
            + "\n"
        )
    if "id" not in request:
        continue
    if mode == "slow" and method == "tools/call" or mode == "slow_initialize":
        time.sleep(10)
    if method == "initialize":
        result = {
            "protocolVersion": "2024-11-05" if mode == "protocol" else "2025-11-25",
            "serverInfo": {"name": "fixture", "version": "1"},
            "capabilities": {"tools": {}},
        }
    elif method == "tools/list":
        definition = {
            "name": "read_example",
            "inputSchema": schema,
            "annotations": {"readOnlyHint": mode != "write"},
        }
        result = {"tools": [definition]}
    else:
        result = {"content": [{"type": "text", "text": json.dumps(request["params"]["arguments"])}]}
    envelope = {"jsonrpc": "2.0", "id": request["id"], "result": result}
    if mode == "request" and method == "tools/list":
        envelope = {"jsonrpc": "2.0", "id": 99, "method": "sampling/createMessage"}
    if mode == "wrong_id":
        envelope["id"] += 1
    if mode == "notification":
        print(json.dumps({"jsonrpc": "2.0", "method": "notifications/message"}), flush=True)
    if mode == "stderr":
        print("normal diagnostic", file=sys.stderr, flush=True)
    if mode == "stderr_flood":
        sys.stderr.write("x" * 70000)
        sys.stderr.flush()
        time.sleep(0.1)
    if mode == "large":
        print("x" * 524300, flush=True)
    elif mode == "broken":
        print("not-json", flush=True)
    elif mode == "encoding":
        sys.stdout.buffer.write(b"\xff\n")
        sys.stdout.flush()
    elif mode == "fragment":
        sys.stdout.write(json.dumps(envelope))
        sys.stdout.flush()
        sys.exit(0)
    else:
        print(json.dumps(envelope), flush=True)
    if mode == "exit_after_init" and method == "initialize":
        sys.exit(0)
    if mode == "block_stdin" and method == "tools/list":
        audit.with_suffix(".server.pid").write_text(str(os.getpid()))
        time.sleep(120)
