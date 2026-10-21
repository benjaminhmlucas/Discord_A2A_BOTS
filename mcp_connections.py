"""Offline profile editing/migration and bounded connection diagnostics.

Writes are exclusive new exports; replacing an active runtime configuration is an
explicit operator deployment step. No inherited app sessions or automatic tools.
"""

import argparse
import asyncio
import json
from pathlib import Path
import sys

import aiohttp

from bridge_capabilities import Capabilities
from bridge_connections import migrated
from bridge_settings import validate_runtime_config


def read_json(path):
    with Path(path).open("rb") as source:
        raw = source.read(1048577)
    if len(raw) > 1048576:
        raise ValueError("Configuration too large")
    return json.loads(raw.decode("utf-8"))


async def execute(args):
    config = read_json(args.config)
    if not isinstance(config, dict):
        raise ValueError("Invalid configuration root")
    validate_runtime_config(config)
    caps = Capabilities(config, lambda _: None)
    if args.action in ("status", "test", "discover"):
        if args.action == "status":
            return [caps.connections.status(n) for n in caps.registry.export()["servers"]]
        tools = await caps.connections.discover(args.name, caps.active_secrets)
        result = caps.connections.status(args.name)
        if args.action == "discover":
            # Names only: never print descriptions, schemas or server-supplied instructions.
            result["tools"] = [caps.redact(t["name"]) for t in tools]
        return result
    if args.action == "migrate":
        result = migrated(config)
    else:
        registry = caps.registry.changed(
            args.action, args.name, read_json(args.profile) if args.action != "remove" else None
        )
        result = json.loads(json.dumps(config))
        result["capabilities"]["connections"] = registry.export()
    validate_runtime_config(result)
    Capabilities(result, lambda _: None)
    # Never overwrite a live config, rollback snapshot, symlink or concurrent export.
    with Path(args.output).open("x", encoding="utf-8") as destination:
        json.dump(result, destination, indent=2, ensure_ascii=False)
        destination.write("\n")
    return {"outcome": "exported", "runtime_changed": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="Operator-owned bridge configuration")
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("status")
    for name in ("test", "discover", "add", "edit", "remove", "migrate"):
        action = actions.add_parser(name)
        if name != "migrate":
            action.add_argument("name")
        if name in ("add", "edit"):
            action.add_argument("--profile", required=True)
        if name in ("add", "edit", "remove", "migrate"):
            action.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(asyncio.run(execute(args))))
        return 0
    except (ValueError, KeyError, TypeError, OSError, aiohttp.ClientError, asyncio.TimeoutError):
        print(
            "MCP configuration or connection failed; check profile, credentials and server availability.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
