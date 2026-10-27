"""Offline profile editing, credential management and bounded connection diagnostics.

Writes are exclusive new exports; replacing an active runtime configuration is an
explicit operator deployment step. No inherited app sessions or automatic tools.
Secrets are read from a hidden prompt or stdin, never from arguments, and are never
printed. A browser opens only for the explicit sign-in command.
"""

import argparse
import asyncio
import getpass
import json
from pathlib import Path
import sys
from typing import Any
import warnings
import webbrowser

import aiohttp

from bridge_auth_policy import AuthenticationError
from bridge_capabilities import Capabilities
from bridge_credentials import CredentialError
from bridge_mcp import AuthorizationRejected
from bridge_settings import validate_runtime_config

CREDENTIAL_ACTIONS = ("credential-set", "credential-delete", "signin", "logout")


def read_json(path: str) -> Any:
    with Path(path).open("rb") as source:
        raw = source.read(1048577)
    if len(raw) > 1048576:
        raise ValueError("Configuration too large")
    return json.loads(raw.decode("utf-8"))


async def execute(args: argparse.Namespace) -> Any:
    config = read_json(args.config)
    if not isinstance(config, dict):
        raise ValueError("Invalid configuration root")
    validate_runtime_config(config)
    caps = Capabilities(config, lambda _: None)
    if args.action == "status":
        return [await status(caps, name) for name in caps.registry.export()["servers"]]
    if args.action in CREDENTIAL_ACTIONS:
        return await credentials(caps, args)
    if args.action in ("test", "discover"):
        tools = await caps.connections.discover(args.name, caps.active_secrets)
        result = caps.connections.status(args.name)
        if args.action == "discover":
            # Names only: never print descriptions, schemas or server-supplied instructions.
            result["tools"] = [caps.redact(t["name"]) for t in tools]
        result.update(await caps.authentication.status(args.name, caps.registry.profile(args.name)))
        return result
    registry = caps.registry.changed(
        args.action, args.name, read_json(args.profile) if args.action != "remove" else None
    )
    result = json.loads(json.dumps(config))
    result.setdefault("capabilities", {"enabled": False})["connections"] = registry.export()
    validate_runtime_config(result)
    Capabilities(result, lambda _: None)
    # Never overwrite a live config, symlink or concurrent export.
    with Path(args.output).open("x", encoding="utf-8") as destination:
        json.dump(result, destination, indent=2, ensure_ascii=False)
        destination.write("\n")
    return {"outcome": "exported", "runtime_changed": False}


async def status(caps: Capabilities, name: str) -> dict[str, Any]:
    result = caps.connections.status(name)
    result.update(await caps.authentication.status(name, caps.registry.profile(name)))
    return result


def secret_input(use_stdin: bool) -> str:
    if use_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    try:
        with warnings.catch_warnings():
            # getpass warns immediately before falling back to visibly echoed input.
            warnings.simplefilter("error", getpass.GetPassWarning)
            return getpass.getpass("Credential value (input hidden): ")
    except getpass.GetPassWarning:
        raise CredentialError(
            "Hidden credential input unavailable; use --stdin with a secure input source"
        ) from None


async def open_browser(url: str, launch: bool) -> None:
    # The URL carries one-time state/PKCE challenge, not a credential.
    print("Complete sign-in in your browser:", url, sep="\n", file=sys.stderr)
    if launch:
        await asyncio.to_thread(webbrowser.open, url)


async def credentials(caps: Capabilities, args: argparse.Namespace) -> dict[str, Any]:
    auth, profile = caps.authentication, caps.registry.profile(args.name)
    if args.action == "credential-set":
        auth.settable(profile, args.reference)  # Reject before prompting for a secret.
        value = secret_input(args.stdin)
        await auth.set_credential(args.name, profile, args.reference, value)
    elif args.action == "credential-delete":
        await auth.delete_credential(args.name, profile, args.reference)
    elif args.action == "signin":
        await auth.signin(
            args.name,
            profile,
            lambda url: open_browser(url, not args.no_browser),
            caps.active_secrets,
        )
    else:
        result = await auth.logout(args.name, profile, caps.active_secrets)
        return {"id": args.name, **result}
    return await status(caps, args.name)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, help="Operator-owned bridge configuration")
    actions = parser.add_subparsers(dest="action", required=True)
    actions.add_parser("status")
    for name in ("test", "discover", "add", "edit", "remove", *CREDENTIAL_ACTIONS):
        action = actions.add_parser(name)
        action.add_argument("name")
        if name in ("add", "edit"):
            action.add_argument("--profile", required=True)
        if name in ("add", "edit", "remove"):
            action.add_argument("--output", required=True)
        if name in ("credential-set", "credential-delete"):
            action.add_argument("reference", help="Name of a native credential reference")
        if name == "credential-set":
            action.add_argument("--stdin", action="store_true", help="Read one line from stdin")
        if name == "signin":
            action.add_argument("--no-browser", action="store_true", help="Only print the URL")
    args = parser.parse_args(argv)
    try:
        print(json.dumps(asyncio.run(execute(args))))
        return 0
    except (AuthenticationError, CredentialError, AuthorizationRejected) as error:
        # These classes carry only static, credential-free guidance.
        print("MCP authentication failed: " + str(error), file=sys.stderr)
        return 1
    except (
        ValueError,
        KeyError,
        TypeError,
        RecursionError,
        OSError,
        aiohttp.ClientError,
        asyncio.TimeoutError,
    ):
        print(
            "MCP configuration or connection failed; check profile, credentials and server availability.",
            file=sys.stderr,
        )
        return 1


if __name__ == "__main__":
    sys.exit(main())
