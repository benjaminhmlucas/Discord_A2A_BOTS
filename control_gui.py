"""Optional loopback control window. Start explicitly with python control_gui.py."""

import argparse
import asyncio
import hmac
import json
from pathlib import Path
import re
import secrets
import webbrowser

import aiohttp
from aiohttp import web

import bridge_control_services as services
import bridge_control_setup as setup_checks
from bridge_control_config import ControlConfig
from bridge_control_connections import ACTIONS, ControlConnections
from bridge_control_forms import SECTIONS, edits, form
from bridge_errors import CapabilityError
from bridge_runtime_credentials import NAMES, RuntimeCredentials, save_runtime_credential
from initialize import initialize

ROOT = Path(__file__).resolve().parent
STATE = web.AppKey("control", dict)
GENERIC = "Request refused. Check the values and reload if another editor changed them."
# Fixed validation sentences carry no request data; anything else gets the generic text.
SAFE = re.compile(r"[A-Z][A-Za-z ,;()/-]{2,120}(: [a-z_]{1,40})?")


def public_message(error):
    text = str(error)
    if isinstance(error, CapabilityError) or SAFE.fullmatch(text):
        return text
    return GENERIC


@web.middleware
async def boundary(request, handler):
    state = request.app[STATE]
    if request.host != state["host"]:
        return web.Response(status=403)
    if request.path.startswith("/api/"):
        expected = "Bearer " + state["token"]
        if not hmac.compare_digest(
            request.headers.get("Authorization", "").encode(), expected.encode()
        ):
            return web.Response(status=403)
        if request.method != "GET" and (
            request.headers.get("Origin") != "http://" + state["host"]
            or request.content_type != "application/json"
        ):
            return web.Response(status=403)
    try:
        response = await handler(request)
    except (
        ValueError,
        TypeError,
        KeyError,
        OSError,
        RuntimeError,
        RecursionError,
        aiohttp.ClientError,
    ) as error:
        # Arbitrary exception text may include pasted secrets or private paths.
        response = web.json_response({"error": public_message(error)}, status=400)
    response.headers.update(
        {
            "Cache-Control": "no-store",
            "Referrer-Policy": "no-referrer",
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        }
    )
    return response


async def asset(request):
    name = request.match_info.get("name", "index.html")
    if name not in ("index.html", "control.js", "control.css"):
        raise web.HTTPNotFound()
    return web.FileResponse(ROOT / "ui" / name)


async def configuration(request):
    state = request.app[STATE]
    async with state["lock"]:
        snapshot = await asyncio.to_thread(state["config"].snapshot)
        # Keep numeric Discord IDs inside JSON text. JavaScript Numbers lose their bits.
        return web.json_response(
            {
                "sections": {
                    section: json.dumps(
                        {key: snapshot["config"][key] for key in keys if key in snapshot["config"]},
                        indent=2,
                    )
                    for section, keys in SECTIONS.items()
                },
                "forms": {
                    section: form(snapshot["config"], section)
                    for section in ("Discord", "Access", "Providers", "Limits")
                },
                "settings": json.dumps(snapshot["settings"], indent=2),
                "context": snapshot["context"],
                "allow_work": snapshot["config"].get("allow_work", False),
                "revisions": snapshot["revisions"],
            }
        )


def save_document(store, data):
    value = data["value"]
    if data["name"] == "bridge_config.json":
        current = store.snapshot()["config"]
        updates = (
            edits(current, data["section"], value)
            if data.get("typed") is True
            else json.loads(value)
        )
        if not isinstance(updates, dict) or not set(updates) <= set(SECTIONS[data["section"]]):
            raise ValueError("Unsupported screen settings")
        value = {**current, **updates}
    elif data["name"] == "local_settings.json":
        value = json.loads(value)
    return store.save(
        data["name"], value, data["revision"], confirm_work=data.get("confirm_work") is True
    )


async def save(request):
    state = request.app[STATE]
    data = await request.json()
    async with state["lock"]:
        result = await asyncio.to_thread(save_document, state["config"], data)
    return web.json_response({"revision": result, "restart_required": True})


async def redact(request):
    data = await request.json()
    if not isinstance(data["text"], str) or len(data["text"]) > 12000:
        raise ValueError("Invalid sample")
    return web.json_response(
        {"text": await asyncio.to_thread(request.app[STATE]["config"].redact, data["text"])}
    )


async def setup(request):
    state = request.app[STATE]
    data = await request.json()
    if set(data) != {"owner_id", "channel_id", "codex_id", "antigravity_id", "claude_id"}:
        raise ValueError("Invalid identities")
    if any(
        not isinstance(value, str) or not value.isascii() or not value.isdigit()
        for value in data.values()
    ):
        raise ValueError("Invalid identities")
    data = {key: int(value) for key, value in data.items()}
    async with state["lock"]:
        await asyncio.to_thread(initialize, **data, root=state["config"].root)
    return web.json_response({"initialized": True})


def runtime_status(store):
    snapshot = store.snapshot()
    native = RuntimeCredentials(snapshot["config"], store.root)
    return {
        "credentials": {name: native.status(name)["state"] for name in NAMES},
        "revision": snapshot["revisions"]["local_settings.json"],
    }


async def credentials(request):
    state = request.app[STATE]
    async with state["lock"]:
        if request.method == "GET":
            result = await asyncio.to_thread(runtime_status, state["config"])
        else:
            data = await request.json()
            if data["action"] not in ("set", "delete"):
                raise ValueError("Unknown credential action")
            result = await asyncio.to_thread(
                save_runtime_credential,
                state["config"],
                data["name"],
                data.get("value"),
                data["revision"],
                remove=data["action"] == "delete",
            )
    return web.json_response(result)


def fields(data, required, optional=()):
    if not isinstance(data, dict) or not set(required) <= set(data) <= {*required, *optional}:
        raise CapabilityError("Unsupported request")
    return data


async def connections(request):
    state = request.app[STATE]
    if request.method == "GET":
        return web.json_response(await state["connections"].overview())
    data = fields(
        await request.json(), ("action", "name"), ("profile", "revision", "reference", "value")
    )
    if data["action"] not in ACTIONS or not isinstance(data["name"], str):
        raise CapabilityError("Unknown connection action")
    if data["action"] in ("add", "edit", "remove"):
        async with state["lock"]:
            result = await state["connections"].act(data["action"], data["name"], data)
    else:
        result = await state["connections"].act(data["action"], data["name"], data)
    return web.json_response(result)


async def checklist(request):
    state = request.app[STATE]
    if request.method == "GET":
        return web.json_response(await asyncio.to_thread(setup_checks.checklist, state["config"]))
    data = fields(await request.json(), ("action",))
    async with state["operations"]:
        if data["action"] == "preflight":
            result = await asyncio.to_thread(setup_checks.preflight, state["config"])
        elif data["action"] in ("install_pm2", "install_codex", "install_claude"):
            target = data["action"].removeprefix("install_")
            result = await asyncio.to_thread(setup_checks.install, state["config"], target)
        else:
            raise CapabilityError("Unknown setup action")
    return web.json_response(result)


async def providers(request):
    store = request.app[STATE]["config"]
    if request.method == "GET":
        return web.json_response(await asyncio.to_thread(setup_checks.providers, store))
    data = fields(await request.json(), ("action", "target"), ("confirm",))
    if data["action"] == "login":
        result = await asyncio.to_thread(setup_checks.login_status, store, data["target"])
    elif data["action"] == "verify":
        result = await setup_checks.verify(store, data["target"])
    elif data["action"] == "message":
        result = await setup_checks.send_test_message(store, data["target"], data.get("confirm"))
    else:
        raise CapabilityError("Unknown provider action")
    return web.json_response(result)


async def service_status(request):
    store = request.app[STATE]["config"]
    listed, health = await asyncio.gather(
        asyncio.to_thread(services.services, store), asyncio.to_thread(services.health, store)
    )
    return web.json_response({"pm2": listed, "health": health, "names": services.SERVICES})


async def service_action(request):
    state = request.app[STATE]
    data = fields(await request.json(), ("action",), ("name", "console", "enabled", "task"))
    store = state["config"]
    async with state["operations"]:
        if data["action"] == "maintenance":
            result = await asyncio.to_thread(services.maintenance, store, data.get("enabled"))
        elif data["action"].startswith("task-"):
            result = await asyncio.to_thread(
                services.recovery_task, store, data["action"][5:], data.get("task")
            )
        else:
            result = await asyncio.to_thread(
                services.control,
                store,
                data["action"],
                data.get("name"),
                data.get("console", False),
            )
    return web.json_response(result)


async def service_logs(request):
    store = request.app[STATE]["config"]
    return web.json_response(
        await asyncio.to_thread(services.logs, store, request.query.get("name", ""))
    )


async def export(request):
    state = request.app[STATE]
    async with state["lock"]:
        bundle = await asyncio.to_thread(state["config"].export)
    # Text, not parsed JSON in the page: Discord IDs keep every digit.
    return web.Response(
        text=json.dumps(bundle, indent=2) + "\n",
        content_type="application/json",
        headers={"Content-Disposition": 'attachment; filename="botbridge-settings.json"'},
    )


async def restore(request):
    state = request.app[STATE]
    data = fields(await request.json(), ("bundle", "revisions"), ("confirm_work",))
    if not isinstance(data["bundle"], str) or len(data["bundle"]) > 1048576:
        raise CapabilityError("Choose a BotBridge settings export")
    bundle = json.loads(data["bundle"])
    async with state["lock"]:
        result = await asyncio.to_thread(
            state["config"].restore,
            bundle,
            data["revisions"],
            confirm_work=data.get("confirm_work") is True,
        )
    return web.json_response({"revisions": result, "restart_required": True})


async def closing(app):
    await app[STATE]["connections"].close()


def create_app(root, host, token):
    app = web.Application(middlewares=[boundary], client_max_size=1048576)
    store = ControlConfig(root)
    app[STATE] = {
        "config": store,
        "connections": ControlConnections(store),
        "host": host,
        "token": token,
        "lock": asyncio.Lock(),
        "operations": asyncio.Lock(),
    }
    app.on_cleanup.append(closing)
    app.add_routes(
        [
            web.get("/", asset),
            web.get("/ui/{name}", asset),
            web.get("/api/config", configuration),
            web.post("/api/save", save),
            web.post("/api/redact", redact),
            web.post("/api/setup", setup),
            web.get("/api/credentials", credentials),
            web.post("/api/credentials", credentials),
            web.get("/api/connections", connections),
            web.post("/api/connections", connections),
            web.get("/api/checklist", checklist),
            web.post("/api/checklist", checklist),
            web.get("/api/providers", providers),
            web.post("/api/providers", providers),
            web.get("/api/services", service_status),
            web.post("/api/services", service_action),
            web.get("/api/logs", service_logs),
            web.get("/api/export", export),
            web.post("/api/import", restore),
        ]
    )
    return app


async def serve(root, launch, stop=None):
    # The session secret is held only in process memory and the opened URL fragment.
    token = secrets.token_urlsafe(32)
    app = create_app(root, "", token)
    runner = web.AppRunner(app, access_log=None)
    await runner.setup()
    try:
        site = web.TCPSite(runner, "127.0.0.1", 0)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        app[STATE]["host"] = f"127.0.0.1:{port}"
        url = f"http://127.0.0.1:{port}/#{token}"
        if launch:
            await asyncio.to_thread(webbrowser.open, url)
        else:
            print(url, flush=True)
        await (asyncio.Event() if stop is None else stop).wait()
    finally:
        await runner.cleanup()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    asyncio.run(serve(args.root, not args.no_browser))


if __name__ == "__main__":
    main()
