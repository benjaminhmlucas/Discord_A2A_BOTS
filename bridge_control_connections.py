"""Local-control actions over the shared MCP registry, connection manager and authentication.

Every action goes through Capabilities' Registry, ConnectionManager and Authentication,
exactly like mcp_connections.py. There is no second transport, permission engine or
secret store. Discovery, connection and sign-in never add, enable or authorize tools.
"""

import asyncio
from contextlib import asynccontextmanager
import copy
import webbrowser

from bridge_auth_policy import references
from bridge_capabilities import Capabilities
from bridge_mcp import PROTOCOL, PROTOCOL_2025, AuthorizationRejected
from bridge_errors import CapabilityError

ACTIONS = (
    "add",
    "edit",
    "remove",
    "test",
    "discover",
    "connect",
    "disconnect",
    "signin",
    "logout",
    "credential-set",
    "credential-delete",
)


async def open_browser(url):
    # Explicit sign-in click only. The URL carries one-time state/PKCE challenge.
    await asyncio.to_thread(webbrowser.open, url)


class ControlConnections:
    def __init__(self, store, opener=open_browser):
        self.store, self.opener = store, opener
        self.caps = None
        self.revision = None
        self.held = {}
        self.locks = {}
        # Actions using the current Capabilities; a new configuration replaces it only
        # when none are in flight and everything the old manager owns is cleaned up.
        self.users = 0
        self.changing = asyncio.Condition()

    @asynccontextmanager
    async def using(self):
        async with self.changing:
            while True:
                # Read inside the lock so a stale snapshot can never replace a newer one.
                snapshot = await asyncio.to_thread(self.store.snapshot)
                revision = snapshot["revisions"]["bridge_config.json"]
                if revision == self.revision:
                    break
                if self.users == 0:
                    # Never orphan a connection owned by the previous configuration.
                    await self.cleanup()
                    self.caps = Capabilities(snapshot["config"], lambda _: None, self.store.root)
                    self.revision = revision
                    break
                await self.changing.wait()
            self.users += 1
            caps = self.caps
        try:
            yield caps
        finally:
            async with self.changing:
                self.users -= 1
                self.changing.notify_all()

    def lock(self, name):
        return self.locks.setdefault(name, asyncio.Lock())

    async def release(self, name):
        manager = self.caps.connections
        # Includes a client kept by a connect whose setup and cleanup both failed.
        if name in self.held or name in manager.owned():
            await manager.disconnect(name)
        self.held.pop(name, None)

    async def cleanup(self):
        if self.caps is None:
            return
        manager = self.caps.connections
        # Everything the manager still owns, not only connections held open by this window:
        # a failed connect or discovery keeps its client when its own cleanup failed.
        await asyncio.gather(
            *(manager.disconnect(name) for name in manager.owned()), return_exceptions=True
        )
        owned = manager.owned()
        self.held = {name: client for name, client in self.held.items() if name in owned}
        if owned:
            # The manager retains ownership; a later attempt retries the same cleanup.
            raise CapabilityError("MCP disconnect failed; retry before changing connections")

    async def close(self):
        async with self.changing:
            await self.changing.wait_for(lambda: self.users == 0)
            await self.cleanup()

    async def status(self, caps, name):
        profile = caps.registry.profile(name)
        result = caps.connections.status(name)
        result.update(await caps.authentication.status(name, profile))
        return result

    async def overview(self):
        async with self.using() as caps:
            return await self.listing(caps)

    async def listing(self, caps):
        servers = []
        for name, profile in caps.registry.export()["servers"].items():
            row = await self.status(caps, name)
            # Validated profiles hold credential references, never credential values.
            row["profile"] = profile
            row["references"] = sorted(references(profile))
            row["oauth"] = caps.authentication.oauth_profile(profile)
            row["tools"] = [
                {
                    "alias": alias,
                    "name": tool["name"],
                    # Discord snowflakes stay strings in JavaScript.
                    "user_ids": [str(i) for i in tool["user_ids"]],
                    "bot_ids": [str(i) for i in tool["bot_ids"]],
                }
                for alias, tool in caps.tools.items()
                if tool["connection"] == name
            ]
            servers.append(row)
        return {
            "servers": servers,
            "revision": self.revision,
            "enabled": caps.enabled,
            "web": caps.web,
            "search": caps.search,
            "protocols": [PROTOCOL, PROTOCOL_2025],
        }

    async def change(self, caps, action, name, profile, revision):
        if action == "remove" and any(t["connection"] == name for t in caps.tools.values()):
            raise CapabilityError("Remove the tools that use this connection first")
        registry = caps.registry.changed(action, name, profile)
        snapshot = await asyncio.to_thread(self.store.snapshot)
        config = copy.deepcopy(snapshot["config"])
        config.setdefault("capabilities", {"enabled": False})["connections"] = registry.export()
        async with self.lock(name):
            await self.release(name)
            saved = await asyncio.to_thread(self.store.save, "bridge_config.json", config, revision)
        return {"revision": saved, "restart_required": True}

    async def act(self, action, name, data):
        # Counted as in use, so a configuration change cannot replace these Capabilities
        # (and their connection owner) while this action is still connecting or cleaning up.
        async with self.using() as caps:
            if action in ("add", "edit", "remove"):
                return await self.change(caps, action, name, data.get("profile"), data["revision"])
            return await self.perform(caps, action, name, data)

    async def perform(self, caps, action, name, data):
        profile = caps.registry.profile(name)
        auth = caps.authentication
        async with self.lock(name):
            result = {}
            if action in ("test", "discover"):
                client = self.held.get(name)
                if client is None:
                    tools = await caps.connections.discover(name, caps.active_secrets)
                else:
                    async with asyncio.timeout(caps.registry.http.seconds):
                        tools = await client.discover()
                if action == "discover":
                    # Names only: never descriptions, schemas or server-supplied instructions.
                    configured = {t["name"] for t in caps.tools.values() if t["connection"] == name}
                    result["tools"] = [
                        {"name": caps.redact(t["name"]), "authorized": t["name"] in configured}
                        for t in tools
                    ]
            elif action == "connect":
                if name in self.held:
                    raise CapabilityError("MCP connection already in use")
                try:
                    self.held[name] = await caps.connections.connect(name, caps.active_secrets)
                except AuthorizationRejected as error:
                    await auth.rejected(name, profile, error.authorization)
                    raise
            elif action == "disconnect":
                await self.release(name)
            elif action == "signin":
                await auth.signin(name, profile, self.opener, caps.active_secrets)
            elif action == "logout":
                await self.release(name)
                result = await auth.logout(name, profile, caps.active_secrets)
            elif action == "credential-set":
                value = data.get("value")
                if not isinstance(value, str):
                    raise CapabilityError("Enter the credential value")
                await auth.set_credential(name, profile, data["reference"], value)
            elif action == "credential-delete":
                await auth.delete_credential(name, profile, data["reference"])
            else:
                raise CapabilityError("Unknown connection action")
            return {**await self.status(caps, name), **result}
