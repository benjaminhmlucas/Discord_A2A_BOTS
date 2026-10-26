"""Native OAuth grants with metadata-only cross-process coordination.

Access and refresh tokens live only in the native credential store. SQLite holds
non-secret generation, expiry and lease rows so bot and CLI processes refresh a
grant once, and a logout or newer sign-in can never be overwritten by a stale
refresh. Native writes happen inside the same IMMEDIATE transaction that checks
the expected generation, so token rotation and logout are serialized.
"""

import asyncio
from collections.abc import Awaitable, Callable, Iterator
from contextlib import asynccontextmanager, contextmanager
import json
from pathlib import Path
from secrets import token_hex
import sqlite3
import time
from typing import Any, AsyncIterator

from bridge_auth_policy import AuthenticationError
from bridge_credentials import CredentialError, CredentialStore
from bridge_http import SafeHTTP
from bridge_oauth_flow import GrantRejected, OAuthFlow

SKEW = 60  # Refresh before expiry so a token cannot lapse during one request.
POLL = 0.05
SIGN_IN = "MCP sign-in required; use the explicit operator sign-in command"
Row = dict[str, Any]


class GrantStore:
    def __init__(self, store: CredentialStore, path: Path, *, lease_seconds: float = 30) -> None:
        self.store, self.path, self.lease_seconds = store, Path(path), lease_seconds
        self.ready = False

    @contextmanager
    def transaction(self) -> Iterator[sqlite3.Connection]:
        if not self.ready:
            self.path.parent.mkdir(parents=True, exist_ok=True)
        db = sqlite3.connect(self.path, timeout=15, isolation_level=None)
        db.row_factory = sqlite3.Row
        try:
            db.execute("BEGIN IMMEDIATE")
            try:
                if not self.ready:
                    db.execute(
                        "CREATE TABLE IF NOT EXISTS oauth_grants(binding TEXT PRIMARY KEY,"
                        " generation INTEGER NOT NULL, active INTEGER NOT NULL,"
                        " expires REAL NOT NULL, refreshable INTEGER NOT NULL,"
                        " grant_binding TEXT NOT NULL)"
                    )
                    db.execute(
                        "CREATE TABLE IF NOT EXISTS oauth_leases(binding TEXT PRIMARY KEY,"
                        " owner TEXT NOT NULL, expires REAL NOT NULL)"
                    )
                yield db
            except BaseException:
                db.execute("ROLLBACK")
                raise
            db.execute("COMMIT")
            self.ready = True
        finally:
            db.close()

    @staticmethod
    def row(db: sqlite3.Connection, binding: str) -> Row | None:
        found = db.execute("SELECT * FROM oauth_grants WHERE binding = ?", (binding,)).fetchone()
        return None if found is None else dict(found)

    def load(self, reference: dict[str, str], binding: str) -> tuple[Row | None, str | None]:
        with self.transaction() as db:
            row = self.row(db, binding)
        if row is None or not row["active"] or row["expires"] - SKEW <= time.time():
            return row, None
        return row, self.store.get(reference, binding, "access")

    def save(
        self,
        reference: dict[str, str],
        binding: str,
        grant: dict[str, Any],
        expected: int | None,
    ) -> bool:
        """Store a sign-in (expected None) or a refresh of one exact generation."""
        failed = False
        with self.transaction() as db:
            row = self.row(db, binding)
            if expected is not None and (
                row is None or not row["active"] or row["generation"] != expected
            ):
                return False  # A logout or newer sign-in won; discard these tokens.
            try:
                if grant["refresh_token"] is None:
                    self.store.delete(reference, binding, "refresh")
                else:
                    self.store.set(reference, binding, grant["refresh_token"], "refresh")
                self.store.set(reference, binding, grant["access_token"], "access")
            except CredentialError:
                failed = True
                # Native stores cannot join the SQLite transaction. Remove any
                # partial write and commit an inactive generation even if cleanup
                # fails, so logout can find and retry orphaned native entries.
                for part in ("refresh", "access"):
                    try:
                        self.store.delete(reference, binding, part)
                    except CredentialError:
                        pass
            identity = json.dumps(
                [grant["issuer"], grant["resource"], grant["scopes"]], separators=(",", ":")
            )
            db.execute(
                "INSERT INTO oauth_grants VALUES (?, ?, ?, ?, ?, ?) ON CONFLICT(binding)"
                " DO UPDATE SET generation = excluded.generation, active = excluded.active,"
                " expires = excluded.expires, refreshable = excluded.refreshable,"
                " grant_binding = excluded.grant_binding",
                (
                    binding,
                    (row["generation"] if row else 0) + 1,
                    not failed,
                    grant["expires_at"] if not failed else 0,
                    not failed and grant["refresh_token"] is not None,
                    identity,
                ),
            )
        if failed:
            raise CredentialError(
                "MCP grant disabled after native write failure; run logout for cleanup and revoke at the provider"
            )
        return True

    def refresh_token(self, reference: dict[str, str], binding: str) -> str | None:
        return self.store.get(reference, binding, "refresh")

    def mark(self, binding: str, generation: int, *, refreshable: bool) -> None:
        """Force refresh after a rejected token, or require sign-in after a rejected grant."""
        with self.transaction() as db:
            db.execute(
                "UPDATE oauth_grants SET expires = 0, refreshable = refreshable AND ?"
                " WHERE binding = ? AND generation = ?",
                (refreshable, binding, generation),
            )

    def reject(self, reference: dict[str, str], binding: str, presented: str) -> None:
        """Reject only the exact token presented, while serializing sign-in and rotation."""
        with self.transaction() as db:
            row = self.row(db, binding)
            if row is not None and row["active"]:
                access = self.store.get(reference, binding, "access")
                if access is not None and presented == "Bearer " + access:
                    db.execute("UPDATE oauth_grants SET expires = 0 WHERE binding = ?", (binding,))

    def remove(self, reference: dict[str, str], binding: str) -> dict[str, Any] | None:
        """Deactivate first, then delete native tokens; returns them for remote revocation."""
        failure = False
        tokens: dict[str, str | None] = {"refresh": None, "access": None}
        with self.transaction() as db:
            row = self.row(db, binding)
            if row is None:
                return None
            db.execute(
                "UPDATE oauth_grants SET generation = generation + 1, active = 0, expires = 0,"
                " refreshable = 0 WHERE binding = ?",
                (binding,),
            )
            for part in ("refresh", "access"):
                try:
                    tokens[part] = self.store.get(reference, binding, part)
                except CredentialError:
                    failure = True
                try:
                    self.store.delete(reference, binding, part)
                except CredentialError:
                    failure = True
            # Commit the inactive generation even when native cleanup fails. Keep
            # cleanup inside this transaction so it cannot delete a newer sign-in.
        if failure:
            raise CredentialError("MCP grant disabled; native cleanup failed, retry logout")
        issuer, resource, scopes = json.loads(row["grant_binding"])
        return {
            "issuer": issuer,
            "resource": resource,
            "scopes": scopes,
            "refresh_token": tokens["refresh"],
            "access_token": tokens["access"],
        }

    def acquire(self, binding: str, owner: str) -> bool:
        now = time.time()
        with self.transaction() as db:
            found = db.execute(
                "SELECT owner, expires FROM oauth_leases WHERE binding = ?", (binding,)
            ).fetchone()
            if found is not None and found["owner"] != owner and found["expires"] > now:
                return False
            db.execute(
                "INSERT INTO oauth_leases VALUES (?, ?, ?) ON CONFLICT(binding)"
                " DO UPDATE SET owner = excluded.owner, expires = excluded.expires",
                (binding, owner, now + self.lease_seconds),
            )
            return True

    def release(self, binding: str, owner: str) -> None:
        with self.transaction() as db:
            db.execute("DELETE FROM oauth_leases WHERE binding = ? AND owner = ?", (binding, owner))

    @asynccontextmanager
    async def lease(self, binding: str) -> AsyncIterator[None]:
        # An abandoned lease expires, so one lease period always suffices to acquire.
        owner = token_hex(16)
        deadline = time.monotonic() + self.lease_seconds + 1
        while not await asyncio.to_thread(self.acquire, binding, owner):
            if time.monotonic() > deadline:
                raise AuthenticationError("MCP authorization refresh busy; retry")
            await asyncio.sleep(POLL)
        try:
            yield
        finally:
            await asyncio.to_thread(self.release, binding, owner)


class OAuthTokens:
    """Runtime and operator OAuth operations over one shared grant store."""

    def __init__(self, grants: GrantStore, http: SafeHTTP) -> None:
        self.grants, self.http = grants, http
        # One in-process refresh per grant; result is the access token plus every
        # token value handled while refreshing (all must be redacted by callers).
        self.refreshing: dict[str, asyncio.Task[tuple[str, set[str]]]] = {}

    def flow(self, profile: dict[str, Any]) -> OAuthFlow:
        return OAuthFlow(profile, self.http)

    async def token(self, profile: dict[str, Any], binding: str, secrets: set[str]) -> str:
        reference = profile["authentication"]["credential"]
        row, access = await asyncio.to_thread(self.grants.load, reference, binding)
        if access is not None:
            secrets.add(access)
            return access
        if row is None or not row["active"] or not row["refreshable"]:
            raise AuthenticationError(SIGN_IN)
        task = self.refreshing.get(binding)
        if task is None:
            # Cancellation of one caller must not discard a rotated refresh token.
            task = asyncio.create_task(self.refresh(profile, reference, binding))
            self.refreshing[binding] = task
            task.add_done_callback(lambda done: self.finished(binding, done))
        refreshed, handled = await asyncio.shield(task)
        secrets.update(handled)
        return refreshed

    def finished(self, binding: str, task: asyncio.Task[tuple[str, set[str]]]) -> None:
        self.refreshing.pop(binding, None)
        # Retrieve the outcome even when every waiter was cancelled.
        _ = task.cancelled() or task.exception()

    async def refresh(
        self, profile: dict[str, Any], reference: dict[str, str], binding: str
    ) -> tuple[str, set[str]]:
        async with self.grants.lease(binding):
            row, access = await asyncio.to_thread(self.grants.load, reference, binding)
            if access is not None:
                return access, {access}  # Another process refreshed while this one waited.
            if row is None or not row["active"] or not row["refreshable"]:
                raise AuthenticationError(SIGN_IN)
            refresh = await asyncio.to_thread(self.grants.refresh_token, reference, binding)
            if refresh is None:
                raise AuthenticationError(SIGN_IN)
            issuer, resource, scopes = json.loads(row["grant_binding"])
            stored = {
                "issuer": issuer,
                "resource": resource,
                "scopes": scopes,
                "refresh_token": refresh,
            }
            try:
                # Finish well inside the lease so no other process can replay this token.
                async with asyncio.timeout(self.grants.lease_seconds / 2):
                    grant = await self.flow(profile).refresh(stored)
            except GrantRejected:
                await asyncio.to_thread(
                    self.grants.mark, binding, row["generation"], refreshable=False
                )
                raise
            if not await asyncio.to_thread(
                self.grants.save, reference, binding, grant, row["generation"]
            ):
                raise AuthenticationError("MCP sign-in changed during refresh; retry")
            handled = {refresh, grant["access_token"], grant["refresh_token"]} - {None}
            return str(grant["access_token"]), handled

    async def rejected(
        self, profile: dict[str, Any], binding: str, presented: str | None = None
    ) -> None:
        reference = profile["authentication"]["credential"]
        if presented is not None:
            await asyncio.to_thread(self.grants.reject, reference, binding, presented)

    async def signin(
        self,
        profile: dict[str, Any],
        binding: str,
        opener: Callable[[str], Awaitable[None]],
        secrets: set[str],
    ) -> None:
        grant = await self.flow(profile).signin(opener)
        secrets.update(v for v in (grant["access_token"], grant["refresh_token"]) if v)
        reference = profile["authentication"]["credential"]
        await asyncio.to_thread(self.grants.save, reference, binding, grant, None)

    async def logout(self, profile: dict[str, Any], binding: str, secrets: set[str]) -> str:
        reference = profile["authentication"]["credential"]
        grant = await asyncio.to_thread(self.grants.remove, reference, binding)
        if grant is None or not (grant["refresh_token"] or grant["access_token"]):
            return "not_signed_in"
        secrets.update(v for v in (grant["access_token"], grant["refresh_token"]) if v)
        try:
            await self.flow(profile).revoke(grant)
        except AuthenticationError:
            return "local_only"  # Static guidance: revoke at the provider.
        return "revoked"

    async def status(self, profile: dict[str, Any], binding: str) -> str:
        reference = profile["authentication"]["credential"]
        row, access = await asyncio.to_thread(self.grants.load, reference, binding)
        if row is None or not row["active"]:
            return "required"
        # Presence is probed in the native store itself, so an unavailable store shows.
        refresh = await asyncio.to_thread(self.grants.refresh_token, reference, binding)
        if access is not None or (row["refreshable"] and refresh is not None):
            return "configured"
        return "expired"
