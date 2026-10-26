"""Partial native writes through real OAuth, grant metadata, and dispatch policy.

Only the OS credential boundary is synthetic; no native credential API is used.
"""

import asyncio
from contextlib import closing
import sqlite3

import pytest

from bridge_auth_policy import AuthenticationError
from bridge_capabilities import Capabilities
from bridge_credentials import CredentialError
from test_oauth_grants import MemoryCredentials, OAuthService, TOKEN_PREFIX, browser, oauth_config


class PartialWrites(MemoryCredentials):
    def __init__(self, after_write, failed_deletes):
        super().__init__()
        self.after_write = after_write
        self.failed_deletes = set(failed_deletes)
        self.fail_access = True
        self.deletes = []
        self.writes = []

    def set(self, key, value):
        self.writes.append(key.rsplit("/", 1)[-1])
        if key.endswith("/access") and self.fail_access:
            if self.after_write:
                super().set(key, value)
            raise OSError("synthetic failure containing " + value)
        super().set(key, value)

    def delete(self, key):
        part = key.rsplit("/", 1)[-1]
        self.deletes.append(part)
        if part in self.failed_deletes:
            raise OSError("synthetic deletion failure")
        super().delete(key)


def test_metadata_failure_rolls_back_rejection_and_preserves_the_valid_grant(tmp_path):
    async def scenario():
        async with OAuthService() as service:
            backend = PartialWrites(False, ())
            backend.fail_access = False
            caps = isolated_caps(service.origin, tmp_path, backend)
            auth, profile = caps.authentication, caps.registry.profile("docs")
            binding = auth.binding("docs", profile)
            reference = profile["authentication"]["credential"]
            grants = auth.oauth.grants
            await auth.signin("docs", profile, browser, set())
            before, access = grants.load(reference, binding)
            try:
                with closing(sqlite3.connect(grants.path)) as db:
                    db.execute(
                        "CREATE TRIGGER reject_metadata_write BEFORE UPDATE ON oauth_grants "
                        "BEGIN SELECT RAISE(ABORT, 'synthetic metadata storage failure'); END"
                    )
                    db.commit()
                with pytest.raises(sqlite3.IntegrityError, match="metadata storage failure"):
                    grants.reject(reference, binding, "Bearer " + access)
                after, current = grants.load(reference, binding)
                assert after == before and current == access
                assert (await auth.status("docs", profile))["authentication"] == "configured"
                assert await caps.connections.discover("docs")
            finally:
                with closing(sqlite3.connect(grants.path)) as db:
                    db.execute("DROP TRIGGER IF EXISTS reject_metadata_write")
                    db.commit()
                await auth.logout("docs", profile, set())
                assert backend.values == {}

    asyncio.run(scenario())


def isolated_caps(origin, root, backend):
    caps = Capabilities(oauth_config(origin), lambda _: None, root)
    # Unconditional on Windows too: never instantiate an OS credential adapter.
    caps.authentication.store._native = backend
    return caps


@pytest.mark.parametrize(
    "after_write", [False, True], ids=["before-access-write", "after-access-write"]
)
@pytest.mark.parametrize("failed_deletes", [(), ("refresh",), ("access",), ("refresh", "access")])
def test_first_signin_partial_write_is_disabled_and_cleanup_remains_reachable(
    tmp_path, after_write, failed_deletes
):
    async def scenario():
        async with OAuthService() as service:
            backend = PartialWrites(after_write, failed_deletes)
            caps = isolated_caps(service.origin, tmp_path, backend)
            auth, profile = caps.authentication, caps.registry.profile("docs")
            binding = auth.binding("docs", profile)
            reference = profile["authentication"]["credential"]
            with pytest.raises(
                CredentialError, match="grant disabled after native write failure"
            ) as error:
                await auth.signin("docs", profile, browser, set())
            assert TOKEN_PREFIX not in str(error.value)
            assert backend.writes == ["refresh", "access"]
            # Failure deleting refresh must not prevent attempting access cleanup.
            assert backend.deletes == ["refresh", "access"]
            expected_parts = set(failed_deletes) & (
                {"refresh", "access"} if after_write else {"refresh"}
            )
            assert {key.rsplit("/", 1)[-1] for key in backend.values} == expected_parts
            assert service.exchanges == ["authorization_code"]
            assert service.calls == []
            # A newly constructed consumer must observe durable inactive metadata.
            restarted = isolated_caps(service.origin, tmp_path, backend)
            auth = restarted.authentication
            row, access = auth.oauth.grants.load(reference, binding)
            assert row is not None and row["generation"] == 1
            assert not row["active"] and not row["refreshable"] and row["expires"] == 0
            assert access is None
            assert (await auth.status("docs", profile))["authentication"] == "required"
            with pytest.raises(AuthenticationError, match="sign-in required"):
                await restarted.connections.discover("docs")
            assert service.calls == [] and service.exchanges == ["authorization_code"]
            # Recover the OS boundary and retry logout. Tombstone keeps partial
            # first-signin entries reachable for deletion and remote revocation.
            remaining = set(backend.values.values())
            backend.failed_deletes.clear()
            result = await auth.logout("docs", profile, set())
            assert result == {
                "authentication": "required",
                "revocation": "revoked" if remaining else "not_signed_in",
            }
            assert backend.values == {}
            # Existing revoke contract prefers refresh, falling back to access.
            expected_revoke = (
                TOKEN_PREFIX + "refresh-1"
                if "refresh" in expected_parts
                else TOKEN_PREFIX + "access-1"
            )
            assert service.revocations == ([expected_revoke] if remaining else [])
            assert (await auth.status("docs", profile))["authentication"] == "required"
            with sqlite3.connect(auth.oauth.grants.path) as db:
                assert db.execute(
                    "SELECT generation, active, refreshable FROM oauth_grants WHERE binding = ?",
                    (binding,),
                ).fetchone() == (2, 0, 0)
            assert TOKEN_PREFIX.encode() not in auth.oauth.grants.path.read_bytes()

    asyncio.run(scenario())


def test_ordinary_valid_grant_still_dispatches_and_logs_out(tmp_path):
    async def scenario():
        async with OAuthService() as service:
            backend = MemoryCredentials()
            caps = isolated_caps(service.origin, tmp_path, backend)
            auth, profile = caps.authentication, caps.registry.profile("docs")
            await auth.signin("docs", profile, browser, set())
            assert (await auth.status("docs", profile))["authentication"] == "configured"
            restarted = isolated_caps(service.origin, tmp_path, backend)
            assert (await restarted.connections.discover("docs"))[0]["name"] == "read_example"
            assert service.calls == [("tools/list", "Bearer " + TOKEN_PREFIX + "access-1")]
            assert service.exchanges == ["authorization_code"]
            assert (await restarted.authentication.logout("docs", profile, set()))[
                "revocation"
            ] == "revoked"
            assert backend.values == {}
            assert service.revocations == [TOKEN_PREFIX + "refresh-1"]

    asyncio.run(scenario())
