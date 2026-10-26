"""Real OAuth/manager refresh retries; only the native credential API can fail."""

import asyncio
import json

import pytest

from bridge_credentials import CredentialError
from bridge_oauth_flow import GrantRejected
from test_oauth_grants import MemoryCredentials, OAuthService, TOKEN_PREFIX, browser
from test_grant_partial_writes import isolated_caps


class OneFailedWrite(MemoryCredentials):
    def __init__(self):
        super().__init__()
        self.fail_part = None
        self.failed = False
        self.deleted = []

    def set(self, key, value):
        if self.fail_part and key.endswith("/" + self.fail_part) and not self.failed:
            self.failed = True
            raise OSError("synthetic native hiccup " + value)
        super().set(key, value)

    def delete(self, key):
        self.deleted.append(key)
        super().delete(key)


@pytest.mark.parametrize("part,rotate", [("access", True), ("refresh", False), ("refresh", True)])
def test_transient_refresh_storage_failure_retries_without_disabling_grant(tmp_path, part, rotate):
    async def scenario():
        async with OAuthService() as service:
            service.rotate = rotate
            backend = OneFailedWrite()
            caps = isolated_caps(service.origin, tmp_path, backend)
            auth, profile = caps.authentication, caps.registry.profile("docs")
            binding = auth.binding("docs", profile)
            reference = profile["authentication"]["credential"]
            grants = auth.oauth.grants
            try:
                await auth.signin("docs", profile, browser, set())
                initial, _ = grants.load(reference, binding)
                old_refresh = grants.refresh_token(reference, binding)
                grants.mark(binding, initial["generation"], refreshable=True)
                before, _ = grants.load(reference, binding)
                backend.fail_part = part
                backend.deleted.clear()
                with pytest.raises(CredentialError) as error:
                    await caps.connections.discover("docs")
                assert TOKEN_PREFIX not in str(error.value)
                after, access = grants.load(reference, binding)
                assert after == before and after["active"] and after["refreshable"]
                assert after["expires"] == 0 and access is None
                assert backend.deleted == []
                assert service.exchanges == ["authorization_code", "refresh_token"]
                stored_refresh = grants.refresh_token(reference, binding)
                assert (stored_refresh == old_refresh) is (part == "refresh")
                if part == "refresh" and rotate:
                    with pytest.raises(GrantRejected) as refusal:
                        await caps.connections.discover("docs")
                    assert TOKEN_PREFIX not in str(refusal.value)
                    row, _ = grants.load(reference, binding)
                    assert row["active"] and not row["refreshable"]
                    assert row["generation"] == before["generation"]
                    assert (await auth.status("docs", profile))["authentication"] == "expired"
                else:
                    assert await caps.connections.discover("docs")
                    assert (await auth.status("docs", profile))["authentication"] == "configured"
                assert service.exchanges == ["authorization_code", "refresh_token", "refresh_token"]
                assert len(service.authorizations) == 1
                assert backend.deleted == []
                assert TOKEN_PREFIX not in json.dumps(await auth.status("docs", profile))
                assert TOKEN_PREFIX.encode() not in grants.path.read_bytes()
            finally:
                backend.fail_part = None
                await auth.logout("docs", profile, set())
                assert backend.values == {}

    asyncio.run(scenario())
