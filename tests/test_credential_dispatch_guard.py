"""Actual selected credentials guard dispatch after a transient native snapshot failure."""

import asyncio
import json

import pytest

from test_bridge import Bridge, Channel, Client, Message
from test_capabilities import C, config_for
from test_oauth_grants import MemoryCredentials, OAuthService


class ReadOnceUnavailable(MemoryCredentials):
    """Only the native OS API boundary fails; all bridge admission/transport stays real."""

    def __init__(self):
        super().__init__()
        self.reads = 0

    def get(self, key):
        self.reads += 1
        if self.reads == 1:
            raise OSError("synthetic transient native read unavailable")
        return super().get(key)


@pytest.mark.parametrize("credential_argument", [True, False])
def test_selected_resolved_credential_guards_dispatch_after_snapshot_read_failure(
    tmp_path, credential_argument
):
    async def scenario():
        async with OAuthService() as service:
            secret = "synthetic-pr30-transient-native-read-canary"
            (tmp_path / "MEMORY.md").write_text("public synthetic memory")
            (tmp_path / "public_context.md").write_text(secret)
            config = config_for(service.origin)
            profile = config["capabilities"]["connections"]["servers"]["fixture"]
            reference = {"source": "native", "name": "fixture"}
            profile["authentication"] = {"type": "bearer", "credential": reference}
            prompts, logs = [], []

            async def provider(prompt, work=False):
                prompts.append(prompt)
                return "synthetic provider answer"

            bridge = Bridge(Client(C), C, provider, logs.append, tmp_path, tmp_path, config=config)
            caps = bridge.capabilities
            native = ReadOnceUnavailable()
            caps.authentication.store._native = native
            binding = caps.authentication.binding("fixture", profile)
            try:
                await caps.authentication.set_credential("fixture", profile, "fixture", secret)
                service.access.add(secret)
                query = secret if credential_argument else "public query"
                request = f"<@{C}> /mcp lookup " + json.dumps({"query": query})
                channel = Channel()
                await bridge.handle(Message(1, request, channel))
                assert native.reads >= 2  # Snapshot failed; selected resolution succeeded.
                tool_calls = [method for method, _ in service.calls if method == "tools/call"]
                if credential_argument:
                    assert not tool_calls
                    assert not prompts
                else:
                    assert len(tool_calls) == 1 and len(prompts) == 1
                    assert "REDACTED CREDENTIAL" in prompts[0]
                assert all(secret not in text for text in prompts + logs)
                assert all(secret not in message.content for message, _ in channel.sent)
                assert not caps.connections._active
            finally:
                caps.authentication.store.delete(reference, binding)
                assert not native.values

    asyncio.run(scenario())
