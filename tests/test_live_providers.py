"""Explicit private opt-in: real authenticated providers, never Discord messages."""

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest
from test_native_setup import export_into

pytestmark = pytest.mark.skipif(
    os.environ.get("BOTBRIDGE_RUN_PROVIDER_TESTS") != "1",
    reason="Real provider tests require explicit private opt-in and authenticated accounts",
)


@pytest.mark.parametrize("name", ["codex", "claude", "gemini"])
def test_actual_authenticated_provider_reply(tmp_path, name):
    root = tmp_path / "private-provider-smoke"
    root.mkdir()
    export_into(root)
    env = os.environ.copy()
    env.pop("BOTBRIDGE_CONFIG_FILE", None)
    settings = json.loads(Path(env["BOTBRIDGE_PROVIDER_TEST_SETTINGS"]).read_text())
    local = json.loads((root / "local_settings.example.json").read_text())
    for key in ("node_executable", "codex_cli", "claude_cli"):
        local[key] = settings[key]
    (root / "local_settings.json").write_text(json.dumps(local))
    (root / "chat_runtime").mkdir()
    (root / "private_memory").mkdir()
    config = json.loads((root / "tests/fixtures/bridge_config.json").read_text())
    config.update(codex_model=settings["codex_model"], codex_reasoning_effort="high")
    (root / "bridge_config.json").write_text(json.dumps(config))
    code = (
        f"import asyncio,bridge_providers as p; provider=p.Gemini({settings['gemini_model']!r})"
        if name == "gemini"
        else f"import asyncio,bridge_providers as p;provider=p.{name}"
    )
    code += (
        ";from bridge_runtime import DISCUSSION_CONTROL,discussion_reply;"
        "smoke=asyncio.run(provider('Reply with exactly BOTBRIDGE_PROVIDER_SMOKE_OK and nothing else. Do not use tools.'));"
        "assert smoke.strip()=='BOTBRIDGE_PROVIDER_SMOKE_OK';"
        "normal=asyncio.run(provider('You are a text-only Discord participant. Original request: discuss a movie idea; "
        "this is the first turn and nobody has agreed yet. Give one sentence and continue.'+DISCUSSION_CONTROL));"
        "assert discussion_reply(normal)[1]=='continue';"
        "blocked=asyncio.run(provider('You are a text-only Discord participant. Original request: review "
        "https://example.invalid/pull/7. If you cannot retrieve it, explain briefly and stop the discussion immediately. "
        "The link contents have not been supplied.'+DISCUSSION_CONTROL));"
        "assert discussion_reply(blocked)[1]=='stop';"
        "print('BOTBRIDGE_PROVIDER_SMOKE_OK')"
    )
    result = subprocess.run(
        [sys.executable, "-c", code], cwd=root, env=env, capture_output=True, text=True, timeout=250
    )
    assert result.returncode == 0, (
        f"{name} real provider failed; inspect private diagnostics locally"
    )
    assert result.stdout.strip() == "BOTBRIDGE_PROVIDER_SMOKE_OK", (
        f"{name} real provider response failed the exact-content check"
    )
    assert not list((root / "private_memory").iterdir())
    receipt = os.environ.get("BOTBRIDGE_TEST_PROVIDER_RECEIPT")
    if receipt:
        path = Path(receipt)
        previous = json.loads(path.read_text()) if path.exists() else {}
        previous[name] = {
            "real_authenticated_request": "passed",
            "exact_reply": "passed",
            "discussion_continue": "passed",
            "conditional_stop": "passed",
            "discord_posts": 0,
        }
        path.write_text(json.dumps(previous, indent=2) + "\n")
