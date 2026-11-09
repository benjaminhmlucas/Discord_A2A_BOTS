from pathlib import Path
from unittest.mock import patch

import pytest

from bridge_control_config import ControlConfig, revision
from initialize import initialize


def configured(tmp_path):
    source = Path(__file__).resolve().parent.parent
    for name in (
        "bridge_config.example.json",
        "local_settings.example.json",
        "public_context.example.md",
    ):
        (tmp_path / name).write_bytes((source / name).read_bytes())
    initialize(201, 301, 101, 102, 103, tmp_path)
    return ControlConfig(tmp_path)


def test_control_saves_use_runtime_validation_and_detect_conflicts(tmp_path):
    store = configured(tmp_path)
    snapshot = store.snapshot()
    config = snapshot["config"]
    config["max_turns"] = 4
    new_hash = store.save("bridge_config.json", config, snapshot["revisions"]["bridge_config.json"])
    assert store.snapshot()["config"]["max_turns"] == 4
    assert new_hash == store.snapshot()["revisions"]["bridge_config.json"]
    with pytest.raises(ValueError, match="changed"):
        store.save("bridge_config.json", config, snapshot["revisions"]["bridge_config.json"])
    current = store.snapshot()
    config["max_turns"] = 99
    with pytest.raises(ValueError):
        store.save("bridge_config.json", config, current["revisions"]["bridge_config.json"])
    assert store.snapshot() == current
    assert not list(tmp_path.glob(".control-*"))


def test_control_work_confirmation_settings_context_and_redaction(tmp_path):
    store = configured(tmp_path)
    snapshot = store.snapshot()
    snapshot["config"]["allow_work"] = True
    with pytest.raises(ValueError, match="risk confirmation"):
        store.save(
            "bridge_config.json", snapshot["config"], snapshot["revisions"]["bridge_config.json"]
        )
    store.save(
        "bridge_config.json",
        snapshot["config"],
        snapshot["revisions"]["bridge_config.json"],
        confirm_work=True,
    )
    snapshot = store.snapshot()
    store.save(
        "local_settings.json", snapshot["settings"], snapshot["revisions"]["local_settings.json"]
    )
    store.save(
        "public_context.md", "new public context", snapshot["revisions"]["public_context.md"]
    )
    assert store.snapshot()["context"] == "new public context"
    (tmp_path / "private_memory/MEMORY.md").write_text(
        "<!--PRIVATE:START-->SYNTHETIC-HIDDEN<!--PRIVATE:END-->", encoding="utf-8"
    )
    assert store.redact("Visible SYNTHETIC-HIDDEN") == "Visible [private]"
    snapshot = store.snapshot()
    snapshot["settings"]["memory_dir"] = str(tmp_path / "private_memory")
    store.save(
        "local_settings.json", snapshot["settings"], snapshot["revisions"]["local_settings.json"]
    )
    assert store.redact("SYNTHETIC-HIDDEN") == "[private]"


def test_control_rejects_invalid_files_and_settings(tmp_path):
    store = configured(tmp_path)
    snapshot = store.snapshot()
    with pytest.raises(ValueError):
        store.path("../outside.json")
    linked = tmp_path / "linked-context.md"
    __import__("os").link(tmp_path / "public_context.md", linked)
    with pytest.raises(ValueError, match="links denied"):
        store.path("public_context.md")
    linked.unlink()
    for settings in (
        [],
        {},
        {**snapshot["settings"], "memory_dir": ""},
        {**snapshot["settings"], "memory_dir": 3},
        {**snapshot["settings"], "memory_dir": "a\0b"},
        {**snapshot["settings"], "memory_dir": "x" * 4097},
    ):
        with pytest.raises(ValueError):
            store.validate(snapshot["config"], settings)
    config = {
        **snapshot["config"],
        "memory": {
            "enabled": True,
            "root": str(tmp_path),
            "files": {},
            "user_ids": [201],
            "bot_ids": [101],
            "credential_env": [],
        },
    }
    with pytest.raises(ValueError, match="same root"):
        store.validate(config, snapshot["settings"])
    for name, value in (
        ("unknown", {}),
        ("public_context.md", []),
        ("public_context.md", "x" * 1048577),
    ):
        with pytest.raises(ValueError):
            store.save(name, value, snapshot["revisions"].get(name))
    (tmp_path / "public_context.md").write_bytes(b"x" * 1048577)
    with pytest.raises(ValueError, match="file denied"):
        store.read("public_context.md")


@pytest.mark.parametrize("change_at", [4, 5])
def test_control_external_changes_busy_lock_and_partial_failure(tmp_path, change_at):
    store = configured(tmp_path)
    snapshot = store.snapshot()
    expected = snapshot["revisions"]["public_context.md"]
    with store.storage.lock(), pytest.raises(ValueError, match="busy"):
        store.save("public_context.md", "new", expected)
    original_files = {name: (tmp_path / name).read_bytes() for name in snapshot["revisions"]}
    real_read = store.read
    calls = 0

    def changed(name):
        nonlocal calls
        calls += 1
        if calls == change_at:
            import json

            settings = json.loads((tmp_path / "local_settings.json").read_text())
            settings["node_executable"] = "external-editor-node"
            (tmp_path / "local_settings.json").write_text(json.dumps(settings))
        return real_read(name)

    with patch.object(store, "read", changed), pytest.raises(ValueError, match="changed"):
        store.save("public_context.md", "new", expected)
    for name, data in original_files.items():
        (tmp_path / name).write_bytes(data)
    with (
        patch.object(store.storage, "atomic", side_effect=OSError("simulated")),
        pytest.raises(OSError),
    ):
        store.save("public_context.md", "new", expected)
    assert store.snapshot() == snapshot
    original_atomic = store.storage.atomic

    def raced(name, data):
        original_atomic(name, data)
        (tmp_path / name).write_text("external editor", encoding="utf-8")

    with (
        patch.object(store.storage, "atomic", raced),
        pytest.raises(RuntimeError, match="verification"),
    ):
        store.save("public_context.md", "new", expected)
    assert revision(b"new") != expected
