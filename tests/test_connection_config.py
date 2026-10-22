"""Operator config and CLI tests exercise real validators, exports and transports."""

import json
from pathlib import Path
import runpy
import sys
from unittest.mock import patch

import pytest

from bridge_capabilities import Capabilities
from bridge_connections import Registry
from bridge_http import SafeHTTP
from test_connections import configured, stdio_profile
import mcp_connections as cli


@pytest.mark.parametrize(
    "data",
    [
        None,
        [],
        {},
        {"version": True, "servers": {}},
        {"version": 2, "servers": {}},
        {"version": 1, "servers": []},
        {"version": 1, "servers": {str(i): {} for i in range(33)}},
        {"version": 1, "servers": {"bad name": {}}},
        {"version": 1, "servers": {1: {}}},
    ],
)
def test_bad_registries(data):
    with pytest.raises(ValueError):
        Registry(data, SafeHTTP())


@pytest.mark.parametrize(
    "key,value",
    [
        ("transport", "sse"),
        ("transport", None),
        ("extra", True),
        ("command", 1),
        ("command", "relative"),
        ("command", "\0bad"),
        ("command", "x" * 1025),
        ("command", str(Path.cwd() / "launch.cmd")),
        ("arguments", {}),
        ("arguments", ["x"] * 33),
        ("arguments", [1]),
        ("arguments", ["x" * 2049]),
        ("arguments", ["bad\0arg"]),
        ("cwd", "relative"),
        ("environment", []),
        ("environment", {"k" + str(i): "v" for i in range(33)}),
        ("environment", {"bad key": "v"}),
        ("environment", {1: "v"}),
        ("environment", {"ok": 1}),
        ("environment", {"ok": "\0"}),
        ("environment", {"API_TOKEN": "plaintext-denied"}),
        ("credential_env", {"AUTH": "unscoped"}),
    ],
)
def test_bad_stdio_profiles(tmp_path, key, value):
    data = {"version": 1, "servers": {"fixture": stdio_profile(tmp_path)}}
    data["servers"]["fixture"][key] = value
    with pytest.raises(ValueError):
        Registry(data, SafeHTTP())


def test_profile_limits_conflicts_and_isolated_editing(tmp_path):
    profile = stdio_profile(tmp_path)
    for bad in (
        None,
        {},
        {"transport": "http"},
        {
            "transport": "http",
            "endpoint": "http://127.0.0.1",
            "protocol": "2025-11-25",
            "credential_env": None,
        },
        {
            "transport": "http",
            "endpoint": "https://example.com",
            "protocol": "old",
            "credential_env": None,
        },
        {
            "transport": "http",
            "endpoint": "https://example.com",
            "protocol": "2025-11-25",
            "credential_env": "ANY",
        },
    ):
        with pytest.raises(ValueError):
            Registry({"version": 1, "servers": {"a": bad}}, SafeHTTP())
    profile["environment"] = {"KEY" + str(i): "x" * 1000 for i in range(20)}
    with pytest.raises(ValueError):
        Registry({"version": 1, "servers": {"a": profile}}, SafeHTTP())
    profile = stdio_profile(tmp_path)
    profile["credential_env"] = {"FIXTURE_SETTING": "BOTBRIDGE_MCP_TEST"}
    with pytest.raises(ValueError):
        Registry({"version": 1, "servers": {"a": profile}}, SafeHTTP())
    registry = Registry({"version": 1, "servers": {}}, SafeHTTP())
    created = registry.changed("add", "a", stdio_profile(tmp_path))
    edited = created.changed("edit", "a", stdio_profile(tmp_path, "stderr"))
    assert not registry.export()["servers"]
    assert created.profile("a")["arguments"] != edited.profile("a")["arguments"]
    assert not edited.changed("remove", "a").export()["servers"]
    copied = created.profile("a")
    copied["arguments"].clear()
    assert created.profile("a")["arguments"]
    for action, name in (
        ("add", "a"),
        ("edit", "missing"),
        ("remove", "missing"),
        ("unknown", "a"),
    ):
        with pytest.raises(ValueError):
            created.changed(action, name, {})
    with pytest.raises(ValueError):
        created.profile("unknown")


@pytest.mark.parametrize(
    "key,value",
    [
        ("extra", 1),
        ("connection", 1),
        ("connection", "unknown"),
        ("name", 1),
        ("name", "bad name"),
        ("read_only", False),
        ("read_only", 1),
        ("user_ids", []),
        ("user_ids", [999]),
        ("bot_ids", [True]),
        ("input_schema", []),
        ("input_schema", {"type": "array"}),
        ("input_schema", {"type": "object"}),
        (
            "input_schema",
            {"type": "object", "additionalProperties": False, "description": "x" * 17000},
        ),
        ("fixed_arguments", []),
        ("fixed_arguments", {"payload": "overrides-dynamic"}),
        ("fixed_arguments", {"x": [1] * 33}),
    ],
)
def test_connected_tools_cannot_relax_permissions(tmp_path, key, value):
    config = configured(tmp_path)
    config["capabilities"]["tools"]["lookup"][key] = value
    with pytest.raises(ValueError):
        Capabilities(config, lambda _: None)


def test_cli_real_profile_edits_migration_and_lifecycle(tmp_path, capsys):
    config = configured(tmp_path)
    source, profile = tmp_path / "config.json", tmp_path / "profile.json"
    source.write_text(json.dumps(config))
    profile.write_text(json.dumps(stdio_profile(tmp_path)))
    original = source.read_bytes()
    args = ["--config", str(source)]
    assert cli.main(args + ["status"]) == 0
    assert '"connected": false' in capsys.readouterr().out
    for action in ("test", "discover"):
        assert cli.main(args + [action, "first"]) == 0
        result = json.loads(capsys.readouterr().out)
        assert result["outcome"] == "completed" and result["connected"] is False
    for action, name in (
        ("add", "third"),
        ("edit", "first"),
        ("remove", "second"),
        ("migrate", None),
    ):
        output = tmp_path / (action + ".json")
        command = args + [action] + ([name] if name else []) + ["--output", str(output)]
        if action in ("add", "edit"):
            command += ["--profile", str(profile)]
        assert cli.main(command) == 0
        Capabilities(json.loads(output.read_text()), lambda _: None)
        assert cli.main(command) == 1  # Exclusive exports cannot overwrite a previous result.
        assert source.read_bytes() == original
    assert cli.main(args + ["test", "missing"]) == 1
    bad = tmp_path / "bad.json"
    bad.write_bytes(b"x" * 1048577)
    assert cli.main(["--config", str(bad), "status"]) == 1
    bad.write_bytes(b"\xff")
    assert cli.main(["--config", str(bad), "status"]) == 1
    bad.write_text("[]")
    # A malformed root must be a safe diagnostic rather than an AttributeError traceback.
    assert cli.main(["--config", str(bad), "status"]) == 1
    with (
        patch.object(sys, "argv", ["mcp_connections.py", *args, "status"]),
        pytest.raises(SystemExit) as exit,
    ):
        runpy.run_module("mcp_connections", run_name="__main__")
    assert exit.value.code == 0
    assert "Traceback" not in capsys.readouterr().err


@pytest.mark.parametrize(
    "change",
    [
        {"total_request_seconds": 0},
        {"owner_id": 0},
        {"enabled_bots": [999]},
        {"bot_ids": {"codex": True, "antigravity": 102, "claude": 103}},
    ],
)
def test_cli_export_uses_runtime_validation_before_creating_output(tmp_path, capsys, change):
    config = configured(tmp_path)
    config.update(change)
    source, output = tmp_path / "source.json", tmp_path / "proposed.json"
    source.write_text(json.dumps(config))
    original = source.read_bytes()
    assert cli.main(["--config", str(source), "migrate", "--output", str(output)]) == 1
    assert not output.exists() and source.read_bytes() == original
    assert "Traceback" not in capsys.readouterr().err


def test_cli_deep_json_config_and_profile_have_static_errors(tmp_path, capsys):
    source, deep, output = (
        tmp_path / "source.json",
        tmp_path / "deep.json",
        tmp_path / "export.json",
    )
    source.write_text(json.dumps(configured(tmp_path)))
    deep.write_text("[" * 2000 + "0" + "]" * 2000)
    assert cli.main(["--config", str(deep), "status"]) == 1
    assert (
        cli.main(
            ["--config", str(source), "add", "new", "--profile", str(deep), "--output", str(output)]
        )
        == 1
    )
    assert not output.exists() and "Traceback" not in capsys.readouterr().err
