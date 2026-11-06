import copy

import pytest

from bridge_control_forms import edits, form, integer
from control_gui import save_document
from test_control_config import configured


def test_typed_forms_roundtrip_without_rounding_ids(tmp_path):
    store = configured(tmp_path)
    snapshot = store.snapshot()
    for section in ("Discord", "Access", "Providers", "Limits"):
        values = {key: field["value"] for key, field in form(snapshot["config"], section).items()}
        if section == "Discord":
            values["owner_id"] = "9007199254740993"
        save_document(
            store,
            {
                "name": "bridge_config.json",
                "section": section,
                "typed": True,
                "value": values,
                "revision": snapshot["revisions"]["bridge_config.json"],
            },
        )
        snapshot = store.snapshot()
    assert snapshot["config"]["owner_id"] == 9007199254740993
    assert form(snapshot["config"], "Discord")["owner_id"]["value"] == "9007199254740993"
    values = {key: field["value"] for key, field in form(snapshot["config"], "Access").items()}
    values["allow_work"] = True
    values["allowed_user_ids"] = "9007199254740993, 202"
    with pytest.raises(ValueError, match="risk confirmation"):
        save_document(
            store,
            {
                "name": "bridge_config.json",
                "section": "Access",
                "typed": True,
                "value": values,
                "revision": snapshot["revisions"]["bridge_config.json"],
            },
        )
    save_document(
        store,
        {
            "name": "bridge_config.json",
            "section": "Access",
            "typed": True,
            "value": values,
            "revision": snapshot["revisions"]["bridge_config.json"],
            "confirm_work": True,
        },
    )
    assert store.snapshot()["config"]["allowed_user_ids"] == [9007199254740993, 202]


def test_typed_form_shapes_and_types_fail_closed(tmp_path):
    store = configured(tmp_path)
    config = store.snapshot()["config"]
    with pytest.raises(ValueError):
        form(config, "Connections")
    for values in ([], {}, {"unexpected": "input"}):
        with pytest.raises(ValueError, match="Incomplete"):
            edits(config, "Discord", values)
    for value in (None, 201, "-1", "１２３", "1.5", ""):
        with pytest.raises(ValueError):
            integer(value)
    for value in (None, "x" * 4097, "a\0b"):
        values = {key: field["value"] for key, field in form(config, "Providers").items()}
        values["codex_model"] = value
        with pytest.raises(ValueError):
            edits(config, "Providers", values)
    values = {key: field["value"] for key, field in form(config, "Access").items()}
    for value in (1, "true", None):
        invalid = copy.deepcopy(values)
        invalid["codex"] = value
        with pytest.raises(ValueError, match="switch"):
            edits(config, "Access", invalid)
    values["codex"] = False
    assert 101 not in edits(config, "Access", values)["enabled_bots"]
