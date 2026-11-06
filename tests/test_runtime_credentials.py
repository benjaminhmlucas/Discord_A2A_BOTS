import os
from unittest.mock import patch

import pytest

import bridge_providers as providers
from bridge_credentials import CredentialError, CredentialStore
from bridge_runtime_credentials import RuntimeCredentials, native_names, save_runtime_credential
from test_control_config import configured

SECRET = "synthetic-runtime-credential-canary"


class Backend:
    def __init__(self):
        self.values = {}

    def get(self, key):
        return self.values.get(key)

    def set(self, key, value):
        self.values[key] = value

    def delete(self, key):
        self.values.pop(key, None)


def test_runtime_credential_save_delete_and_provider_lookup(tmp_path):
    store = configured(tmp_path)
    backend = Backend()
    config = store.snapshot()["config"]
    with patch.object(CredentialStore, "_backend", return_value=backend):
        native = RuntimeCredentials(config, tmp_path)
        assert native.status("CODEXBOT_TOKEN") == {"state": "not_set"}
        with pytest.raises(CredentialError, match="unavailable"):
            native.required("CODEXBOT_TOKEN")
        with pytest.raises(CredentialError, match="Unknown"):
            native.reference("UNRELATED")
        snapshot = store.snapshot()
        result = save_runtime_credential(
            store, "CODEXBOT_TOKEN", SECRET, snapshot["revisions"]["local_settings.json"]
        )
        assert result == {"name": "CODEXBOT_TOKEN", "state": "set"}
        snapshot = store.snapshot()
        assert snapshot["settings"]["runtime_credentials"] == ["CODEXBOT_TOKEN"]
        assert native.required("CODEXBOT_TOKEN") == SECRET
        assert native.status("CODEXBOT_TOKEN") == {"state": "set"}
        assert SECRET not in str(snapshot) and SECRET not in str(result)
        with (
            patch.object(providers, "_settings", snapshot["settings"]),
            patch.object(providers, "ROOT", tmp_path),
            patch.object(providers, "read_identity_config", return_value=config),
        ):
            assert providers.secret("CODEXBOT_TOKEN") == SECRET
        result = save_runtime_credential(
            store, "CODEXBOT_TOKEN", None, snapshot["revisions"]["local_settings.json"], remove=True
        )
        assert result == {"name": "CODEXBOT_TOKEN", "state": "not_set"}
        assert not backend.values
        assert native_names(store.snapshot()["settings"]) == ["CODEXBOT_TOKEN"]


@pytest.mark.parametrize("previous", [None, "synthetic-previous-value"])
def test_runtime_credential_rolls_back_on_config_failure(tmp_path, previous):
    store = configured(tmp_path)
    backend = Backend()
    snapshot = store.snapshot()
    with patch.object(CredentialStore, "_backend", return_value=backend):
        native = RuntimeCredentials(snapshot["config"], tmp_path)
        reference, binding = native.reference("GEMINI_API_KEY")
        if previous is not None:
            native.auth.store.set(reference, binding, previous)
        before = dict(backend.values)
        with (
            patch.object(store, "save", side_effect=ValueError("conflict")),
            pytest.raises(ValueError),
        ):
            save_runtime_credential(
                store, "GEMINI_API_KEY", SECRET, snapshot["revisions"]["local_settings.json"]
            )
        assert backend.values == before and store.snapshot() == snapshot
        original_get = Backend.get
        reads = 0

        def mismatched(instance, key):
            nonlocal reads
            reads += 1
            return "wrong-readback" if reads == 2 else original_get(instance, key)

        with (
            patch.object(Backend, "get", mismatched),
            pytest.raises(CredentialError, match="verification"),
        ):
            save_runtime_credential(
                store, "GEMINI_API_KEY", SECRET, snapshot["revisions"]["local_settings.json"]
            )
        assert backend.values == before and store.snapshot() == snapshot


def test_runtime_credential_policy_and_stale_metadata_fail_before_store_access(tmp_path):
    store = configured(tmp_path)
    snapshot = store.snapshot()
    assert native_names({}) == []
    for names in (None, "CODEXBOT_TOKEN", ["UNKNOWN"], ["CODEXBOT_TOKEN", "CODEXBOT_TOKEN"], [{}]):
        with pytest.raises(ValueError, match="references"):
            native_names({"runtime_credentials": names})
        with pytest.raises(ValueError):
            store.validate(
                snapshot["config"], {**snapshot["settings"], "runtime_credentials": names}
            )
    with patch.object(CredentialStore, "_backend", side_effect=AssertionError("unexpected store")):
        with pytest.raises(ValueError, match="action"):
            save_runtime_credential(store, "CODEXBOT_TOKEN", SECRET, "stale", remove=1)
        with pytest.raises(CredentialError):
            save_runtime_credential(store, "CODEXBOT_TOKEN", "", "stale")
        with pytest.raises(ValueError, match="changed"):
            save_runtime_credential(store, "CODEXBOT_TOKEN", SECRET, "stale")


def test_control_never_saves_or_returns_known_credentials(tmp_path):
    store = configured(tmp_path)
    backend = Backend()
    with patch.object(CredentialStore, "_backend", return_value=backend):
        save_runtime_credential(
            store, "CODEXBOT_TOKEN", SECRET, store.snapshot()["revisions"]["local_settings.json"]
        )
        snapshot = store.snapshot()
        assert store.redact("Visible " + SECRET) == "Visible [private]"
        for value in (SECRET, "AIza" + "x" * 35):
            with pytest.raises(ValueError, match="credential screen"):
                store.save("public_context.md", value, snapshot["revisions"]["public_context.md"])
        assert store.snapshot() == snapshot
        escaped = 'synthetic-"quoted"\ncredential'
        save_runtime_credential(
            store, "CODEXBOT_TOKEN", escaped, store.snapshot()["revisions"]["local_settings.json"]
        )
        with pytest.raises(ValueError, match="credential screen"):
            store.save(
                "public_context.md", "Prefix " + escaped, snapshot["revisions"]["public_context.md"]
            )
        (tmp_path / "public_context.md").write_text(escaped, encoding="utf-8")
        with pytest.raises(ValueError, match="credential screen"):
            store.snapshot()


@pytest.mark.skipif(
    os.name != "nt" and os.environ.get("BOTBRIDGE_TEST_NATIVE_CREDENTIALS") != "1",
    reason="Native store roundtrip runs on Windows and the dedicated native-store jobs",
)
def test_runtime_credential_native_roundtrip_is_disposable(tmp_path):
    store = configured(tmp_path)
    native = RuntimeCredentials(store.snapshot()["config"], tmp_path)
    reference, binding = native.reference("GEMINI_API_KEY")
    try:
        result = save_runtime_credential(
            store, "GEMINI_API_KEY", SECRET, store.snapshot()["revisions"]["local_settings.json"]
        )
        assert result["state"] == "set"
        assert native.required("GEMINI_API_KEY") == SECRET
        assert SECRET not in str(store.snapshot())
        save_runtime_credential(
            store,
            "GEMINI_API_KEY",
            None,
            store.snapshot()["revisions"]["local_settings.json"],
            remove=True,
        )
        assert native.optional("GEMINI_API_KEY") is None
    finally:
        native.auth.store.delete(reference, binding)
