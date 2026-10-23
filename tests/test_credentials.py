"""Real scoped credential references and disposable native credentials.

Only OS failure boundaries are injected; the store and reference policy are real.
Other native operating systems are exercised by the dedicated credential CI job.
"""

import hashlib
import json
import os
import sys
import uuid
from unittest.mock import patch

import pytest

from bridge_credentials import (
    CredentialError,
    CredentialStore,
    checked_reference,
    connection_binding,
)


REF = {"source": "native", "name": "fixture"}
ENV = {"source": "environment", "name": "BOTBRIDGE_MCP_FIXTURE"}
BINDING = hashlib.sha256(b"synthetic-profile").hexdigest()
CANARY = "synthetic-ticket27-credential-do-not-publish"


@pytest.mark.parametrize(
    "reference",
    [
        None,
        [],
        {},
        {"source": "native"},
        {"source": "native", "name": "bad/path"},
        {"source": "native", "name": "UPPER"},
        {"source": "native", "name": 1},
        {"source": "file", "name": "fixture"},
        {"source": "environment", "name": "CodexBot_Key"},
        {"source": "native", "name": "fixture", "value": CANARY},
    ],
)
def test_reference_policy_never_accepts_plaintext_or_foreign_credentials(reference):
    with pytest.raises(CredentialError) as error:
        checked_reference(reference)
    assert CANARY not in str(error.value)


def test_environment_is_explicit_read_only_and_status_is_masked():
    store = CredentialStore("test")
    with patch.dict(os.environ, {ENV["name"]: CANARY}):
        assert store.get(ENV, BINDING) == CANARY
        assert store.status(ENV, BINDING) == {"state": "set"}
        for operation, args in ((store.set, (CANARY,)), (store.delete, ())):
            with pytest.raises(CredentialError, match="externally managed"):
                operation(ENV, BINDING, *args)
        assert os.environ[ENV["name"]] == CANARY
        for invalid in ("", "x" * 2561):
            with patch.dict(os.environ, {ENV["name"]: invalid}):
                assert store.status(ENV, BINDING) == {"state": "unavailable"}
    with patch.dict(os.environ):
        os.environ.pop(ENV["name"], None)
        assert store.get(ENV, BINDING) is None
        assert store.status(ENV, BINDING) == {"state": "not_set"}
    assert CANARY not in json.dumps(store.status(ENV, BINDING))


def test_binding_tracks_connection_principal_and_profile():
    base = connection_binding([201, 301], "docs", {"endpoint": "https://example.com"})
    assert base == connection_binding([201, 301], "docs", {"endpoint": "https://example.com"})
    assert len(base) == 64
    for principal, alias, profile in (
        ([202, 301], "docs", {"endpoint": "https://example.com"}),
        ([201, 301], "other", {"endpoint": "https://example.com"}),
        ([201, 301], "docs", {"endpoint": "https://different.example"}),
    ):
        assert connection_binding(principal, alias, profile) != base
    for namespace in (None, "../foreign", "UPPER", "x" * 65):
        with pytest.raises(CredentialError):
            CredentialStore(namespace)
    for binding in (None, "bad", "A" * 64):
        with pytest.raises(CredentialError):
            CredentialStore("test").get(ENV, binding)


def test_unsupported_native_backend_fails_without_environment_fallback():
    with patch("sys.platform", "unsupported"), patch.dict(os.environ, {ENV["name"]: CANARY}):
        store = CredentialStore("test")
        assert store.status(REF, BINDING) == {"state": "unavailable"}
        with pytest.raises(CredentialError, match="unsupported"):
            store.get(REF, BINDING)


@pytest.mark.skipif(
    sys.platform != "win32" and os.environ.get("BOTBRIDGE_TEST_NATIVE_CREDENTIALS") != "1",
    reason="Native keychain requires the isolated credential CI/session",
)
def test_native_disposable_roundtrip_update_scoping_and_delete():
    store = CredentialStore("test-" + uuid.uuid4().hex)
    other = connection_binding([202], "other", {})
    try:
        assert store.get(REF, BINDING) is None
        assert store.status(REF, BINDING) == {"state": "not_set"}
        store.set(REF, BINDING, CANARY)
        assert store.get(REF, BINDING) == CANARY
        assert store.get(REF, other) is None
        assert store.status(REF, BINDING) == {"state": "set"}
        for value in ("unicode-\U0001f600-\u00e9", "x" * 2560):
            store.set(REF, BINDING, value)
            assert store.get(REF, BINDING) == value
        for invalid in ("", None, "\0", "x" * 2561, "\ud800"):
            with pytest.raises(CredentialError):
                store.set(REF, BINDING, invalid)
        assert store.get(REF, BINDING) == "x" * 2560
        store.delete(REF, BINDING)
        store.delete(REF, BINDING)
        assert store.get(REF, BINDING) is None
    finally:
        store.delete(REF, BINDING)
        store.delete(REF, other)


@pytest.mark.skipif(sys.platform != "win32", reason="Actual Windows credential API boundary")
def test_native_access_failures_do_not_expose_os_error_or_use_plaintext(tmp_path):
    import ctypes

    store = CredentialStore("test-" + uuid.uuid4().hex)
    backend = store._backend()

    def denied(*args):
        ctypes.set_last_error(5)
        return 0

    for attribute, operation, args in (
        ("read", store.get, ()),
        ("write", store.set, (CANARY,)),
        ("remove", store.delete, ()),
    ):
        with patch.object(backend, attribute, denied), pytest.raises(CredentialError) as error:
            operation(REF, BINDING, *args)
        assert CANARY not in str(error.value)
    with patch.object(backend, "read", side_effect=OSError(CANARY)):
        assert store.status(REF, BINDING) == {"state": "unavailable"}
    assert not list(tmp_path.iterdir())
