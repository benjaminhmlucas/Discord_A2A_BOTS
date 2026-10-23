"""Every native credential adapter, on every CI host, through its OS API boundary.

Only the operating-system library is replaced: advapi32 (Windows), Security.framework
(macOS) and the SecretStorage D-Bus SDK (Linux). Adapter, store, helper process and
policy code run for real. Actual native stores are exercised separately: Windows in
the normal suite and macOS/Linux in the dedicated native credential CI job.
"""

import ctypes
import json
import os
from pathlib import Path
import runpy
import subprocess
import sys
import types
from unittest.mock import patch

import coverage
import pytest

import bridge_credentials as credentials
from bridge_credentials import (
    CredentialError,
    CredentialStore,
    LinuxCredentials,
    MacCredentials,
    WindowsCredentials,
)

ROOT = Path(__file__).resolve().parent.parent
CANARY = "synthetic-ticket27-adapter-canary"
KEY = "BotBridge.MCP/test/" + "a" * 64 + "/fixture"


class Foreign:
    """A foreign-function stand-in that accepts ctypes argtypes/restype assignment."""

    def __init__(self, implementation):
        self.implementation = implementation

    def __call__(self, *args):
        return self.implementation(*args)


class Advapi:
    """Windows Credential Manager API semantics over an in-memory table."""

    def __init__(self):
        self.values, self.error, self.freed, self.kept = {}, 0, 0, []
        self.fail = set()

    def CredReadW(self, target, kind, flags, pointer):
        assert kind == 1 and flags == 0
        if "read" in self.fail or target not in self.values:
            self.error = 5 if "read" in self.fail else 1168
            return 0
        data = ctypes.create_string_buffer(self.values[target], len(self.values[target]))
        item = credentials._Credential(
            size=len(self.values[target]), blob=ctypes.cast(data, ctypes.c_void_p)
        )
        self.kept += [data, item]
        pointer._obj.contents = item
        return 1

    def CredWriteW(self, pointer, flags):
        item = pointer._obj
        assert flags == 0 and item.kind == 1 and item.persist == 2
        if "write" in self.fail:
            self.error = 5
            return 0
        self.values[item.target] = ctypes.string_at(item.blob, item.size)
        return 1

    def CredDeleteW(self, target, kind, flags):
        if "remove" in self.fail or target not in self.values:
            self.error = 5 if "remove" in self.fail else 1168
            return 0
        del self.values[target]
        return 1

    def CredFree(self, pointer):
        self.freed += 1


@pytest.fixture
def windows():
    api = Advapi()
    library = types.SimpleNamespace(
        CredReadW=Foreign(api.CredReadW),
        CredWriteW=Foreign(api.CredWriteW),
        CredDeleteW=Foreign(api.CredDeleteW),
        CredFree=Foreign(api.CredFree),
    )
    with (
        patch.object(ctypes, "WinDLL", lambda name, **_: library, create=True),
        patch.object(ctypes, "get_last_error", lambda: api.error, create=True),
    ):
        yield api, WindowsCredentials()


def test_windows_adapter_roundtrip_update_delete_and_static_failures(windows):
    api, backend = windows
    assert backend.get(KEY) is None
    backend.set(KEY, CANARY)
    assert backend.get(KEY) == CANARY and api.freed == 1
    backend.set(KEY, "unicode-é")
    assert backend.get(KEY) == "unicode-é"
    backend.delete(KEY)
    backend.delete(KEY)  # Already absent (ERROR_NOT_FOUND) is not an error.
    assert backend.get(KEY) is None
    for operation, args, failure in (
        (backend.get, (KEY,), "read"),
        (backend.set, (KEY, CANARY), "write"),
        (backend.delete, (KEY,), "remove"),
    ):
        api.fail = {failure}
        with pytest.raises(CredentialError) as error:
            operation(*args)
        assert CANARY not in str(error.value)
    api.fail = set()
    api.values[KEY] = b"\xff"
    with pytest.raises(UnicodeError):
        backend.get(KEY)  # The store maps this to a static unavailable error.
    assert api.freed == 3


class Security:
    """Security.framework generic-password semantics; interaction flag recorded."""

    def __init__(self):
        self.values, self.handles, self.calls, self.status = {}, {}, [], {}
        self.buffers = []

    def SecKeychainSetUserInteractionAllowed(self, allowed):
        self.calls.append(("interaction", allowed))
        return self.status.get("interaction", 0)

    def SecKeychainFindGenericPassword(
        self, chain, service_size, service, account_size, account, size, data, item
    ):
        assert chain is None and account == b"botbridge-mcp"
        assert service_size == len(service) and account_size == len(account)
        if "find" in self.status:
            return self.status["find"]
        if service not in self.values:
            return -25300
        handle = len(self.handles) + 100
        self.handles[handle] = service
        item._obj.value = handle
        if size is not None:
            buffer = ctypes.create_string_buffer(self.values[service], len(self.values[service]))
            self.buffers.append(buffer)
            size._obj.value = len(self.values[service])
            data._obj.value = ctypes.addressof(buffer)
        return 0

    def SecKeychainAddGenericPassword(
        self, chain, service_size, service, account_size, account, size, data, item
    ):
        assert chain is None and item is None and size == len(data)
        self.values[service] = data
        return self.status.get("add", 0)

    def SecKeychainItemModifyAttributesAndData(self, item, attributes, size, data):
        assert attributes is None and size == len(data)
        self.values[self.handles[item.value]] = data
        return self.status.get("modify", 0)

    def SecKeychainItemDelete(self, item):
        del self.values[self.handles[item.value]]
        return self.status.get("delete", 0)

    def SecKeychainItemFreeContent(self, attributes, data):
        self.calls.append("free-content")
        return 0


@pytest.fixture
def mac():
    api, released = Security(), []
    names = [
        "SecKeychainSetUserInteractionAllowed",
        "SecKeychainFindGenericPassword",
        "SecKeychainAddGenericPassword",
        "SecKeychainItemModifyAttributesAndData",
        "SecKeychainItemDelete",
        "SecKeychainItemFreeContent",
    ]
    security = types.SimpleNamespace(**{name: Foreign(getattr(api, name)) for name in names})
    core = types.SimpleNamespace(CFRelease=Foreign(lambda item: released.append(item.value)))
    libraries = {
        "/System/Library/Frameworks/Security.framework/Security": security,
        "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation": core,
    }
    with patch.object(ctypes, "CDLL", lambda path: libraries[path]):
        yield api, released


def test_mac_adapter_disables_interaction_and_roundtrips(mac):
    api, released = mac
    backend = MacCredentials()
    assert api.calls == [("interaction", False)]
    assert backend.get(KEY) is None
    backend.set(KEY, CANARY)
    assert backend.get(KEY) == CANARY
    backend.set(KEY, "rotated")
    assert backend.get(KEY) == "rotated"
    backend.delete(KEY)
    backend.delete(KEY)
    assert backend.get(KEY) is None
    assert len(released) == 4 and api.calls.count("free-content") == 2
    api.values[KEY.encode()] = b"\xff"
    with pytest.raises(UnicodeError):
        backend.get(KEY)
    assert len(released) == 5  # The item is released even when decoding fails.


@pytest.mark.parametrize("failure", ["interaction", "find", "add", "modify", "delete"])
def test_mac_adapter_failures_are_static_guidance(mac, failure):
    api, _ = mac
    if failure == "interaction":
        api.status["interaction"] = -25308
        with pytest.raises(CredentialError, match="unlock or authorize"):
            MacCredentials()
        return
    backend = MacCredentials()
    if failure in ("modify", "delete"):
        backend.set(KEY, CANARY)
    api.status[failure] = -25308  # errSecInteractionNotAllowed
    with pytest.raises(CredentialError, match="unlock or authorize") as error:
        if failure == "delete":
            backend.delete(KEY)
        else:
            backend.set(KEY, "new")
    assert CANARY not in str(error.value)


class SecretService:
    """SecretStorage SDK surface used by the adapter, with prompt/lock controls."""

    def __init__(self, path=None):
        self.path = Path(path) if path else None
        self.items = self.load()
        self.locked, self.encrypted, self.prompt, self.closed = False, True, "/", 0

    def load(self):
        if self.path and self.path.exists():
            return [tuple(item) for item in json.loads(self.path.read_text())]
        return []

    def save(self):
        if self.path:
            self.path.write_text(json.dumps(self.items))

    def module(self):
        service = self

        class Connection:
            def close(self):
                service.closed += 1

        class Item:
            def __init__(self, index):
                self.item_path = "/item/" + str(index)
                self.index = index
                self.session = None

            def ensure_not_locked(self):
                if service.locked:
                    raise RuntimeError("locked " + CANARY)

            def get_secret(self):
                assert self.session is not None
                return service.items[self.index][1].encode("latin-1")

        class Collection:
            collection_path = "/org/freedesktop/secrets/aliases/default"

            def ensure_not_locked(self):
                if service.locked:
                    raise RuntimeError("locked " + CANARY)

            def search_items(self, attributes):
                for index, (stored, _) in enumerate(service.items):
                    if stored == attributes["key"]:
                        yield Item(index)

        class Wrapper:
            def __init__(self, path, interface, connection):
                self.path, self.interface = path, interface

            def call(self, method, signature, *args):
                if method == "CreateItem":
                    properties, secret, replace = args
                    assert replace is True
                    key = properties["org.freedesktop.Secret.Item.Attributes"][1]["key"]
                    service.items = [i for i in service.items if i[0] != key]
                    service.items.append((key, secret[2].decode("latin-1")))
                    service.save()
                    return "/item/new", service.prompt
                index = int(self.path.rsplit("/", 1)[1])
                service.items[index] = ("deleted", "")
                service.save()
                return (service.prompt,)

        root = types.ModuleType("secretstorage")
        util = types.ModuleType("secretstorage.util")
        root.dbus_init = Connection
        root.get_collection_by_alias = lambda connection, alias: (
            Collection() if alias == "default" else None
        )
        util.DBusAddressWrapper = Wrapper
        util.format_secret = lambda session, value, kind: ("/session", b"", value, kind)
        util.open_session = lambda connection: types.SimpleNamespace(encrypted=service.encrypted)
        root.util = util
        return {"secretstorage": root, "secretstorage.util": util}


def test_linux_sdk_operations_are_encrypted_promptless_and_unambiguous():
    service = SecretService()
    backend = LinuxCredentials()
    with patch.dict(sys.modules, service.module()):
        assert backend._operate_direct(KEY, None) is None
        assert backend._operate_direct(KEY, CANARY) is None
        assert backend._operate_direct(KEY, None) == CANARY
        assert backend._operate_direct(KEY, None, remove=True) is None
        assert backend._operate_direct(KEY, None) is None
        service.items = [(KEY, "one"), (KEY, "two")]
        with pytest.raises(CredentialError, match="Ambiguous"):
            backend._operate_direct(KEY, None)
        service.items = [(KEY, "one")]
        service.encrypted = False
        for value in (None, CANARY):
            with pytest.raises(CredentialError, match="Encrypted"):
                backend._operate_direct(KEY, value)
        service.encrypted, service.prompt = True, "/org/freedesktop/secrets/prompt/1"
        with pytest.raises(CredentialError, match="interaction denied"):
            backend._operate_direct(KEY, CANARY)
        with pytest.raises(CredentialError, match="interaction denied"):
            backend._operate_direct(KEY, None, remove=True)
        service.prompt, service.locked = "/", True
        with pytest.raises(RuntimeError):
            backend._operate_direct(KEY, None)
    assert service.closed == 11  # Every operation closed its D-Bus connection.


def fake_package(tmp_path, store):
    package = tmp_path / "fake_sdk" / "secretstorage"
    package.mkdir(parents=True)
    source = Path(__file__).read_text(encoding="utf-8")
    start = source.index("class SecretService:")
    end = source.index("def test_linux_sdk_operations")
    (package / "service.py").write_text(
        "import json\nimport types\nfrom pathlib import Path\n"
        + f"CANARY = {CANARY!r}\n"
        + source[start:end]
        + "\nMODULES = SecretService("
        + repr(str(store))
        + ").module()\n"
    )
    (package / "__init__.py").write_text(
        "from secretstorage.service import MODULES\n"
        "dbus_init = MODULES['secretstorage'].dbus_init\n"
        "get_collection_by_alias = MODULES['secretstorage'].get_collection_by_alias\n"
    )
    (package / "util.py").write_text(
        "from secretstorage.service import MODULES\n"
        "_util = MODULES['secretstorage.util']\n"
        "DBusAddressWrapper = _util.DBusAddressWrapper\n"
        "format_secret = _util.format_secret\n"
        "open_session = _util.open_session\n"
    )
    return package.parent


def run_helper(tmp_path, sdk, request, number):
    datafile = tmp_path / f"helper-{number}.coverage"
    env = {
        k: v
        for k, v in os.environ.items()
        if k.upper() in {"SYSTEMROOT", "WINDIR", "PATH", "TEMP", "TMP"}
    }
    env["PYTHONPATH"] = str(sdk)
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "coverage",
            "run",
            "--data-file",
            str(datafile),
            "bridge_credential_host.py",
        ],
        cwd=ROOT,
        env=env,
        input=request if isinstance(request, bytes) else json.dumps(request).encode(),
        capture_output=True,
        timeout=30,
        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
    )
    active = coverage.Coverage.current()
    if active:
        child = coverage.CoverageData(basename=str(datafile))
        child.read()
        active.get_data().update(child)
    return result


def test_linux_helper_process_contract_measured_in_real_subprocesses(tmp_path):
    # Import guard without running main in the pytest process.
    runpy.run_path(str(ROOT / "bridge_credential_host.py"), run_name="helper_library")
    store = tmp_path / "store.json"
    sdk = fake_package(tmp_path, store)
    requests = [
        ({"key": KEY, "value": CANARY, "remove": False}, 0, {"value": None}),
        ({"key": KEY, "value": None, "remove": False}, 0, {"value": CANARY}),
        ({"key": KEY, "value": None, "remove": True}, 0, {"value": None}),
        ({"key": KEY, "value": None, "remove": False}, 0, {"value": None}),
        ({"key": "Foreign/" + KEY, "value": None, "remove": False}, 1, None),
        ({"key": KEY, "value": None}, 1, None),
        ({"key": KEY, "value": None, "remove": 1}, 1, None),
        ({"key": KEY * 3, "value": None, "remove": False}, 1, None),
        ({"key": KEY, "value": "", "remove": False}, 1, None),
        ([], 1, None),
        (b"\xff", 1, None),
    ]
    for number, (request, code, response) in enumerate(requests):
        result = run_helper(tmp_path, sdk, request, number)
        assert result.returncode == code and result.stderr == b""
        assert (json.loads(result.stdout) if response is not None else result.stdout) == (
            response if response is not None else b""
        )
    # A malformed stored value is refused by the helper rather than returned.
    store.write_text(json.dumps([[KEY, ""]]))
    refused = run_helper(tmp_path, sdk, requests[1][0], 99)
    assert refused.returncode == 1 and refused.stdout == refused.stderr == b""


def test_linux_parent_uses_the_bounded_helper_end_to_end(tmp_path):
    store = tmp_path / "store.json"
    sdk = fake_package(tmp_path, store)
    backend = LinuxCredentials()
    with patch.dict(os.environ, {"PYTHONPATH": str(sdk)}):
        assert backend.get(KEY) is None
        backend.set(KEY, CANARY)
        assert backend.get(KEY) == CANARY
        backend.delete(KEY)
        assert backend.get(KEY) is None
    real = subprocess.run
    for stdout, code, message in (
        (b"x" * 16385, 0, "unavailable"),
        (b'{"other": 1}', 0, "Invalid credential helper"),
        (b"[]", 0, "Invalid credential helper"),
        (b"not json", 0, "timed out"),
        (b"", 1, "unavailable"),
    ):
        with patch(
            "subprocess.run",
            lambda *a, stdout_value=stdout, code_value=code, **k: subprocess.CompletedProcess(
                a, code_value, stdout_value
            ),
        ):
            with pytest.raises(CredentialError, match=message):
                backend.get(KEY)
    assert subprocess.run is real


@pytest.mark.parametrize(
    "platform,adapter", [("win32", "WindowsCredentials"), ("darwin", "MacCredentials")]
)
def test_store_selects_only_the_platform_adapter(platform, adapter):
    selected = []
    with (
        patch("sys.platform", platform),
        patch.object(credentials, adapter, lambda: selected.append(adapter) or object()),
    ):
        store = CredentialStore("test")
        assert store._backend() is store._backend()
    assert selected == [adapter]


def test_store_selects_linux_and_maps_sdk_errors_to_static_unavailable(tmp_path):
    with patch("sys.platform", "linux"):
        store = CredentialStore("test")
        assert isinstance(store._backend(), LinuxCredentials)
    store._native = types.SimpleNamespace(
        get=lambda key: (_ for _ in ()).throw(RuntimeError(CANARY))
    )
    with pytest.raises(CredentialError, match="no fallback") as error:
        store.get({"source": "native", "name": "fixture"}, "a" * 64)
    assert CANARY not in str(error.value)
    with pytest.raises(CredentialError, match="part"):
        store.get({"source": "native", "name": "fixture"}, "a" * 64, "token")
    with pytest.raises(CredentialError, match="externally managed"):
        store.get({"source": "environment", "name": "BOTBRIDGE_MCP_X"}, "a" * 64, "access")
