"""Scoped credential references, with no automatic backend discovery or plaintext fallback.

Native adapters never create/unlock a keychain or request user interaction.
Environment references are explicit and externally managed, never written here.
"""

from contextlib import closing
import ctypes
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from typing import Any

from bridge_errors import CapabilityError
from scripts.console_windows import creation_flags

NAME = re.compile(r"[a-z][a-z0-9_.-]{0,63}\Z")
ENV_NAME = re.compile(r"BOTBRIDGE_MCP_[A-Z][A-Z0-9_]{0,49}\Z")
MAX_SECRET_BYTES = 2560  # Windows generic credential blob limit; common portable bound.
# OAuth grants keep access and refresh tokens as separate native entries, each bounded.
PARTS = ("value", "access", "refresh")


class CredentialError(CapabilityError):
    """Static diagnostics only: never forward native errors or credential values."""


def checked_reference(reference: Any) -> dict[str, str]:
    if not isinstance(reference, dict) or set(reference) != {"source", "name"}:
        raise CredentialError("Invalid credential reference")
    source, name = reference["source"], reference["name"]
    pattern = ENV_NAME if source == "environment" else NAME
    if (
        source not in ("native", "environment")
        or not isinstance(name, str)
        or not pattern.fullmatch(name)
    ):
        raise CredentialError("Invalid credential reference")
    return reference


def checked_secret(value: Any) -> str:
    try:
        if (
            not isinstance(value, str)
            or not value
            or "\0" in value
            or len(value.encode("utf-8")) > MAX_SECRET_BYTES
        ):
            raise CredentialError(
                "Credential is empty, malformed or exceeds the portable store limit"
            )
    except UnicodeError:
        raise CredentialError("Invalid credential encoding") from None
    return str(value)


def connection_binding(principal: object, connection: str, profile: object) -> str:
    """Bind native records to the selected principal, alias and exact configuration."""
    encoded = json.dumps(
        [principal, connection, profile], sort_keys=True, separators=(",", ":"), allow_nan=False
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class _FileTime(ctypes.Structure):
    _fields_ = [("low", ctypes.c_uint32), ("high", ctypes.c_uint32)]


class _Credential(ctypes.Structure):
    _fields_ = [
        ("flags", ctypes.c_uint32),
        ("kind", ctypes.c_uint32),
        ("target", ctypes.c_wchar_p),
        ("comment", ctypes.c_wchar_p),
        ("written", _FileTime),
        ("size", ctypes.c_uint32),
        ("blob", ctypes.c_void_p),
        ("persist", ctypes.c_uint32),
        ("count", ctypes.c_uint32),
        ("attributes", ctypes.c_void_p),
        ("alias", ctypes.c_wchar_p),
        ("user", ctypes.c_wchar_p),
    ]


class WindowsCredentials:
    def __init__(self) -> None:
        library = getattr(ctypes, "WinDLL")("advapi32", use_last_error=True)
        pointer = ctypes.POINTER(_Credential)
        self.read, self.write, self.remove, self.free = (
            library.CredReadW,
            library.CredWriteW,
            library.CredDeleteW,
            library.CredFree,
        )
        self.read.argtypes = [
            ctypes.c_wchar_p,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.POINTER(pointer),
        ]
        self.write.argtypes = [pointer, ctypes.c_uint32]
        self.remove.argtypes = [ctypes.c_wchar_p, ctypes.c_uint32, ctypes.c_uint32]
        for operation in (self.read, self.write, self.remove):
            operation.restype = ctypes.c_int
        self.free.argtypes, self.free.restype = [ctypes.c_void_p], None

    def get(self, key: str) -> str | None:
        item = ctypes.POINTER(_Credential)()
        if not self.read(key, 1, 0, ctypes.byref(item)):
            if getattr(ctypes, "get_last_error")() == 1168:
                return None
            raise CredentialError("Windows credential read unavailable")
        try:
            return ctypes.string_at(item.contents.blob, item.contents.size).decode("utf-8")
        finally:
            self.free(item)

    def set(self, key: str, value: str) -> None:
        data = value.encode("utf-8")
        blob = ctypes.create_string_buffer(data)
        item = _Credential(
            kind=1,
            target=key,
            comment="BotBridge MCP credential",
            size=len(data),
            blob=ctypes.cast(blob, ctypes.c_void_p),
            persist=2,
            user="botbridge-mcp",
        )
        if not self.write(ctypes.byref(item), 0):
            raise CredentialError("Windows credential write unavailable")

    def delete(self, key: str) -> None:
        if not self.remove(key, 1, 0) and getattr(ctypes, "get_last_error")() != 1168:
            raise CredentialError("Windows credential deletion unavailable")


class MacCredentials:
    """Security.framework generic passwords; application interaction explicitly disabled."""

    def __init__(self) -> None:
        self.security = ctypes.CDLL("/System/Library/Frameworks/Security.framework/Security")
        self.core = ctypes.CDLL(
            "/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation"
        )
        self.core.CFRelease.argtypes, self.core.CFRelease.restype = [ctypes.c_void_p], None
        self.security.SecKeychainSetUserInteractionAllowed.argtypes = [ctypes.c_ubyte]
        self.security.SecKeychainSetUserInteractionAllowed.restype = ctypes.c_int32
        self._check(self.security.SecKeychainSetUserInteractionAllowed(False))
        signatures = {
            "SecKeychainFindGenericPassword": [
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_char_p,
                ctypes.c_uint32,
                ctypes.c_char_p,
                ctypes.POINTER(ctypes.c_uint32),
                ctypes.POINTER(ctypes.c_void_p),
                ctypes.POINTER(ctypes.c_void_p),
            ],
            "SecKeychainAddGenericPassword": [
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_char_p,
                ctypes.c_uint32,
                ctypes.c_char_p,
                ctypes.c_uint32,
                ctypes.c_void_p,
                ctypes.c_void_p,
            ],
            "SecKeychainItemModifyAttributesAndData": [
                ctypes.c_void_p,
                ctypes.c_void_p,
                ctypes.c_uint32,
                ctypes.c_void_p,
            ],
            "SecKeychainItemDelete": [ctypes.c_void_p],
            "SecKeychainItemFreeContent": [ctypes.c_void_p, ctypes.c_void_p],
        }
        for name, args in signatures.items():
            operation = getattr(self.security, name)
            operation.argtypes, operation.restype = args, ctypes.c_int32

    @staticmethod
    def _check(status: int) -> None:
        if status:
            raise CredentialError(
                "macOS credential operation unavailable; unlock or authorize the keychain outside the bridge"
            )

    def _find(self, key: str, *, read_value: bool = True) -> tuple[str | None, Any]:
        encoded, account = key.encode(), b"botbridge-mcp"
        size, data, item = ctypes.c_uint32(), ctypes.c_void_p(), ctypes.c_void_p()
        status = self.security.SecKeychainFindGenericPassword(
            None,
            len(encoded),
            encoded,
            len(account),
            account,
            ctypes.byref(size) if read_value else None,
            ctypes.byref(data) if read_value else None,
            ctypes.byref(item),
        )
        if status == -25300:
            return None, None
        self._check(status)
        try:
            return ctypes.string_at(data, size.value).decode("utf-8") if read_value else None, item
        except BaseException:
            self.core.CFRelease(item)
            raise
        finally:
            if read_value:
                self.security.SecKeychainItemFreeContent(None, data)

    def get(self, key: str) -> str | None:
        value, item = self._find(key)
        if item:
            self.core.CFRelease(item)
        return value

    def set(self, key: str, value: str) -> None:
        _, item = self._find(key, read_value=False)
        data = value.encode()
        if item:
            try:
                self._check(
                    self.security.SecKeychainItemModifyAttributesAndData(
                        item, None, len(data), data
                    )
                )
            finally:
                self.core.CFRelease(item)
        else:
            encoded, account = key.encode(), b"botbridge-mcp"
            self._check(
                self.security.SecKeychainAddGenericPassword(
                    None, len(encoded), encoded, len(account), account, len(data), data, None
                )
            )

    def delete(self, key: str) -> None:
        _, item = self._find(key, read_value=False)
        if item:
            try:
                self._check(self.security.SecKeychainItemDelete(item))
            finally:
                self.core.CFRelease(item)


class LinuxCredentials:
    def _operate(self, key: str, value: str | None, remove: bool = False) -> str | None:
        # A timeout around to_thread cannot terminate blocking D-Bus SDK calls.
        # Isolate the entire SDK operation (including connection setup) in a
        # killable helper; tokens travel only through inherited anonymous pipes.
        host = str(Path(__file__).with_name("bridge_credential_host.py"))
        try:
            result = subprocess.run(
                [sys.executable, host],
                input=json.dumps({"key": key, "value": value, "remove": remove}).encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=3,
                check=False,
                creationflags=creation_flags(),
            )
            if result.returncode != 0 or len(result.stdout) > 16384:
                raise CredentialError("Linux credential operation unavailable")
            response = json.loads(result.stdout)
            if not isinstance(response, dict) or set(response) != {"value"}:
                raise CredentialError("Invalid credential helper response")
            return checked_secret(response["value"]) if response["value"] is not None else None
        except CredentialError:
            raise
        except Exception:
            raise CredentialError("Linux credential operation unavailable or timed out") from None

    def _collection(self, connection: Any) -> Any:
        # Unlike get_default_collection, this cannot create a collection/prompt.
        collection = importlib.import_module("secretstorage").get_collection_by_alias(
            connection, "default"
        )
        collection.ensure_not_locked()
        return collection

    def _operate_direct(self, key: str, value: str | None, remove: bool = False) -> str | None:
        # Imported only inside the bounded helper process on Linux.
        util = importlib.import_module("secretstorage.util")
        wrapper, format_secret, open_session = (
            util.DBusAddressWrapper,
            util.format_secret,
            util.open_session,
        )
        with closing(importlib.import_module("secretstorage").dbus_init()) as connection:
            collection = self._collection(connection)
            attributes = {"application": "BotBridge.MCP", "key": key}
            if value is not None:
                session = open_session(connection)
                if not session.encrypted:
                    raise CredentialError("Encrypted Secret Service session required")
                address = wrapper(
                    collection.collection_path, "org.freedesktop.Secret.Collection", connection
                )
                _, prompt = address.call(
                    "CreateItem",
                    "a{sv}(oayays)b",
                    {
                        "org.freedesktop.Secret.Item.Label": ("s", "BotBridge MCP credential"),
                        "org.freedesktop.Secret.Item.Attributes": ("a{ss}", attributes),
                    },
                    format_secret(session, value.encode(), "text/plain"),
                    True,
                )
                if prompt != "/":
                    raise CredentialError("Native credential interaction denied")
                return None
            items = list(collection.search_items(attributes))
            if remove:
                for item in items:
                    item.ensure_not_locked()
                    address = wrapper(item.item_path, "org.freedesktop.Secret.Item", connection)
                    (prompt,) = address.call("Delete", "")
                    if prompt != "/":
                        raise CredentialError("Native credential interaction denied")
                return None
            if len(items) > 1:
                raise CredentialError("Ambiguous native credential")
            if not items:
                return None
            items[0].ensure_not_locked()
            items[0].session = open_session(connection)
            if not items[0].session.encrypted:
                raise CredentialError("Encrypted Secret Service session required")
            return str(items[0].get_secret().decode("utf-8"))

    def get(self, key: str) -> str | None:
        return self._operate(key, None)

    def set(self, key: str, value: str) -> None:
        self._operate(key, value)

    def delete(self, key: str) -> None:
        self._operate(key, None, remove=True)


Backend = WindowsCredentials | MacCredentials | LinuxCredentials


class CredentialStore:
    def __init__(self, namespace: str) -> None:
        if not isinstance(namespace, str) or not NAME.fullmatch(namespace):
            raise CredentialError("Invalid credential namespace")
        self.namespace = namespace
        self._native: Backend | None = None

    def _backend(self) -> Backend:
        if self._native is None:
            if sys.platform == "win32":
                self._native = WindowsCredentials()
            elif sys.platform == "darwin":
                self._native = MacCredentials()
            elif sys.platform.startswith("linux"):
                self._native = LinuxCredentials()
            else:
                raise CredentialError(
                    "Native credential backend unsupported; explicitly configure environment references"
                )
        return self._native

    def _key(self, reference: dict[str, str], binding: str, part: str) -> str:
        checked_reference(reference)
        if not isinstance(binding, str) or not re.fullmatch(r"[0-9a-f]{64}", binding):
            raise CredentialError("Invalid credential binding")
        if part not in PARTS:
            raise CredentialError("Invalid credential part")
        key = "BotBridge.MCP/" + self.namespace + "/" + binding + "/" + reference["name"]
        return key if part == "value" else key + "/" + part

    def _operate(
        self,
        reference: dict[str, str],
        binding: str,
        action: str,
        value: str | None = None,
        part: str = "value",
    ) -> str | None:
        key = self._key(reference, binding, part)
        try:
            if reference["source"] == "environment":
                if action != "get" or part != "value":
                    raise CredentialError("Environment credentials are externally managed")
                result = os.environ.get(reference["name"])
            else:
                if action == "set":
                    value = checked_secret(value)  # Reject bad input before touching a store.
                operation = getattr(self._backend(), action)
                result = operation(key, value) if action == "set" else operation(key)
            return checked_secret(result) if result is not None else None
        except CredentialError:
            raise
        except Exception:
            # Native/DBus errors may contain credentials; never expose them.
            raise CredentialError(
                "Native credential store unavailable; no fallback was used"
            ) from None

    def get(self, reference: dict[str, str], binding: str, part: str = "value") -> str | None:
        return self._operate(reference, binding, "get", part=part)

    def set(self, reference: dict[str, str], binding: str, value: str, part: str = "value") -> None:
        self._operate(reference, binding, "set", value, part=part)

    def delete(self, reference: dict[str, str], binding: str, part: str = "value") -> None:
        self._operate(reference, binding, "delete", part=part)

    def status(
        self, reference: dict[str, str], binding: str, part: str = "value"
    ) -> dict[str, str]:
        try:
            state = self.get(reference, binding, part) is not None
            return {"state": "set" if state else "not_set"}
        except CredentialError:
            return {"state": "unavailable"}
