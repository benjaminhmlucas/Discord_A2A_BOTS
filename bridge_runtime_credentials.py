"""Explicit runtime credential references over the existing deployment-native store."""

import os
from pathlib import Path

import bridge_authentication
from bridge_credentials import CredentialError, checked_secret
from bridge_http import SafeHTTP

NAMES = (
    "CODEXBOT_TOKEN",
    "ANTIGRAVITYBOT_TOKEN",
    "CLAUDEBOT_TOKEN",
    "GEMINI_API_KEY",
    "CLAUDE_CODE_OAUTH_TOKEN",
)


def legacy(name):
    """The established process/Windows User environment source; None when absent."""
    value = os.environ.get(name)
    if isinstance(value, str) and value.strip():
        return value
    if os.name == "nt":
        import winreg

        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, "Environment") as key:
                value = winreg.QueryValueEx(key, name)[0]
                if isinstance(value, str) and value.strip():
                    return value
        except OSError:
            pass
    return None


def native_names(settings):
    names = settings.get("runtime_credentials", [])
    if (
        not isinstance(names, list)
        or any(name not in NAMES for name in names)
        or len(names) != len(set(names))
    ):
        raise ValueError("Invalid runtime credential references")
    return names


class RuntimeCredentials:
    def __init__(self, config, root):
        self.auth = bridge_authentication.deployment_authentication(config, Path(root), SafeHTTP())

    def reference(self, name):
        if name not in NAMES:
            raise CredentialError("Unknown runtime credential")
        alias = "runtime-" + name.lower().replace("_", "-")
        return {"source": "native", "name": alias}, self.auth.binding(
            alias, {"purpose": "bot-provider-runtime-v1", "name": name}
        )

    def optional(self, name):
        reference, binding = self.reference(name)
        return self.auth.store.get(reference, binding)

    def required(self, name):
        value = self.optional(name)
        if value is None:
            raise CredentialError("Runtime credential unavailable; save it through local control")
        return value

    def status(self, name):
        reference, binding = self.reference(name)
        return self.auth.store.status(reference, binding)


def save_runtime_credential(store, name, value, expected, *, remove=False):
    if type(remove) is not bool:
        raise ValueError("Invalid credential action")
    if not remove:
        value = checked_secret(value)
    current = store.snapshot()
    if expected != current["revisions"]["local_settings.json"]:
        raise ValueError("Configuration changed; reload before saving")
    native = RuntimeCredentials(current["config"], store.root)
    reference, binding = native.reference(name)
    # The existing deployment credential coordinator serializes native changes across GUIs.
    with native.auth.oauth.grants.transaction():
        previous = native.optional(name)
        try:
            if remove:
                native.auth.store.delete(reference, binding)
            else:
                native.auth.store.set(reference, binding, value)
            if native.optional(name) != (None if remove else value):
                raise CredentialError("Credential store verification failed")
            settings = current["settings"]
            settings["runtime_credentials"] = list(dict.fromkeys([*native_names(settings), name]))
            store.save("local_settings.json", settings, expected)
        except BaseException:
            if previous is None:
                native.auth.store.delete(reference, binding)
            else:
                native.auth.store.set(reference, binding, previous)
            raise
    return {"name": name, "state": "not_set" if remove else "set"}
