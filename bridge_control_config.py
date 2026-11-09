"""Validated local-control configuration reads, compare-and-swap saves and exports."""

import copy
import asyncio
from contextlib import contextmanager
import hashlib
import json
from pathlib import Path
import threading

from bridge_capabilities import Capabilities
from bridge_control_journal import ImportJournal
from bridge_memory_io import MemoryStore
from bridge_privacy import Privacy, redact_spans
from bridge_runtime_credentials import NAMES, RuntimeCredentials, legacy, native_names
from bridge_settings import IMPORT_FILES, validate_runtime_config


FILES = IMPORT_FILES
EXPORT_FORMAT = "botbridge-control-export-v1"


def revision(data):
    return hashlib.sha256(data).hexdigest()


class ControlConfig:
    def __init__(self, root):
        self.root = Path(root).resolve(strict=True)
        self.storage = MemoryStore(self.root, {})
        self.journal = ImportJournal(self.storage)
        # Per worker thread: whether this thread already holds the configuration lock.
        self.lock_state = threading.local()

    def path(self, name):
        if name not in ("bridge_config.json", "local_settings.json", "public_context.md"):
            raise ValueError("Unsupported configuration file")
        return self.storage.path(name)

    def read(self, name):
        self.path(name)
        data = self.storage.read(name, limit=1048576)
        return data, revision(data)

    def validate(self, config, settings):
        result = validate_runtime_config(copy.deepcopy(config))
        Capabilities(result, lambda _: None)
        paths = {
            "node_executable",
            "pm2_cli",
            "codex_cli",
            "claude_cli",
            "memory_dir",
        }
        if not isinstance(settings, dict) or not paths <= set(settings) <= paths | {
            "runtime_credentials"
        }:
            raise ValueError("Unsupported local settings")
        native_names(settings)
        for key in paths:
            value = settings[key]
            if not isinstance(value, str) or not value or "\0" in value or len(value) > 4096:
                raise ValueError("Invalid local path")
        privacy = Path(settings["memory_dir"])
        privacy = privacy if privacy.is_absolute() else self.root / privacy
        if result.get("memory", {}).get("enabled") and Path(result["memory"]["root"]) != privacy:
            raise ValueError("Memory and privacy must use the same root")
        return result

    @contextmanager
    def locked(self):
        with self.storage.parent(FILES[0]), self.storage.lock():
            self.lock_state.active = True
            try:
                yield
            finally:
                self.lock_state.active = False

    def snapshot(self):
        # An import interrupted by process exit is rolled back before anything is read.
        if self.journal.pending():
            if getattr(self.lock_state, "active", False):
                self.journal.recover()
            else:
                with self.locked():
                    self.journal.recover()
        config, config_hash = self.read("bridge_config.json")
        settings, settings_hash = self.read("local_settings.json")
        context, context_hash = self.read("public_context.md")
        config, settings = json.loads(config), json.loads(settings)
        config = self.validate(config, settings)
        self.secret_free((config, settings, context.decode("utf-8")), config, settings)
        return {
            "config": config,
            "settings": settings,
            "context": context.decode("utf-8"),
            "revisions": {
                "bridge_config.json": config_hash,
                "local_settings.json": settings_hash,
                "public_context.md": context_hash,
            },
        }

    def known_secrets(self, config, settings):
        caps = Capabilities(config, lambda _: None, self.root)
        asyncio.run(caps.refresh_credentials())
        values = caps.secrets | caps.active_secrets
        native = RuntimeCredentials(config, self.root)
        for name in native_names(settings):
            value = native.optional(name)
            if value is not None:
                values.add(value)
        # Legacy process and Windows User environment values are redacted as well.
        values.update(value for value in map(legacy, NAMES) if value)
        return tuple(values)

    def secret_free(self, document, config, settings):
        text = (
            json.dumps(document, ensure_ascii=False).replace("\\r\\n", "\\n").replace("\\r", "\\n")
        )
        values = self.known_secrets(config, settings)
        encoded = tuple(
            json.dumps(value, ensure_ascii=False)[1:-1]
            .replace("\\r\\n", "\\n")
            .replace("\\r", "\\n")
            for value in values
        )
        if redact_spans(text, (), values + encoded, markers=False) != text:
            raise ValueError("Credentials must be saved through the credential screen")

    def save(self, name, value, expected, *, confirm_work=False):
        # Validate the complete proposed policy before creating any writable resource.
        current = self.snapshot()
        if current["revisions"].get(name) != expected:
            raise ValueError("Configuration changed; reload before saving")
        if name == "bridge_config.json":
            config = self.validate(value, current["settings"])
            if (
                config.get("allow_work")
                and not current["config"].get("allow_work")
                and not confirm_work
            ):
                raise ValueError("Owner work requires explicit risk confirmation")
            data = json.dumps(config, indent=2).encode("utf-8") + b"\n"
        elif name == "local_settings.json":
            self.validate(current["config"], value)
            data = json.dumps(value, indent=2).encode("utf-8") + b"\n"
        elif name == "public_context.md":
            if not isinstance(value, str):
                raise ValueError("Public context must be text")
            data = value.encode("utf-8")
        else:
            raise ValueError("Unsupported configuration file")
        if len(data) > 1048576:
            raise ValueError("Configuration exceeds the size limit")
        self.secret_free(
            value,
            config if name == "bridge_config.json" else current["config"],
            value if name == "local_settings.json" else current["settings"],
        )
        self.path(name)
        self.storage.write_allowed(name)
        with self.locked():
            # Recheck every validation dependency, not just the edited file.
            if self.snapshot()["revisions"] != current["revisions"]:
                raise ValueError("Configuration changed; reload before saving")
            self.storage.atomic(name, data)
            if self.read(name)[0] != data:
                raise RuntimeError("Saved configuration verification failed")
        return revision(data)

    def export(self):
        """Non-secret settings only: credentials live in native stores or the environment."""
        current = self.snapshot()
        return {
            "format": EXPORT_FORMAT,
            "bridge_config.json": current["config"],
            "local_settings.json": current["settings"],
            "public_context.md": current["context"],
        }

    def restore(self, bundle, expected, *, confirm_work=False):
        """Validate a complete export, then replace all three files together or none."""
        if (
            not isinstance(bundle, dict)
            or set(bundle) != {"format", *FILES}
            or bundle["format"] != EXPORT_FORMAT
        ):
            raise ValueError("Unsupported configuration export")
        current = self.snapshot()
        if current["revisions"] != expected:
            raise ValueError("Configuration changed; reload before saving")
        settings, context = bundle["local_settings.json"], bundle["public_context.md"]
        config = self.validate(bundle["bridge_config.json"], settings)
        if not isinstance(context, str):
            raise ValueError("Public context must be text")
        if (
            config.get("allow_work")
            and not current["config"].get("allow_work")
            and not confirm_work
        ):
            raise ValueError("Owner work requires explicit risk confirmation")
        data = {
            "bridge_config.json": json.dumps(config, indent=2).encode("utf-8") + b"\n",
            "local_settings.json": json.dumps(settings, indent=2).encode("utf-8") + b"\n",
            "public_context.md": context.encode("utf-8"),
        }
        if any(len(value) > 1048576 for value in data.values()):
            raise ValueError("Configuration exceeds the size limit")
        self.secret_free((config, settings, context), config, settings)
        for name in FILES:
            self.storage.write_allowed(name)
        with self.locked():
            if self.snapshot()["revisions"] != current["revisions"]:
                raise ValueError("Configuration changed; reload before saving")
            previous = {name: self.read(name)[0] for name in FILES}
            # Durable before the first replacement, so a process exit part way through
            # is rolled back by the next reader instead of leaving mixed files.
            self.journal.begin(previous, data)
            written = []
            try:
                for name in FILES:
                    written.append(name)
                    self.storage.atomic(name, data[name])
                    if self.read(name)[0] != data[name]:
                        raise RuntimeError("Saved configuration verification failed")
            except BaseException:
                for name in written:
                    self.storage.atomic(name, previous[name])
                # Reached only when every rollback write succeeded; otherwise the record
                # stays and the next reader finishes the rollback.
                self.journal.finish()
                raise
            self.journal.finish()
        return {name: revision(value) for name, value in data.items()}

    def redactor(self):
        """One redaction function for several texts, from a single configuration read."""
        current = self.snapshot()
        settings = current["settings"]
        root = Path(settings["memory_dir"])
        privacy = Privacy(root if root.is_absolute() else self.root / root)
        values = privacy.refresh()
        secrets = self.known_secrets(current["config"], settings)
        return lambda text: redact_spans(text, values, secrets)

    def redact(self, text):
        return self.redactor()(text)
