import importlib.util
import json
import shutil
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def module(name, relative):
    spec = importlib.util.spec_from_file_location(name, ROOT / relative)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


initialize = module("initialize", "initialize.py").initialize
release = module("release_check", "scripts/check_release.py")
logrotate = module("logrotate_fix", "scripts/fix_logrotate.py")


class SetupTests(unittest.TestCase):
    def test_initialize_safe_defaults_and_refuses_overwrite(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            for name in (
                "bridge_config.example.json",
                "local_settings.example.json",
                "public_context.example.md",
            ):
                shutil.copyfile(ROOT / name, root / name)
            config = initialize(201, 301, 101, 102, 103, root)
            self.assertFalse(config["allow_work"])
            self.assertEqual(config["allowed_user_ids"], [201])
            self.assertEqual(config["enabled_bots"], [101, 102, 103])
            scopes = json.loads((root / "log_management.config.json").read_text())["scopes"]
            self.assertTrue(all(Path(item["directory"]).is_relative_to(root) for item in scopes))
            with self.assertRaises(FileExistsError):
                initialize(201, 301, 101, 102, 103, root)

    def test_invalid_or_duplicate_ids_do_not_create_local_settings(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            with self.assertRaises(ValueError):
                initialize(0, 301, 101, 102, 103, root)
            with self.assertRaises(ValueError):
                initialize(201, 301, 101, 101, 103, root)
            self.assertEqual(list(root.iterdir()), [])

    def test_initializer_detects_corrupt_readback(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp).resolve()
            for name in (
                "bridge_config.example.json",
                "local_settings.example.json",
                "public_context.example.md",
            ):
                shutil.copyfile(ROOT / name, root / name)
            original = Path.read_text

            def read(path, *args, **kwargs):
                return (
                    "{}" if path == root / "bridge_config.json" else original(path, *args, **kwargs)
                )

            with patch.object(Path, "read_text", read):
                with self.assertRaisesRegex(RuntimeError, "verification"):
                    initialize(201, 301, 101, 102, 103, root)

    def test_release_gate_finds_private_paths_and_synthetic_secrets(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "private_memory").mkdir()
            (root / "private_memory/note.md").write_text("private fixture")
            # The control window's lock and interrupted-import record (local file copies).
            (root / ".botbridge-memory").mkdir()
            (root / ".botbridge-memory/control-import.json").write_text("{}")
            (root / "bad.txt").write_text("sk-ant-" + "x" * 32)
            count, failures = release.scan(root)
            self.assertEqual(count, 3)
            self.assertEqual(len(failures), 3)
            self.assertTrue(any(reason == "credential-like content" for _, reason in failures))

    def test_logrotate_fix_verified_unchanged_and_version_checked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "package.json").write_text('{"version":"3.0.1"}')
            source = "// upstream module\n" + logrotate.FIX + "\nvar TZ = conf.TZ;\n"
            (root / "app.js").write_text(source)
            logrotate.verify(root)
            self.assertEqual(source, (root / "app.js").read_text())
            self.assertEqual(["app.js", "package.json"], sorted(p.name for p in root.iterdir()))
            for version in ("3.0.0", "99.0.0"):
                (root / "package.json").write_text(f'{{"version":"{version}"}}')
                with self.assertRaisesRegex(RuntimeError, "Unexpected logrotate version"):
                    logrotate.verify(root)
