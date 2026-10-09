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

    def test_logrotate_detects_write_not_persisted(self):
        from unittest.mock import patch

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "package.json").write_text('{"version":"3.0.0"}')
            app = root / "app.js"
            app.write_text(
                "const parseBool = (str, defaultVal = false) => {\n  return str.toLowerCase() === 'true';\n};\n"
            )
            original = Path.write_text

            def write(path, *args, **kwargs):
                return 0 if path == app else original(path, *args, **kwargs)

            with patch.object(Path, "write_text", write):
                with self.assertRaisesRegex(RuntimeError, "verification"):
                    logrotate.patch(root)

    def test_release_gate_finds_private_paths_and_synthetic_secrets(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "private_memory").mkdir()
            (root / "private_memory/note.md").write_text("private fixture")
            (root / "bad.txt").write_text("sk-ant-" + "x" * 32)
            count, failures = release.scan(root)
            self.assertEqual(count, 2)
            self.assertEqual(len(failures), 2)
            self.assertTrue(any(reason == "credential-like content" for _, reason in failures))

    def test_logrotate_patch_idempotent_and_version_checked(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "package.json").write_text('{"version":"3.0.0"}')
            (root / "app.js").write_text(
                "const parseBool = (str, defaultVal = false) => {\n  return str.toLowerCase() === 'true';\n};\n"
            )
            logrotate.patch(root)
            first = (root / "app.js").read_text()
            logrotate.patch(root)
            self.assertEqual(first, (root / "app.js").read_text())
            self.assertIn(logrotate.FIX, first)
            (root / "package.json").write_text('{"version":"99.0.0"}')
            with self.assertRaises(RuntimeError):
                logrotate.patch(root)
