"""Guard policy runs on every OS without loading native libraries or real secrets."""

import os
from pathlib import Path
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

from credential_guard import CredentialGuard
from scripts.console_windows import creation_flags

DEPLOY = "deploy-" + "a" * 16


@pytest.mark.parametrize(
    "key",
    [
        "unrelated-real-credential",
        "BotBridge.MCP/real/credential",
        "BotBridge.MCP/test-not-hex/credential",
        "BotBridge.MCP/test-123g/credential",
        "BotBridge.MCP/test/",
        "BotBridge.MCP/" + DEPLOY + "/credential",
        None,
    ],
)
def test_guard_refuses_foreign_malformed_and_unregistered_targets(tmp_path, key):
    guard = CredentialGuard(tmp_path)
    calls = []
    protected = guard.protect(lambda instance, target: calls.append(target))
    with pytest.raises(pytest.fail.Exception, match="Native credential guard blocked"):
        protected(object(), key)
    assert not calls and len(guard.violations) == 1


@pytest.mark.parametrize("name", ["live-installation", "pytest-base-sibling"])
def test_non_temp_root_does_not_register_a_deployment(tmp_path, name):
    guard = CredentialGuard(tmp_path / "pytest-base")
    assert not guard.register_install(tmp_path / name, DEPLOY)
    with pytest.raises(pytest.fail.Exception, match="unregistered deployment"):
        guard.check("BotBridge.MCP/" + DEPLOY + "/credential")


@pytest.mark.parametrize("namespace", ["test", "test-0123456789abcdef", "test-" + "a" * 32])
def test_reserved_throwaway_namespaces_are_allowed(tmp_path, namespace):
    CredentialGuard(tmp_path).check("BotBridge.MCP/" + namespace + "/credential")


def test_temp_installation_and_its_registered_deployment_are_allowed(tmp_path):
    guard = CredentialGuard(tmp_path)
    assert guard.register_install(tmp_path / "installation", DEPLOY)
    guard.check("BotBridge.MCP/" + DEPLOY + "/credential")
    guard.assert_clean()


def test_temp_installation_cannot_register_a_malformed_namespace(tmp_path):
    guard = CredentialGuard(tmp_path)
    with pytest.raises(pytest.fail.Exception, match="unexpected deployment namespace"):
        guard.register_install(tmp_path / "installation", "deploy-not-a-hash")


def test_swallowed_baseexception_still_fails_the_function_check(tmp_path):
    guard = CredentialGuard(tmp_path)
    try:
        guard.check("foreign")
    except BaseException:
        pass
    with pytest.raises(pytest.fail.Exception, match="recorded an unsafe operation"):
        guard.assert_clean()
    guard.assert_clean()


def test_factory_registration_uses_the_actual_installation_root(tmp_path):
    guard = CredentialGuard(tmp_path)
    calls = []

    def factory(config, root, http):
        calls.append(Path(root))
        return SimpleNamespace(store=SimpleNamespace(namespace=DEPLOY))

    wrapped = guard.protect_deployment(factory)
    result = wrapped({}, tmp_path / "installation", object())
    assert result.store.namespace == DEPLOY and calls == [tmp_path / "installation"]
    guard.check("BotBridge.MCP/" + DEPLOY + "/credential")


def test_real_factory_is_wrapped_at_both_import_sites(tmp_path, native_credential_guard):
    import bridge_authentication
    import bridge_capabilities
    from bridge_http import SafeHTTP

    for index, factory in enumerate(
        (
            bridge_authentication.deployment_authentication,
            bridge_capabilities.deployment_authentication,
        )
    ):
        auth = factory({"owner_id": 201}, tmp_path / str(index), SafeHTTP())
        assert auth.store.namespace in native_credential_guard.deployments
        native_credential_guard.check("BotBridge.MCP/" + auth.store.namespace + "/credential")


@pytest.mark.parametrize(
    "adapter,method",
    [
        (name, method)
        for name in ("WindowsCredentials", "MacCredentials", "LinuxCredentials")
        for method in ("get", "set", "delete")
    ]
    + [("LinuxCredentials", "_operate_direct")],
)
def test_all_native_entry_points_use_the_session_guard(native_credential_guard, adapter, method):
    import bridge_credentials

    wrapped = getattr(getattr(bridge_credentials, adapter), method)
    assert hasattr(wrapped, "__wrapped__")
    assert any(cell.cell_contents is native_credential_guard for cell in wrapped.__closure__)


@pytest.mark.parametrize("phase", ["collection", "test", "session_teardown"])
def test_actual_pytest_guard_blocks_collection_and_caught_violations(tmp_path, phase):
    project = tmp_path / "guard-plugin-project"
    project.mkdir()
    tests_root = Path(__file__).resolve().parent
    for name in ("conftest.py", "credential_guard.py"):
        shutil.copyfile(tests_root / name, project / name)
    # No native library is initialized: even a broken guard reaches only a
    # missing instance attribute, never Credential Manager or another OS store.
    probe = "from bridge_credentials import WindowsCredentials\nbackend = object.__new__(WindowsCredentials)\n"
    if phase == "collection":
        probe += "backend.get('foreign-native-target')\n"
    elif phase == "session_teardown":
        probe += (
            "import pytest\n"
            "@pytest.fixture(scope='session', autouse=True)\n"
            "def late_finalizer():\n"
            "    yield\n"
            "    try:\n"
            "        backend.get('foreign-native-target')\n"
            "    except BaseException:\n"
            "        pass\n"
            "def test_passes():\n"
            "    pass\n"
        )
    else:
        probe += "def test_swallowed():\n    try:\n        backend.get('foreign-native-target')\n    except BaseException:\n        pass\n"
    (project / "test_probe.py").write_text(probe, encoding="utf-8")
    env = os.environ.copy()
    env.pop("PYTEST_ADDOPTS", None)
    env.pop("PYTEST_PLUGINS", None)
    env["PYTHONPATH"] = str(tests_root.parent)
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "--tb=short"],
        cwd=project,
        env=env,
        capture_output=True,
        text=True,
        timeout=30,
        creationflags=creation_flags(),
    )
    assert result.returncode == (2 if phase == "collection" else 1), result.stdout + result.stderr
    assert (
        "Native credential guard blocked"
        if phase == "collection"
        else "recorded an unsafe operation"
    ) in result.stdout
    assert "AttributeError" not in result.stdout
