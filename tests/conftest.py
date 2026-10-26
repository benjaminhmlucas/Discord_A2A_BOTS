"""Native adapters may touch only reserved test keys or pytest-temp installations."""

import pytest

from credential_guard import CredentialGuard

# Install before collection, not just at fixture setup: a future module-level
# credential call must be blocked too. Deployment admission stays empty until the
# public session fixture provides pytest's actual basetemp.
_patches = pytest.MonkeyPatch()
_guard = CredentialGuard()
_guard.install(_patches)


@pytest.fixture(scope="session", autouse=True)
def native_credential_guard(tmp_path_factory):
    _guard.basetemp = tmp_path_factory.getbasetemp().resolve()
    yield _guard


@pytest.fixture(autouse=True)
def check_native_credential_violations(native_credential_guard):
    yield
    native_credential_guard.assert_clean()


@pytest.hookimpl(hookwrapper=True, tryfirst=True)
def pytest_sessionfinish(session, exitstatus):
    # Module/session finalizers run after the last function-scoped check. A
    # swallowed violation there must still make the complete run fail. Check
    # after pytest's own session-finish hooks tear down remaining fixtures.
    yield
    try:
        _guard.assert_clean()
    except pytest.fail.Exception:
        if session.exitstatus == pytest.ExitCode.OK:
            session.exitstatus = pytest.ExitCode.TESTS_FAILED
        reporter = session.config.pluginmanager.get_plugin("terminalreporter")
        if reporter is not None:
            reporter.write_sep("!", "Native credential guard recorded an unsafe operation")


def pytest_unconfigure(config):
    # Also undo on collection failure, when session fixtures never get requested.
    _patches.undo()
