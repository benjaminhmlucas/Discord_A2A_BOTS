"""Test-process native credential admission; never installed by product code."""

from functools import wraps
from pathlib import Path
import re

import pytest

TARGET = re.compile(r"\ABotBridge\.MCP/(?P<namespace>test(?:-[0-9a-f]+)?|deploy-[0-9a-f]{16})/.+\Z")
DEPLOYMENT = re.compile(r"\Adeploy-[0-9a-f]{16}\Z")


class CredentialGuard:
    def __init__(self, basetemp=None):
        self.basetemp = None if basetemp is None else Path(basetemp).resolve()
        self.deployments = set()
        self.violations = []

    def register_install(self, root, namespace):
        resolved = Path(root).resolve()
        if self.basetemp is None or not resolved.is_relative_to(self.basetemp):
            return False
        if not isinstance(namespace, str) or not DEPLOYMENT.fullmatch(namespace):
            self.violate("unexpected deployment namespace")
        self.deployments.add(namespace)
        return True

    def violate(self, reason):
        # Record before raising: CredentialStore catches Exception, and tests may
        # catch BaseException. Neither may turn an unsafe call into a quiet pass.
        self.violations.append(reason)
        pytest.fail("Native credential guard blocked " + reason, pytrace=False)

    def check(self, key):
        match = TARGET.fullmatch(key) if isinstance(key, str) else None
        if match is None:
            self.violate("a target outside disposable test namespaces")
        namespace = match["namespace"]
        if namespace.startswith("deploy-") and namespace not in self.deployments:
            self.violate("an unregistered deployment namespace")

    def assert_clean(self):
        if self.violations:
            self.violations.clear()
            pytest.fail("Native credential guard recorded an unsafe operation", pytrace=False)

    def protect(self, operation):
        @wraps(operation)
        def guarded(instance, key, *args, **kwargs):
            self.check(key)
            return operation(instance, key, *args, **kwargs)

        return guarded

    def protect_deployment(self, factory):
        @wraps(factory)
        def guarded(config, root, http):
            resolved = Path(root).resolve()
            auth = factory(config, root, http)
            self.register_install(resolved, auth.store.namespace)
            return auth

        return guarded

    def install(self, monkeypatch):
        import bridge_authentication
        import bridge_capabilities
        from bridge_credentials import LinuxCredentials, MacCredentials, WindowsCredentials

        for adapter in (WindowsCredentials, MacCredentials, LinuxCredentials):
            for name in ("get", "set", "delete"):
                monkeypatch.setattr(adapter, name, self.protect(getattr(adapter, name)))
        monkeypatch.setattr(
            LinuxCredentials, "_operate_direct", self.protect(LinuxCredentials._operate_direct)
        )
        factory = self.protect_deployment(bridge_authentication.deployment_authentication)
        monkeypatch.setattr(bridge_authentication, "deployment_authentication", factory)
        monkeypatch.setattr(bridge_capabilities, "deployment_authentication", factory)
