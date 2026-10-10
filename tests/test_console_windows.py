from types import SimpleNamespace
from unittest.mock import patch

import pytest

from scripts import console_windows as windows


@pytest.mark.parametrize("platform", ["nt", "posix"])
@pytest.mark.parametrize("show", [None, "0", "1", "true"])
@pytest.mark.parametrize("background", [False, True])
@pytest.mark.parametrize("attached", [False, True])
def test_console_policy(platform, show, background, attached):
    env = {} if show is None else {"BOTBRIDGE_SHOW_CONSOLE": show}
    kernel = SimpleNamespace(GetConsoleWindow=lambda: int(attached))
    with (
        patch.object(windows, "os", SimpleNamespace(name=platform, environ=env)),
        patch.object(windows.ctypes, "windll", SimpleNamespace(kernel32=kernel), create=True),
        patch.object(windows.subprocess, "CREATE_NO_WINDOW", 0x08000000, create=True),
    ):
        expected = (
            0x08000000 if platform == "nt" and show != "1" and (background or not attached) else 0
        )
        assert windows.creation_flags(background=background) == expected
        assert windows.creation_flags(background=background, env=env) == expected
