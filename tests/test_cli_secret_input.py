"""Real secret-input logic; only the terminal's unavailable-echo-control boundary is substituted."""

import getpass
import io
import sys
from unittest.mock import patch

import pytest

from bridge_credentials import CredentialError
import mcp_connections as cli


CANARY = "synthetic-pr30-hidden-input-canary"


class UnreadableInput(io.StringIO):
    def readline(self, *args, **kwargs):
        raise AssertionError("An unavailable hidden prompt must refuse before reading input")


def test_hidden_prompt_refuses_real_getpass_echo_fallback_before_reading(capsys):
    # This is the stdlib's actual echo fallback, reached when terminal echo control fails.
    # Keeping it real proves the GetPassWarning is stopped before _raw_input executes.
    with (
        patch.object(getpass, "getpass", getpass.fallback_getpass),
        patch.object(sys, "stdin", UnreadableInput(CANARY + "\n")),
        pytest.raises(CredentialError, match="Hidden credential input unavailable; use --stdin"),
    ):
        cli.secret_input(False)
    captured = capsys.readouterr()
    assert CANARY not in captured.out + captured.err
    assert "Warning: Password input may be echoed" not in captured.err


def test_explicit_stdin_remains_available_without_a_terminal():
    with (
        patch.object(sys, "stdin", io.StringIO(CANARY + "\r\nignored-second-line")),
        patch.object(getpass, "getpass", side_effect=AssertionError("Terminal must not be used")),
    ):
        assert cli.secret_input(True) == CANARY


def test_supported_hidden_terminal_returns_value_without_printing_it(capsys):
    with patch.object(getpass, "getpass", return_value=CANARY) as terminal:
        assert cli.secret_input(False) == CANARY
    terminal.assert_called_once_with("Credential value (input hidden): ")
    captured = capsys.readouterr()
    assert CANARY not in captured.out + captured.err
