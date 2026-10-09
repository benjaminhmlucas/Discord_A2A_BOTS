"""Provider boundary shared by routing and implementations, without runtime settings."""

import re
from collections.abc import Awaitable, Callable
from typing import TypeAlias


Provider: TypeAlias = Callable[[str, bool], Awaitable[str]]


class ProviderError(RuntimeError):
    """Only static codes and numeric statuses may enter health files and logs."""

    def __init__(self, code: str):
        if not re.fullmatch(
            r"(?:GeminiHTTP[1-5][0-9]{2}|GeminiEmptyContent|CodexExit-?[0-9]{1,10}|"
            r"ClaudeExit-?[0-9]{1,10}|ClaudeBackendError|EmptyCodexResponse|EmptyClaudeResponse)",
            code,
        ):
            raise ValueError("Invalid provider error code")
        self.code = code
        super().__init__(code)
