"""Public context is opt-in; shared-channel output always receives DLP."""

import os
import re
from pathlib import Path

BLOCK = re.compile(r"<!--\s*PRIVATE:START\s*-->(.*?)<!--\s*PRIVATE:END\s*-->", re.I | re.S)
TAG = re.compile(r"<!--\s*PRIVATE:(?:START|END)\s*-->", re.I)


def private_values(text: str) -> tuple[str, ...]:
    """Validate a complete marker structure before exposing any text."""
    matches = list(BLOCK.finditer(text))
    if len(TAG.findall(text)) != len(matches) * 2:
        raise RuntimeError("Malformed privacy markers")
    values = []
    for match in matches:
        secret = match.group(1).strip()
        if secret:
            values.append(secret)
            values.extend(line.strip() for line in secret.splitlines() if line.strip())
    return tuple(values)


def redact_credentials(text: str) -> str:
    text = re.sub(
        r"(?i)(?:https://discord(?:app)?\.com/api/webhooks/)\S+", "[private webhook]", text
    )
    text = re.sub(r"\bAIza[\w-]{30,}\b", "[private key]", text)
    return re.sub(r"\b[\w-]{23,30}\.[\w-]{6}\.[\w-]{25,}\b", "[private token]", text)


class Privacy:
    def __init__(self, memory_dir: str | Path) -> None:
        self.memory_dir = Path(memory_dir)

    def refresh(self) -> tuple[str, ...]:
        # Unreadable or malformed privacy data must prevent public submission.
        paths: list[Path] = []

        def scan_error(error: OSError) -> None:
            raise error

        # rglob silently skips inaccessible subdirectories. Walk must propagate errors,
        # and reject directory links/junctions before deciding whether to descend.
        for directory, children, files in os.walk(
            self.memory_dir, onerror=scan_error, followlinks=False
        ):
            for candidate in [
                Path(directory),
                *(Path(directory) / name for name in children + files),
            ]:
                if (
                    candidate.is_symlink()
                    or getattr(candidate.lstat(), "st_file_attributes", 0) & 0x400
                ):
                    raise RuntimeError("Privacy source symlink/reparse point rejected")
            paths.extend(Path(directory) / name for name in files if name.lower().endswith(".md"))
        paths.sort()
        if not paths:
            raise RuntimeError("Privacy source unavailable")
        # Always re-read: ACL changes do not change file size/mtime. Publish the new
        # secret set only after every source has been read and validated successfully.
        values: list[str] = []
        for p in paths:
            text = p.read_text(encoding="utf-8-sig", errors="strict")
            values.extend(private_values(text))
        secrets = sorted(set(values), key=len, reverse=True)
        return tuple(secrets)

    def filter(self, text: str) -> str:
        return self.filter_many(text)[0]

    def filter_many(self, *texts: str) -> tuple[str, ...]:
        """Read once for a batch, then use one complete snapshot for all inputs."""
        secrets = self.refresh()
        return tuple(self._filter(text, secrets) for text in texts)

    def _filter(self, text: str, secrets: tuple[str, ...]) -> str:
        text = BLOCK.sub("[private]", text)
        if TAG.search(text):
            raise RuntimeError("Malformed private text")
        for value in secrets:
            # Spaces/newlines and case variation should not bypass literal DLP.
            pattern = r"\s+".join(re.escape(part) for part in value.split())
            text = re.sub(pattern, "[private]", text, flags=re.I)
        # Never publish credential-like values from local tool errors/output.
        return redact_credentials(text)
