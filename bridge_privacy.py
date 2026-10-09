"""Public context is opt-in; shared-channel output always receives DLP."""

import os
import re
from pathlib import Path

BLOCK = re.compile(r"<!--\s*PRIVATE:START\s*-->(.*?)<!--\s*PRIVATE:END\s*-->", re.I | re.S)
TAG = re.compile(r"<!--\s*PRIVATE:(?:START|END)\s*-->", re.I)


class Privacy:
    def __init__(self, memory_dir):
        self.memory_dir = Path(memory_dir)
        self.signature = None
        self.secrets = []

    def refresh(self) -> None:
        # Unreadable or malformed privacy data must prevent public submission.
        paths = []

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
        signature = [(str(p), p.stat().st_mtime_ns, p.stat().st_size) for p in paths]
        # Always re-read: ACL changes do not change file size/mtime. Publish the new
        # secret set only after every source has been read and validated successfully.
        values = []
        for p in paths:
            text = p.read_text(encoding="utf-8-sig", errors="strict")
            matches = list(BLOCK.finditer(text))
            if len(TAG.findall(text)) != len(matches) * 2:
                raise RuntimeError("Malformed privacy markers")
            for m in matches:
                secret = m.group(1).strip()
                if secret:
                    values.append(secret)
                    values.extend(line.strip() for line in secret.splitlines() if line.strip())
        self.secrets = sorted(set(values), key=len, reverse=True)
        self.signature = signature

    def filter(self, text):
        self.refresh()
        text = BLOCK.sub("[private]", text)
        if TAG.search(text):
            raise RuntimeError("Malformed private text")
        for value in self.secrets:
            # Spaces/newlines and case variation should not bypass literal DLP.
            pattern = r"\s+".join(re.escape(part) for part in value.split())
            text = re.sub(pattern, "[private]", text, flags=re.I)
        # Never publish credential-like values from local tool errors/output.
        text = re.sub(
            r"(?i)(?:https://discord(?:app)?\.com/api/webhooks/)\S+", "[private webhook]", text
        )
        text = re.sub(r"\bAIza[\w-]{30,}\b", "[private key]", text)
        text = re.sub(r"\b[\w-]{23,30}\.[\w-]{6}\.[\w-]{25,}\b", "[private token]", text)
        return text
