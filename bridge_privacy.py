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


WEBHOOK = re.compile(r"https://discord(?:app)?\.com/api/webhooks/\S+", re.I)
API_KEY = re.compile(r"\bAIza[\w-]{30,}\b")
TOKEN = re.compile(r"\b[\w-]{23,30}\.[\w-]{6}\.[\w-]{25,}\b")
CREDENTIAL_PATTERNS = (
    (WEBHOOK, "[private webhook]"),
    (API_KEY, "[private key]"),
    (TOKEN, "[private token]"),
)
# WEBHOOK and API_KEY run to the end of their character run, so a match starting inside
# one ends where it does; plain matching finds them all without quadratic rescanning.
RUN_PATTERNS = (WEBHOOK, API_KEY)


def redact_credentials(text: str) -> str:
    for pattern, placeholder in CREDENTIAL_PATTERNS:
        text = pattern.sub(placeholder, text)
    return text


def redact_spans(
    text: str, values: tuple[str, ...], credentials: tuple[str, ...], *, markers: bool = True
) -> str:
    """Redact PRIVATE blocks, PRIVATE values and credentials found in the original text.

    Every match, including overlapping occurrences of the same value, is located in the
    unmodified text; overlapping or adjacent matches are merged and each merged range is
    replaced once. Sequential substitution cannot be used here: one replacement can
    split or swallow part of another match, leaving the rest of a private value or
    credential in the output. With markers=False (owner-private text), PRIVATE blocks
    are left visible and only the supplied values and credentials are redacted.
    """
    spans: list[tuple[int, int]] = []
    if markers:
        spans = [match.span() for match in BLOCK.finditer(text)]
        if any(
            not any(a <= t.start() and t.end() <= b for a, b in spans) for t in TAG.finditer(text)
        ):
            raise RuntimeError("Malformed private text")
    # Spaces/newlines and case variation should not bypass literal DLP. Blank values
    # would match the empty string everywhere, so they are skipped.
    patterns = [
        re.compile(r"\s+".join(map(re.escape, value.split())), re.I)
        for value in values
        if value.split()
    ]
    patterns += [re.compile(re.escape(secret)) for secret in filter(None, credentials)]
    for pattern in patterns:
        spans.extend(_overlapping(pattern, text))
    shapes = _shape_spans(text)
    covered = [False] * len(text)
    for start, end in spans + shapes:
        covered[start:end] = [True] * (end - start)
    while True:
        # A placeholder splits a character run, so removing a value can create a credential
        # shape, and masking one shape can cut off another that only exists once a value
        # is removed. Search the text with only private values removed and with everything
        # removed, map new shapes back onto the original text, and repeat. Each pass
        # covers at least one more original character, so this terminates.
        new = []
        for hidden in (spans, spans + shapes):
            output, origin = _render(text, hidden)
            for start, end in _shape_spans(output):
                span = (origin[start][0], origin[end - 1][1])
                if not all(covered[span[0] : span[1]]):
                    new.append(span)
                    covered[span[0] : span[1]] = [True] * (span[1] - span[0])
        if not new:
            return _render(text, spans + shapes)[0]
        shapes += new


def _overlapping(pattern: re.Pattern[str], text: str) -> list[tuple[int, int]]:
    # A lookahead reports every start position, so overlapping occurrences count.
    lookahead = re.compile(f"(?=({pattern.pattern}))", pattern.flags)
    return [match.span(1) for match in lookahead.finditer(text)]


def _shape_spans(text: str) -> list[tuple[int, int]]:
    # A second token can start inside the first token's last segment and extend past it.
    spans = _overlapping(TOKEN, text)
    spans.extend(match.span() for pattern in RUN_PATTERNS for match in pattern.finditer(text))
    return spans


def _render(text: str, spans: list[tuple[int, int]]) -> tuple[str, list[tuple[int, int]]]:
    """Replace merged spans once; map each output character to its original range."""
    output: list[str] = []
    origin: list[tuple[int, int]] = []
    position = 0
    for start, end in sorted(spans):
        if start > position or not output:
            output.append(text[position:start])
            origin.extend((index, index + 1) for index in range(position, start))
            output.append("[private]")
            origin.extend([(start, end)] * len("[private]"))
        elif end > position:
            # Extend the current placeholder's original range to the merged span.
            first = len(origin) - len("[private]")
            origin[first:] = [(origin[first][0], end)] * len("[private]")
        position = max(position, end)
    output.append(text[position:])
    origin.extend((index, index + 1) for index in range(position, len(text)))
    return "".join(output), origin


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
            entries = [(Path(directory), False), *((Path(directory) / n, False) for n in children)]
            # Memory note commits create and rename non-Markdown temporaries in this tree;
            # one may vanish after listing. Directories and Markdown sources must not.
            entries += [(Path(directory) / n, not n.lower().endswith(".md")) for n in files]
            for candidate, transient in entries:
                try:
                    metadata = candidate.lstat()
                except FileNotFoundError:
                    if transient:
                        continue
                    raise
                if candidate.is_symlink() or getattr(metadata, "st_file_attributes", 0) & 0x400:
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
