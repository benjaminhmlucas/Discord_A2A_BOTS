"""Check tracked files (or a clean export) for private paths and common secret formats.

This checks the current tree, not Git history, and does not guarantee absence of secrets.
It reports file names only, never matched credential values or folder paths.
"""

import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PRIVATE_DIRS = {
    ".pm2",
    ".botbridge-memory",
    "private_memory",
    "openclaw_memory",
    "runtime_state",
    "chat_runtime",
    "backups",
    "retired",
    "generated",
    "node_modules",
    "tools",
    "logs",
}
PRIVATE_NAMES = {
    "auth.json",
    "credentials.json",
    "MEMORY.md",
    "LIVE_STATE.md",
    "HANDOFF.md",
    "SESSION_LOG.md",
    "incoming.md",
    "codex_incoming.md",
    "codex_discord_log.md",
    "log_management_state.json",
}
LOCAL_ROOT_FILES = {
    "bridge_config.json",
    "local_settings.json",
    "log_management.config.json",
    "public_context.md",
}
PATTERNS = [
    re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{30,}\b"),
    re.compile(r"\bAIza[A-Za-z0-9_-]{30,}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{30,}\b"),
    re.compile(r"https://discord(?:app)?\.com/api(?:/v\d+)?/webhooks/\d+/[A-Za-z0-9_-]+"),
    re.compile(r"\b[A-Za-z0-9_-]{23,30}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{25,}\b"),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
]
SEPARATOR = r"[\\/]{1,2}"  # One or two, so JSON-escaped Windows paths match too.
UNROOTED = r"(?<![\w.~-])"  # Not inside a URL path or a longer path.
# Where a folder name stops. A sentence's full stop may follow it; more name may not.
NAME_END = r"(?![\w-]|\.+[\w-])"
# Every web URL, removed before folder paths are matched so nothing inside one counts.
# file: URLs name local paths and stay.
URL = re.compile(r"\b(?!file:)[A-Za-z][A-Za-z0-9+.-]+://[^\s\"'`<>]*", re.I)
# One folder name: anything up to a separator, a character Windows forbids, or the line end.
FOLDER_NAME = r"[^\s\\/\"'`<>|:*?][^\\/\"'`<>|:*?\r\n]*"
SHARED_PROFILES = {"public", "default", "all users"}
# A shared profile named in an unquoted sentence, then white space or punctuation.
SHARED_IN_PROSE = re.compile(r"(?:Public|Default|All Users)[.,;!)\]]*(?:\s|$)", re.I)
# A profile folder, with any quote that opens the path, then the folder name.
PROFILE_PATTERNS = [
    re.compile(
        rf"(?P<quote>[\"'`]?)\b[A-Za-z]:{SEPARATOR}(?:Users|Documents and Settings)"
        rf"{SEPARATOR}(?P<name>{FOLDER_NAME})?",
        re.I,
    ),
    # Linux and macOS homes, and the WSL or Git Bash spelling of a Windows profile.
    re.compile(
        rf"(?P<quote>[\"'`]?){UNROOTED}/(?:home|(?:(?:mnt/)?[A-Za-z]/)?Users)/"
        rf"(?P<name>{FOLDER_NAME})?"
    ),
]
SHORT_NAME = r"[A-Z][A-Z0-9]{1,5}~[1-9][0-9]?"
# A rooted local path: a drive, or a leading separator not inside a longer word or path.
LOCAL_ROOT = rf"(?:\b[A-Za-z]:|(?<![\w.~:/\\-])(?=[\\/])){SEPARATOR}"
FOLDER_PATTERNS = [
    # Windows 8.3 short names, such as a shortened profile folder in a temp path, in
    # any case but only inside a rooted local path, so "HEAD~1" passes.
    re.compile(rf"{LOCAL_ROOT}(?:{FOLDER_NAME}{SEPARATOR})*{SHORT_NAME}(?![\w~-])", re.I),
]


def personal_profile(match):
    """Whether a profile folder match names a person rather than a placeholder or share.

    The whole folder name is compared with the shared profiles. A separator or the quote
    that opened the path marks where the name ends, so a Public profile path quoted with
    a longer name, or followed by more name before the next separator, is personal. In
    unquoted prose with no separator after it, the name may instead end at white space
    or sentence punctuation, so a sentence can name the Public profile and continue.
    """
    name = match["name"]
    if not name or name[0] in "<%${":
        return False
    if match["quote"] or match.string[match.end() : match.end() + 1] in ("\\", "/"):
        return name.casefold() not in SHARED_PROFILES
    return not SHARED_IN_PROSE.match(name)


def personal_path(text, folders):
    text = URL.sub(" ", text)
    return any(
        personal_profile(match) for pattern in PROFILE_PATTERNS for match in pattern.finditer(text)
    ) or any(pattern.search(text) for pattern in folders)


def private_folders(root):
    """This machine's home and checkout folders, plus any in BOTBRIDGE_PRIVATE_PATHS.

    BOTBRIDGE_PRIVATE_PATHS lists more folders (such as a deployed install) separated
    by os.pathsep. Bare drives and the filesystem root are never patterns. A folder
    on a Windows drive is also matched in its WSL and Git Bash spellings.
    """
    extra = os.environ.get("BOTBRIDGE_PRIVATE_PATHS", "").split(os.pathsep)
    patterns = []
    for folder in (Path.home(), Path(root), *(Path(item) for item in extra if item.strip())):
        parts = [part for part in re.split(r"[\\/]+", str(folder)) if part]
        if len(parts) < 2:
            continue
        # Keep a rooted path's leading separator, so the same text inside a URL passes.
        lead = SEPARATOR if str(folder)[:1] in ("\\", "/") else ""
        head, *rest = map(re.escape, parts)
        head = rf"{UNROOTED}{lead}{head}"
        if re.fullmatch(r"[A-Za-z]:", parts[0]):
            head = rf"(?:{head}|{UNROOTED}/(?:mnt/)?{parts[0][0]})"
        patterns.append(re.compile(SEPARATOR.join([head, *rest]) + NAME_END, re.I))
    return patterns


def check_path(relative):
    parts = relative.parts
    name = relative.name
    if any(p in PRIVATE_DIRS or p.startswith((".venv", "repair_")) for p in parts):
        return "private runtime/dependency directory"
    if name in PRIVATE_NAMES or (len(parts) == 1 and name in LOCAL_ROOT_FILES):
        return "private/local file"
    if (name.startswith(".env") and name != ".env.example") or name.startswith("dump.pm2"):
        return "credential/process configuration"
    if re.search(r"\.(?:log(?:\..*)?|sqlite.*|db|pem|key|bak|tmp|zip)$", name):
        return "runtime/credential/archive file"
    return None


def files(root):
    if (root / ".git").exists():
        # An extensionless "git" file can trigger Windows' Open With chooser.
        executable = "git.exe" if os.name == "nt" else "git"
        result = subprocess.run(
            [shutil.which(executable) or executable, "-C", str(root), "ls-files", "-z"],
            check=True,
            capture_output=True,
        )
        for item in result.stdout.decode("utf-8").split("\0"):
            if item:
                yield root / item
    else:
        for path in root.rglob("*"):
            if (
                path.is_file()
                and ".git" not in path.parts
                and "__pycache__" not in path.parts
                and path.suffix != ".pyc"
            ):
                yield path


def scan(root=ROOT):
    root = Path(root).resolve()
    folders = FOLDER_PATTERNS + private_folders(root)
    failures, count = [], 0
    for path in files(root):
        count += 1
        relative = path.relative_to(root)
        reason = check_path(relative)
        if path.is_symlink():
            reason = "symlink requires review"
        if reason:
            failures.append((str(relative), reason))
            continue
        if path.stat().st_size > 2_000_000:
            failures.append((str(relative), "oversize source file requires review"))
            continue
        data = path.read_bytes()
        if b"\0" in data:
            failures.append((str(relative), "binary file requires review"))
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            failures.append((str(relative), "non-UTF-8 file requires review"))
            continue
        if any(pattern.search(text) for pattern in PATTERNS):
            failures.append((str(relative), "credential-like content"))
        elif personal_path(text, folders):
            failures.append((str(relative), "personal folder path"))
    if count == 0:
        failures.append((".", "no tracked/exported files checked"))
    return count, failures


if __name__ == "__main__":
    count, failures = scan()
    for name, reason in failures:
        print(f"FAIL {name}: {reason}")
    print(f"Checked {count} files; {len(failures)} findings. Git history requires a separate scan.")
    sys.exit(bool(failures))
