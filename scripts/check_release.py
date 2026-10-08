"""Check tracked files (or a clean export) for private paths and common secret formats.

This checks the current tree, not Git history, and does not guarantee absence of secrets.
It reports file names only, never matched credential values.
"""
import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PRIVATE_DIRS = {'.pm2', 'private_memory', 'openclaw_memory', 'runtime_state', 'chat_runtime',
                'backups', 'retired', 'generated', 'node_modules', 'tools', 'logs'}
PRIVATE_NAMES = {'auth.json', 'credentials.json', 'MEMORY.md', 'LIVE_STATE.md', 'HANDOFF.md',
                 'SESSION_LOG.md', 'incoming.md', 'codex_incoming.md', 'codex_discord_log.md',
                 'log_management_state.json'}
LOCAL_ROOT_FILES = {'bridge_config.json', 'local_settings.json', 'log_management.config.json', 'public_context.md'}
PATTERNS = [
    re.compile(r'\bsk-ant-[A-Za-z0-9_-]{20,}\b'),
    re.compile(r'\bsk-[A-Za-z0-9_-]{30,}\b'),
    re.compile(r'\bAIza[A-Za-z0-9_-]{30,}\b'),
    re.compile(r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b'),
    re.compile(r'\bgithub_pat_[A-Za-z0-9_]{30,}\b'),
    re.compile(r'https://discord(?:app)?\.com/api(?:/v\d+)?/webhooks/\d+/[A-Za-z0-9_-]+'),
    re.compile(r'\b[A-Za-z0-9_-]{23,30}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{25,}\b'),
    re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
]


def check_path(relative):
    parts = relative.parts
    name = relative.name
    if any(p in PRIVATE_DIRS or p.startswith(('.venv', 'repair_')) for p in parts):
        return 'private runtime/dependency directory'
    if name in PRIVATE_NAMES or (len(parts) == 1 and name in LOCAL_ROOT_FILES):
        return 'private/local file'
    if (name.startswith('.env') and name != '.env.example') or name.startswith('dump.pm2'):
        return 'credential/process configuration'
    if re.search(r'\.(?:log(?:\..*)?|sqlite.*|db|pem|key|bak|tmp|zip)$', name):
        return 'runtime/credential/archive file'
    return None


def files(root):
    if (root / '.git').exists():
        result = subprocess.run(['git', '-C', str(root), 'ls-files', '-z'], check=True, capture_output=True)
        for item in result.stdout.decode('utf-8').split('\0'):
            if item:
                yield root / item
    else:
        for path in root.rglob('*'):
            if path.is_file() and '.git' not in path.parts and '__pycache__' not in path.parts and path.suffix != '.pyc':
                yield path


def scan(root=ROOT):
    root = Path(root).resolve()
    failures, count = [], 0
    for path in files(root):
        count += 1
        relative = path.relative_to(root)
        reason = check_path(relative)
        if path.is_symlink():
            reason = 'symlink requires review'
        if reason:
            failures.append((str(relative), reason))
            continue
        if path.stat().st_size > 2_000_000:
            failures.append((str(relative), 'oversize source file requires review'))
            continue
        data = path.read_bytes()
        if b'\0' in data:
            failures.append((str(relative), 'binary file requires review'))
            continue
        try:
            text = data.decode('utf-8')
        except UnicodeDecodeError:
            failures.append((str(relative), 'non-UTF-8 file requires review'))
            continue
        if any(pattern.search(text) for pattern in PATTERNS):
            failures.append((str(relative), 'credential-like content'))
    if count == 0:
        failures.append(('.', 'no tracked/exported files checked'))
    return count, failures


if __name__ == '__main__':
    count, failures = scan()
    for name, reason in failures:
        print(f'FAIL {name}: {reason}')
    print(f'Checked {count} files; {len(failures)} findings. Git history requires a separate scan.')
    sys.exit(bool(failures))
