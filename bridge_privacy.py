"""Public context is opt-in; shared-channel output always receives DLP."""
import re
from pathlib import Path

BLOCK = re.compile(r'<!--\s*PRIVATE:START\s*-->(.*?)<!--\s*PRIVATE:END\s*-->', re.I | re.S)
TAG = re.compile(r'<!--\s*PRIVATE:(?:START|END)\s*-->', re.I)


class Privacy:
    def __init__(self, memory_dir):
        self.memory_dir = Path(memory_dir)
        self.signature = None
        self.secrets = []

    def refresh(self):
        # Unreadable or malformed privacy data must prevent public submission.
        paths = sorted(self.memory_dir.rglob('*.md'))
        if not paths:
            raise RuntimeError('Privacy source unavailable')
        signature = [(str(p), p.stat().st_mtime_ns, p.stat().st_size) for p in paths]
        if signature == self.signature:
            return
        values = []
        for p in paths:
            if p.is_symlink():
                raise RuntimeError('Privacy source symlink rejected')
            text = p.read_text(encoding='utf-8-sig', errors='strict')
            matches = list(BLOCK.finditer(text))
            if len(TAG.findall(text)) != len(matches) * 2:
                raise RuntimeError('Malformed privacy markers')
            for m in matches:
                secret = m.group(1).strip()
                if secret:
                    values.append(secret)
                    values.extend(line.strip() for line in secret.splitlines() if line.strip())
        self.secrets = sorted(set(values), key=len, reverse=True)
        self.signature = signature

    def filter(self, text):
        self.refresh()
        text = BLOCK.sub('[private]', text)
        if TAG.search(text):
            raise RuntimeError('Malformed private text')
        for value in self.secrets:
            # Spaces/newlines and case variation should not bypass literal DLP.
            pattern = r'\s+'.join(re.escape(part) for part in value.split())
            text = re.sub(pattern, '[private]', text, flags=re.I)
        # Never publish credential-like values from local tool errors/output.
        text = re.sub(r'(?i)(?:https://discord(?:app)?\.com/api/webhooks/)\S+', '[private webhook]', text)
        text = re.sub(r'\bAIza[\w-]{30,}\b', '[private key]', text)
        text = re.sub(r'\b[\w-]{23,30}\.[\w-]{6}\.[\w-]{25,}\b', '[private token]', text)
        return text
