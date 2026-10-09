"""Idempotent Boolean parser fix for the repository-local pm2-logrotate 3.0.0."""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / ".pm2/modules/pm2-logrotate/node_modules/pm2-logrotate"
FIX = """const parseBool = (str, defaultVal = false) => {
  if (str === true || str === 'true') return true;
  if (str === false || str === 'false') return false;
  return defaultVal;
};"""


def patch(module=MODULE):
    module = Path(module)
    version = json.loads((module / "package.json").read_text())["version"]
    if version != "3.0.0":
        raise RuntimeError("Unexpected logrotate version; review before patching")
    path = module / "app.js"
    source = path.read_text(encoding="utf-8")
    if FIX not in source:
        pattern = r"const parseBool\s*=\s*\(str,\s*defaultVal\s*=\s*false\)\s*=>\s*\{.*?\n\};"
        result, count = re.subn(pattern, lambda _: FIX, source, flags=re.S)
        if count != 1:
            raise RuntimeError("Unrecognized Boolean parser; review before patching")
        backup = path.with_suffix(".js.bak")
        if not backup.exists():
            backup.write_text(source, encoding="utf-8")
        path.write_text(result, encoding="utf-8")
    if FIX not in path.read_text(encoding="utf-8"):
        raise RuntimeError("Written logrotate patch failed verification")
    print("Repository-local logrotate Boolean fix verified")


if __name__ == "__main__":
    patch()
