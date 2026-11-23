"""Verify the Boolean parser fix in the repository-local pm2-logrotate 3.0.1.

pm2-logrotate 3.0.0 returned the default for real Boolean settings, so it ignored
`compress: true`; this script used to patch that. 3.0.1 ships the same fix upstream.
The check refuses any other version and confirms the fixed parser is present
without changing the installed module.
"""

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULE = ROOT / ".pm2/modules/pm2-logrotate/node_modules/pm2-logrotate"
VERSION = "3.0.1"
FIX = """const parseBool = (val, defaultVal = false) => {
  if (val === true || val === 'true') return true;
  if (val === false || val === 'false') return false;
  return defaultVal;
};"""


def verify(module=MODULE):
    module = Path(module)
    version = json.loads((module / "package.json").read_text())["version"]
    if version != VERSION:
        raise RuntimeError("Unexpected logrotate version; review before use")
    if FIX not in (module / "app.js").read_text(encoding="utf-8"):
        raise RuntimeError("logrotate Boolean parser fix missing; review before use")
    print("Repository-local logrotate Boolean fix verified")


if __name__ == "__main__":
    verify()
