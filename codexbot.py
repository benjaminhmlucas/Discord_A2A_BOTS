"""BotBridge identity launcher; shared consumer is bridge_runtime.py."""

from bridge_bot import main
from botbridge_common import CODEX_APP_ID

if __name__ == "__main__":
    main(CODEX_APP_ID)
