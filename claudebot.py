"""BotBridge identity launcher; shared consumer is bridge_runtime.py."""

from bridge_bot import main
from botbridge_common import CLAUDE_BOT_APP_ID

if __name__ == "__main__":
    main(CLAUDE_BOT_APP_ID)
