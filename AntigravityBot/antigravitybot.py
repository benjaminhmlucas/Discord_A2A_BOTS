"""BotBridge identity launcher; shared consumer is bridge_runtime.py."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from bridge_bot import main
from botbridge_common import ANTIGRAVITY_APP_ID

if __name__ == "__main__":
    main(ANTIGRAVITY_APP_ID)
