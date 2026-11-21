import os
import sys
import tempfile
from pathlib import Path

# Redirect the traffic log before logger.py is imported so tests never touch
# the real traffic.log in the project root.
_TMP_LOG = Path(tempfile.mkdtemp()) / "traffic.log"
os.environ["TRAFFIC_LOG_FILE"] = str(_TMP_LOG)

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))
