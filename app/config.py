from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
THREAT_INTEL_CSV = DATA_DIR / "threat_intel.csv"
MAX_EVENTS = 5000
MAX_ALERTS = 1000
WEBSOCKET_CLIENT_LIMIT = 100
