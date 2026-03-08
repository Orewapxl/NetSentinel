from __future__ import annotations

import os
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = Path(os.getenv("NETSENTINEL_DATA_DIR", BASE_DIR / "data"))
RUNTIME_DIR = Path(os.getenv("NETSENTINEL_RUNTIME_DIR", DATA_DIR / "runtime"))
THREAT_INTEL_CSV = Path(os.getenv("NETSENTINEL_THREAT_INTEL_CSV", DATA_DIR / "threat_intel.csv"))

MAX_EVENTS = int(os.getenv("NETSENTINEL_MAX_EVENTS", "5000"))
MAX_ALERTS = int(os.getenv("NETSENTINEL_MAX_ALERTS", "1000"))
WEBSOCKET_CLIENT_LIMIT = int(os.getenv("NETSENTINEL_WEBSOCKET_CLIENT_LIMIT", "100"))
HOST = os.getenv("NETSENTINEL_HOST", "0.0.0.0")
PORT = int(os.getenv("NETSENTINEL_PORT", "8000"))
LOG_LEVEL = os.getenv("NETSENTINEL_LOG_LEVEL", "info")
PERSIST_RUNTIME = os.getenv("NETSENTINEL_PERSIST_RUNTIME", "true").strip().lower() in {"1", "true", "yes", "on"}
APP_ENV = os.getenv("NETSENTINEL_APP_ENV", "production")

RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)
