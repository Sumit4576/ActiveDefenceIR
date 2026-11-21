import json
import logging
import os
from datetime import datetime
from pathlib import Path

# Setup the log file path
LOG_FILE = Path(os.environ.get("TRAFFIC_LOG_FILE", Path(__file__).parent / "traffic.log"))

# Create a custom logger
logger = logging.getLogger("TrafficLogger")
logger.setLevel(logging.INFO)

# File handler for JSON logs
file_handler = logging.FileHandler(LOG_FILE)
file_handler.setLevel(logging.INFO)
logger.addHandler(file_handler)

# ------------------------------------------------------------------
# Subscriber callback system (Module 2 hook)
# External modules can register callbacks to receive log entries
# in real-time without polling the log file.
# ------------------------------------------------------------------
_subscribers: list = []


def subscribe(callback) -> None:
    """Register a callback to be invoked on every new log entry.

    The callback receives a single argument: the log_entry dict.
    """
    _subscribers.append(callback)


def log_request(source_ip: str, http_method: str, endpoint: str, payload: dict, status_code: int):
    """Logs the HTTP request in structured JSON format."""
    log_entry = {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "source_ip": source_ip,
        "http_method": http_method,
        "endpoint": endpoint,
        "payload": payload,
        "status_code": status_code,
    }
    logger.info(json.dumps(log_entry))

    # Notify all subscribers
    for cb in _subscribers:
        try:
            cb(log_entry)
        except Exception as e:
            print(f"[Logger] Subscriber error: {e}")
