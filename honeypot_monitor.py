"""
Honeypot Activity Monitor (Module 3)
=====================================
Watches the honeypot_logs/ directory for new activity logs from deployed
honeypot containers. Aggregates them into a unified honeypot_activity.log
file for Module 4's AI agents, and prints a live feed to the terminal.
"""

import json
import threading
from datetime import datetime
from pathlib import Path

# ======================================================================
# Paths
# ======================================================================

PROJECT_DIR = Path(__file__).parent
HONEYPOT_LOGS_DIR = PROJECT_DIR / "honeypot_logs"
AGGREGATED_LOG = PROJECT_DIR / "honeypot_activity.log"

# ANSI colors
MAGENTA = "\033[95m"
CYAN = "\033[96m"
YELLOW = "\033[93m"
GREEN = "\033[92m"
RED = "\033[91m"
DIM = "\033[2m"
BOLD = "\033[1m"
RESET = "\033[0m"


class HoneypotMonitor:
    """Watches honeypot log directories and aggregates activity."""

    def __init__(self, poll_interval: float = 2.0):
        self.poll_interval = poll_interval
        self._stop_event = threading.Event()
        # Track file positions: file_path -> last_read_position
        self._file_positions: dict[str, int] = {}
        self.event_count = 0

        # Ensure directories exist
        HONEYPOT_LOGS_DIR.mkdir(parents=True, exist_ok=True)

    def start(self) -> threading.Thread:
        """Start the monitor in a background thread."""
        t = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="HoneypotMonitor",
        )
        t.start()
        return t

    def stop(self) -> None:
        """Signal the monitor to stop."""
        self._stop_event.set()

    def _monitor_loop(self) -> None:
        """Main polling loop — scans for new log content."""
        while not self._stop_event.is_set():
            try:
                self._scan_logs()
            except Exception as e:
                print(f"  {DIM}[Monitor] Error scanning logs: {e}{RESET}")
            self._stop_event.wait(self.poll_interval)

    def _scan_logs(self) -> None:
        """Scan all honeypot log subdirectories for new content."""
        if not HONEYPOT_LOGS_DIR.exists():
            return

        for honeypot_dir in HONEYPOT_LOGS_DIR.iterdir():
            if not honeypot_dir.is_dir():
                continue

            # Look for any .log or .json log files
            log_files = list(honeypot_dir.glob("**/*.log")) + list(honeypot_dir.glob("**/*.json"))

            for log_file in log_files:
                self._read_new_lines(log_file, honeypot_dir.name)

    def _read_new_lines(self, log_file: Path, honeypot_name: str) -> None:
        """Read new lines from a log file since last check."""
        file_key = str(log_file)
        last_pos = self._file_positions.get(file_key, 0)

        try:
            file_size = log_file.stat().st_size
        except OSError:
            return

        if file_size <= last_pos:
            return  # No new content

        try:
            with open(log_file, "r", encoding="utf-8", errors="replace") as f:
                f.seek(last_pos)
                new_content = f.read()
                self._file_positions[file_key] = f.tell()
        except OSError:
            return

        # Process each new line
        for line in new_content.strip().splitlines():
            line = line.strip()
            if not line:
                continue

            self.event_count += 1

            # Try to parse as JSON for pretty printing
            event = None
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                pass

            # Aggregate to unified log
            self._append_aggregated(honeypot_name, line, event)

            # Print live feed
            self._print_event(honeypot_name, event, line)

    def _append_aggregated(self, honeypot_name: str, raw_line: str, event: dict | None) -> None:
        """Append event to the aggregated honeypot_activity.log."""
        aggregated_entry = {
            "honeypot": honeypot_name,
            "received_at": datetime.utcnow().isoformat() + "Z",
        }

        if event is not None:
            aggregated_entry["event"] = event
        else:
            aggregated_entry["raw"] = raw_line

        with open(AGGREGATED_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(aggregated_entry) + "\n")

    def _print_event(self, honeypot_name: str, event: dict | None, raw_line: str) -> None:
        """Print a color-coded event to the terminal."""
        if event is None:
            print(f"  {DIM}[{honeypot_name}] {raw_line[:120]}{RESET}")
            return

        event_type = event.get("event_type", event.get("eventid", "unknown"))
        source_ip = event.get("source_ip", event.get("src_ip", "?"))

        # Color-code by severity
        if any(kw in str(event_type).upper() for kw in ["SQLI", "INJECTION", "CRITICAL", "login.failed"]):
            color = RED
            icon = "🔴"
        elif any(kw in str(event_type).upper() for kw in ["POST", "QUERY", "command", "login"]):
            color = YELLOW
            icon = "🟡"
        else:
            color = DIM
            icon = "⚪"

        print(f"  {color}{icon} [{honeypot_name}] " f"{event_type} from {source_ip}{RESET}")

        # Print extra details for interesting events
        if event.get("injection_detected") or event.get("severity") == "CRITICAL":
            payload = event.get("payload", event.get("query", ""))
            if payload:
                print(f"     {RED}↳ Payload: {str(payload)[:100]}{RESET}")

    def summary(self) -> dict:
        """Return a summary of monitored activity."""
        return {
            "total_events": self.event_count,
            "tracked_files": len(self._file_positions),
        }
