"""
Detection Engine -- Real-Time Anomaly Detection (Module 2)
=========================================================
Monitors traffic.log for new entries via file-tailing, extracts features
from each incoming log entry, and runs the Isolation Forest model to
detect anomalies in real-time.

Detected anomalies are printed as color-coded alerts and stored in
`alerts.log` for downstream consumption by Module 3.
"""

import json
import time
import uuid
import threading
from datetime import datetime
from pathlib import Path

from feature_extractor import FeatureExtractor
from anomaly_detector import AnomalyDetector

# Alert log file
ALERT_LOG = Path(__file__).parent / "alerts.log"
TRAFFIC_LOG = Path(__file__).parent / "traffic.log"


class DetectionEngine:
    """Real-time anomaly detection engine.

    Tails traffic.log for new entries and classifies each one using
    the trained Isolation Forest model."""

    def __init__(self, model_dir: Path | None = None, window_seconds: int = 60):
        self.extractor = FeatureExtractor(window_seconds=window_seconds)
        self.detector = AnomalyDetector()
        self.alerts: list[dict] = []
        self._stop_event = threading.Event()

        # Load trained model
        print("\n[DetectionEngine] Initializing...")
        self.detector.load(model_dir)
        print("[DetectionEngine] Ready -- monitoring traffic.\n")

    def on_log_entry(self, log_entry: dict) -> None:
        """Process a single log entry.

        Extracts features, runs the model, and generates an alert if
        the entry is classified as anomalous."""

        # Extract features
        features = self.extractor.extract(log_entry)

        # Run prediction
        is_anomaly, score = self.detector.predict(features)

        if is_anomaly:
            attack_type = self.detector.classify_attack_type(log_entry)
            alert = self._create_alert(log_entry, score, attack_type)
            self.alerts.append(alert)
            self._print_alert(alert)
            self._persist_alert(alert)

    def tail_log(self, log_path: Path | None = None, poll_interval: float = 0.5) -> None:
        """Tail a traffic log file, processing new lines as they appear.

        This method blocks until stop() is called. It seeks to the end
        of the file on startup and only processes new entries."""
        path = log_path or TRAFFIC_LOG

        # Wait for the file to exist
        while not path.exists() and not self._stop_event.is_set():
            time.sleep(0.5)

        with open(path, "r", encoding="utf-8") as f:
            # Seek to end — only process new entries
            f.seek(0, 2)

            while not self._stop_event.is_set():
                line = f.readline()
                if line:
                    line = line.strip()
                    if line:
                        try:
                            entry = json.loads(line)
                            self.on_log_entry(entry)
                        except json.JSONDecodeError:
                            continue
                else:
                    time.sleep(poll_interval)

    def start_tailing(self, log_path: Path | None = None) -> threading.Thread:
        """Start tailing the log file in a background thread.

        Returns the thread object."""
        t = threading.Thread(
            target=self.tail_log,
            args=(log_path,),
            daemon=True,
            name="DetectionEngine-Tail",
        )
        t.start()
        return t

    def stop(self) -> None:
        """Signal the tail loop to stop."""
        self._stop_event.set()

    def _create_alert(self, log_entry: dict, anomaly_score: float, attack_type: str) -> dict:
        """Build a structured alert dict."""
        return {
            "alert_id": str(uuid.uuid4())[:8],
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "source_ip": log_entry["source_ip"],
            "endpoint": log_entry.get("endpoint", "unknown"),
            "attack_type": attack_type,
            "anomaly_score": round(anomaly_score, 4),
            "payload_snapshot": log_entry.get("payload", {}),
            "status": "new",
        }

    @staticmethod
    def _print_alert(alert: dict) -> None:
        """Print a color-coded alert to the console."""
        # ANSI color codes
        RED = "\033[91m"
        YELLOW = "\033[93m"
        CYAN = "\033[96m"
        BOLD = "\033[1m"
        RESET = "\033[0m"

        severity = "HIGH" if alert["anomaly_score"] < -0.2 else "MEDIUM"
        color = RED if severity == "HIGH" else YELLOW

        print(f"\n{color}{BOLD}+======================================================+{RESET}")
        print(f"{color}{BOLD}|  [!] ANOMALY DETECTED -- {severity} SEVERITY{' ' * (28 - len(severity))}|{RESET}")
        print(f"{color}{BOLD}+======================================================+{RESET}")
        print(f"{color}|  {CYAN}Alert ID:{RESET}     {alert['alert_id']}")
        print(f"{color}|  {CYAN}Source IP:{RESET}    {alert['source_ip']}")
        print(f"{color}|  {CYAN}Attack Type:{RESET}  {alert['attack_type']}")
        print(f"{color}|  {CYAN}Score:{RESET}        {alert['anomaly_score']}")
        print(f"{color}|  {CYAN}Endpoint:{RESET}     {alert['endpoint']}")
        print(f"{color}|  {CYAN}Timestamp:{RESET}    {alert['timestamp']}")
        print(f"{color}{BOLD}+======================================================+{RESET}\n")

    @staticmethod
    def _persist_alert(alert: dict) -> None:
        """Append the alert as a JSON line to alerts.log."""
        with open(ALERT_LOG, "a", encoding="utf-8") as f:
            f.write(json.dumps(alert) + "\n")
