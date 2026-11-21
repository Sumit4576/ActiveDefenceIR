"""
Feature Extractor for Anomaly Detection (Module 2)
===================================================
Transforms raw JSON traffic log entries into numerical feature vectors
suitable for the Isolation Forest anomaly detection model.

Features engineered:
    - request_rate:     Requests per IP in a sliding time window
    - unique_payloads:  Count of distinct payload strings per IP in window
    - payload_entropy:  Shannon entropy of the payload username field
    - payload_length:   Length of concatenated payload values
    - is_private_ip:    Binary flag — 1 if source IP is RFC-1918 private
    - failure_rate:     Fraction of 401 responses for the IP in window
    - time_delta_mean:  Mean inter-request interval (seconds) for the IP in window
"""

import json
import math
import ipaddress
from collections import defaultdict
from datetime import datetime, timedelta
from pathlib import Path

import pandas as pd


class FeatureExtractor:
    """Maintains a sliding window of recent log entries and extracts
    numerical features for each new entry."""

    def __init__(self, window_seconds: int = 60):
        self.window_seconds = window_seconds
        # ip -> list of (timestamp, log_entry) tuples
        self._buffer: dict[str, list[tuple[datetime, dict]]] = defaultdict(list)

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def extract(self, log_entry: dict) -> dict[str, float]:
        """Extract features for a single log entry, updating the sliding
        window buffer in the process."""
        ip = log_entry["source_ip"]
        ts = self._parse_ts(log_entry["timestamp"])

        # Add entry to the buffer
        self._buffer[ip].append((ts, log_entry))

        # Prune entries outside the window
        self._prune(ip, ts)

        # Build feature vector from current window state for this IP
        window = self._buffer[ip]
        return self._compute_features(log_entry, ip, ts, window)

    def extract_batch(self, log_entries: list[dict]) -> pd.DataFrame:
        """Extract features for a batch of log entries (e.g. for training).
        Resets internal buffer before processing to avoid stale state."""
        self._buffer.clear()
        rows = []
        for entry in log_entries:
            features = self.extract(entry)
            rows.append(features)
        return pd.DataFrame(rows)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _compute_features(
        self,
        entry: dict,
        ip: str,
        ts: datetime,
        window: list[tuple[datetime, dict]],
    ) -> dict[str, float]:
        """Compute the full feature vector for a single entry."""

        # --- request_rate: count of requests in the window ---
        request_rate = float(len(window))

        # --- unique_payloads: distinct payload strings in window ---
        payload_strings = set()
        for _, e in window:
            payload_strings.add(json.dumps(e.get("payload", {}), sort_keys=True))
        unique_payloads = float(len(payload_strings))

        # --- payload_entropy: Shannon entropy of username field ---
        username = str(entry.get("payload", {}).get("username", ""))
        payload_entropy = self._shannon_entropy(username)

        # --- payload_length: total length of payload values ---
        payload = entry.get("payload", {})
        payload_length = float(sum(len(str(v)) for v in payload.values()))

        # --- is_private_ip ---
        is_private = self._is_private_ip(ip)

        # --- failure_rate: fraction of 401s in window ---
        failures = sum(1 for _, e in window if e.get("status_code") == 401)
        failure_rate = failures / len(window) if window else 0.0

        # --- time_delta_mean: mean inter-request interval in seconds ---
        time_delta_mean = self._mean_time_delta(window)

        return {
            "request_rate": request_rate,
            "unique_payloads": unique_payloads,
            "payload_entropy": payload_entropy,
            "payload_length": payload_length,
            "is_private_ip": is_private,
            "failure_rate": failure_rate,
            "time_delta_mean": time_delta_mean,
        }

    def _prune(self, ip: str, current_ts: datetime) -> None:
        """Remove entries older than the sliding window."""
        cutoff = current_ts - timedelta(seconds=self.window_seconds)
        self._buffer[ip] = [(ts, e) for ts, e in self._buffer[ip] if ts >= cutoff]

    @staticmethod
    def _parse_ts(ts_str: str) -> datetime:
        """Parse ISO-format timestamp from the log entry."""
        # Handle trailing 'Z' for UTC
        clean = ts_str.replace("Z", "+00:00")
        try:
            return datetime.fromisoformat(clean)
        except ValueError:
            # Fallback: strip timezone and parse naive
            return datetime.fromisoformat(ts_str.rstrip("Z"))

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        freq: dict[str, int] = {}
        for ch in text:
            freq[ch] = freq.get(ch, 0) + 1
        length = len(text)
        entropy = 0.0
        for count in freq.values():
            p = count / length
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    @staticmethod
    def _is_private_ip(ip_str: str) -> float:
        """Return 1.0 if the IP is RFC-1918 private, else 0.0."""
        try:
            return 1.0 if ipaddress.ip_address(ip_str).is_private else 0.0
        except ValueError:
            return 0.0

    @staticmethod
    def _mean_time_delta(window: list[tuple[datetime, dict]]) -> float:
        """Compute mean time delta (seconds) between consecutive requests
        in the window. Returns 0.0 if fewer than 2 entries."""
        if len(window) < 2:
            return 0.0
        timestamps = [ts for ts, _ in window]
        deltas = [(timestamps[i + 1] - timestamps[i]).total_seconds() for i in range(len(timestamps) - 1)]
        return sum(deltas) / len(deltas) if deltas else 0.0


def load_log_file(log_path: Path) -> list[dict]:
    """Load a JSON-lines traffic log file and return a list of dicts."""
    entries = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    return entries
