"""
Model Training Script (Module 2)
=================================
Standalone script to train (or retrain) the Isolation Forest anomaly
detection model on existing traffic log data.

Usage:
    python train_model.py                   # trains on traffic.log
    python train_model.py --log custom.log  # trains on a custom log file
    python train_model.py --synthesize 500  # synthesize extra entries
"""

import argparse
import random
from datetime import datetime, timedelta
from pathlib import Path

from feature_extractor import FeatureExtractor, load_log_file
from anomaly_detector import AnomalyDetector, FEATURE_COLS

# ======================================================================
# Synthetic data generation (to augment small training sets)
# ======================================================================

BENIGN_IPS = ["192.168.1.10", "192.168.1.15", "10.0.0.5", "192.168.1.20", "10.0.0.8"]
MALICIOUS_IPS = ["203.0.113.45", "198.51.100.22", "45.33.32.156", "185.220.101.1"]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "admin' --",
    "'; DROP TABLE users--",
    "' UNION SELECT * FROM passwords --",
    "1' OR '1'='1' /*",
    "admin'/*",
    "' OR 1=1 --",
]


def _generate_benign_entries(count: int, start_time: datetime) -> list[dict]:
    """Generate synthetic benign traffic entries."""
    entries = []
    ts = start_time
    for _ in range(count):
        ts += timedelta(seconds=random.uniform(1.0, 4.0))
        entry = {
            "timestamp": ts.isoformat() + "Z",
            "source_ip": random.choice(BENIGN_IPS),
            "http_method": "POST",
            "endpoint": "/api/login",
            "payload": {"username": "user", "password": "password123"},
            "status_code": 401,
        }
        entries.append(entry)
    return entries


def _generate_brute_force_burst(ip: str, start_time: datetime) -> list[dict]:
    """Generate a burst of brute-force login attempts."""
    entries = []
    ts = start_time
    for _ in range(random.randint(15, 25)):
        ts += timedelta(seconds=random.uniform(0.02, 0.1))
        entry = {
            "timestamp": ts.isoformat() + "Z",
            "source_ip": ip,
            "http_method": "POST",
            "endpoint": "/api/login",
            "payload": {
                "username": "admin",
                "password": f"pass{random.randint(100, 999)}",
            },
            "status_code": 401,
        }
        entries.append(entry)
    return entries


def _generate_sqli_burst(ip: str, start_time: datetime) -> list[dict]:
    """Generate a burst of SQL injection attempts."""
    entries = []
    ts = start_time
    for payload in random.sample(SQLI_PAYLOADS, k=min(4, len(SQLI_PAYLOADS))):
        ts += timedelta(seconds=random.uniform(0.3, 1.0))
        entry = {
            "timestamp": ts.isoformat() + "Z",
            "source_ip": ip,
            "http_method": "POST",
            "endpoint": "/api/login",
            "payload": {"username": payload, "password": "any"},
            "status_code": 401,
        }
        entries.append(entry)
    return entries


def synthesize_training_data(target_count: int) -> list[dict]:
    """Generate a mixed dataset of benign and malicious traffic."""
    print(f"\n  Synthesizing {target_count} additional training entries...")

    entries = []
    start = datetime(2026, 7, 7, 10, 0, 0)

    # ~70% benign
    benign_count = int(target_count * 0.70)
    entries.extend(_generate_benign_entries(benign_count, start))

    # ~30% malicious bursts interspersed
    malicious_target = target_count - benign_count
    generated = 0
    ts = start + timedelta(seconds=random.uniform(5, 15))

    while generated < malicious_target:
        ip = random.choice(MALICIOUS_IPS)
        attack = random.choice(["brute_force", "sqli"])

        if attack == "brute_force":
            burst = _generate_brute_force_burst(ip, ts)
        else:
            burst = _generate_sqli_burst(ip, ts)

        entries.extend(burst)
        generated += len(burst)
        ts += timedelta(seconds=random.uniform(10, 30))

    # Sort by timestamp to simulate real chronological flow
    entries.sort(key=lambda e: e["timestamp"])
    print(f"  Generated {len(entries)} entries ({benign_count} benign, {len(entries) - benign_count} malicious)")
    return entries


# ======================================================================
# Main training routine
# ======================================================================


def train(log_path: Path, synthesize_count: int = 0) -> None:
    """Train the Isolation Forest model."""

    CYAN = "\033[96m"
    GREEN = "\033[92m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    print(f"\n{CYAN}{BOLD}{'='*60}{RESET}")
    print(f"{CYAN}{BOLD}  Active Defence IR — Model Training (Module 2){RESET}")
    print(f"{CYAN}{BOLD}{'='*60}{RESET}")

    # Load existing log data
    print(f"\n  Loading log data from: {log_path}")
    entries = load_log_file(log_path)
    print(f"  Loaded {len(entries)} entries from log file.")

    # Optionally synthesize more data
    if synthesize_count > 0:
        synthetic = synthesize_training_data(synthesize_count)
        entries = synthetic + entries
        print(f"  Total training entries: {len(entries)}")

    if len(entries) < 10:
        print("\n  ⚠  WARNING: Very few training entries. Consider running")
        print("     Module 1 longer or using --synthesize to add data.\n")

    # Extract features
    print("\n  Extracting features...")
    extractor = FeatureExtractor(window_seconds=60)
    features_df = extractor.extract_batch(entries)
    print(f"  Feature matrix shape: {features_df.shape}")
    print("\n  Feature statistics:")
    print(features_df[FEATURE_COLS].describe().to_string())

    # Train model
    print("\n  Training Isolation Forest...")
    detector = AnomalyDetector(contamination=0.15, n_estimators=150)
    stats = detector.train(features_df)

    print(f"\n{GREEN}{BOLD}  Training Complete!{RESET}")
    print(f"  {'-'*40}")
    print(f"  Total samples:      {stats['total_samples']}")
    print(f"  Anomalies detected: {stats['anomalies_detected']} ({stats['anomaly_pct']}%)")
    print(f"  Normal detected:    {stats['normal_detected']}")
    print(f"  Score range:        [{stats['score_min']}, {stats['score_max']}]")
    print(f"  Score mean:         {stats['score_mean']}")

    # Save model
    print("\n  Saving model artifacts...")
    detector.save()

    print(f"\n{GREEN}{BOLD}  [OK] Model ready for use by detection_engine.py{RESET}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train the Isolation Forest anomaly detection model.")
    parser.add_argument(
        "--log",
        type=str,
        default=str(Path(__file__).parent / "traffic.log"),
        help="Path to the traffic log file (default: traffic.log)",
    )
    parser.add_argument(
        "--synthesize",
        type=int,
        default=500,
        help="Number of synthetic entries to generate for augmentation (default: 500, set 0 to disable)",
    )

    args = parser.parse_args()
    train(Path(args.log), synthesize_count=args.synthesize)
