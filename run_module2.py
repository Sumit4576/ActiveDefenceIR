"""
Module 2 Runner -- Detection Engineering
========================================
Orchestrates the full Module 1 + Module 2 pipeline:
  1. Starts the mock target server (Module 1)
  2. Starts the real-time detection engine (Module 2) -- tails traffic.log
  3. Starts the traffic simulator (Module 1)

Usage:
    python run_module2.py
"""

import subprocess
import time
import sys
import os
from pathlib import Path

from detection_engine import DetectionEngine


def run_module_2():
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    BOLD = "\033[1m"
    RESET = "\033[0m"

    project_dir = os.path.dirname(os.path.abspath(__file__))
    model_dir = Path(project_dir) / "model"

    print(f"\n{CYAN}{BOLD}{'='*60}{RESET}")
    print(f"{CYAN}{BOLD}  Active Defense IR - Module 2: Detection Engine{RESET}")
    print(f"{CYAN}{BOLD}{'='*60}{RESET}")

    # Check if model exists
    if not (model_dir / "isolation_forest.pkl").exists():
        print(f"\n{BOLD}  [!] No trained model found. Training now...{RESET}")
        subprocess.run(
            [sys.executable, "train_model.py"],
            cwd=project_dir,
            check=True,
        )

    # 1. Start the mock target server (Module 1 backend)
    print(f"\n{GREEN}-> Starting Mock Target Server...{RESET}")
    backend_process = subprocess.Popen(
        [sys.executable, "main.py"],
        stdout=sys.stdout,
        stderr=sys.stderr,
        cwd=project_dir,
    )

    # Give the server time to start
    time.sleep(2)

    # 2. Initialize the detection engine and start tailing traffic.log
    print(f"{GREEN}-> Initializing Detection Engine...{RESET}")
    engine = DetectionEngine(model_dir=model_dir)
    engine.start_tailing()

    # 3. Start the traffic simulator (Module 1 log generator)
    print(f"{GREEN}-> Starting Traffic Simulator...{RESET}")
    generator_process = subprocess.Popen(
        [sys.executable, "log_generator.py"],
        stdout=sys.stdout,
        stderr=sys.stderr,
        cwd=project_dir,
    )

    print(f"\n{CYAN}{BOLD}  System is LIVE -- monitoring for anomalies...{RESET}")
    print("  Press Ctrl+C to stop.\n")

    try:
        backend_process.wait()
    except KeyboardInterrupt:
        print(f"\n{BOLD}Shutting down Module 2...{RESET}")
        engine.stop()
        backend_process.terminate()
        generator_process.terminate()

        # Print summary
        alert_count = len(engine.alerts)
        print("\n  Session Summary:")
        print("  -----------------------------------")
        print(f"  Total alerts generated: {alert_count}")
        if alert_count > 0:
            attack_types = {}
            for a in engine.alerts:
                t = a["attack_type"]
                attack_types[t] = attack_types.get(t, 0) + 1
            for atype, count in attack_types.items():
                print(f"    {atype}: {count}")
        print("\n  Alerts persisted to: alerts.log")
        print("  Shutdown complete.\n")


if __name__ == "__main__":
    run_module_2()
