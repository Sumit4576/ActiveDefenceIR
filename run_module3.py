"""
Module 3 Runner -- Active Defence / Deception Orchestrator
===========================================================
Orchestrates the full Module 1 + Module 2 + Module 3 pipeline:
  1. Checks Docker availability (alerts user if not running)
  2. Pre-builds/pulls honeypot images
  3. Starts the mock target server (Module 1)
  4. Starts the traffic simulator (Module 1)
  5. Starts the detection engine (Module 2)
  6. Starts the deception orchestrator (Module 3)
  7. Starts the honeypot activity monitor (Module 3)

Usage:
    python run_module3.py
"""

import subprocess
import time
import sys
import os
from pathlib import Path

from detection_engine import DetectionEngine
from deception_orchestrator import DeceptionOrchestrator
from honeypot_monitor import HoneypotMonitor


def run_module_3():
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    MAGENTA = "\033[95m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"

    project_dir = os.path.dirname(os.path.abspath(__file__))
    model_dir = Path(project_dir) / "model"

    # ------------------------------------------------------------------
    # Banner
    # ------------------------------------------------------------------
    print(f"\n{MAGENTA}{BOLD}{'='*60}{RESET}")
    print(f"{MAGENTA}{BOLD}  Active Defence IR - Module 3: Deception Orchestrator{RESET}")
    print(f"{MAGENTA}{BOLD}{'='*60}{RESET}")
    print(f"{DIM}  Pipeline: Traffic Sim -> Detection Engine -> Honeypot Deploy{RESET}")

    # ------------------------------------------------------------------
    # Step 0: Check Docker availability
    # ------------------------------------------------------------------
    print(f"\n{CYAN}{BOLD}[Step 0] Checking Docker Engine...{RESET}")
    orchestrator = DeceptionOrchestrator(
        port_range_start=9000,
        port_range_end=9100,
        ttl_seconds=300,
    )

    if not orchestrator.check_docker():
        print(f"\n{RED}{BOLD}  Cannot proceed without Docker. Exiting.{RESET}\n")
        sys.exit(1)

    # ------------------------------------------------------------------
    # Step 1: Pre-build / pull honeypot images
    # ------------------------------------------------------------------
    print(f"\n{CYAN}{BOLD}[Step 1] Preparing honeypot images...{RESET}")
    try:
        orchestrator.prepare_images()
    except Exception as e:
        print(f"\n{RED}  Failed to prepare images: {e}{RESET}")
        print(f"{YELLOW}  Continuing anyway — images may be built on first deploy.{RESET}")

    # ------------------------------------------------------------------
    # Step 2: Ensure ML model is trained
    # ------------------------------------------------------------------
    if not (model_dir / "isolation_forest.pkl").exists():
        print(f"\n{CYAN}{BOLD}[Step 2] Training ML model (first run)...{RESET}")
        subprocess.run(
            [sys.executable, "train_model.py"],
            cwd=project_dir,
            check=True,
        )
    else:
        print(f"\n{CYAN}{BOLD}[Step 2]{RESET} {GREEN}ML model found.{RESET}")

    # ------------------------------------------------------------------
    # Step 3: Start the mock target server (Module 1)
    # ------------------------------------------------------------------
    print(f"\n{CYAN}{BOLD}[Step 3] Starting Mock Target Server...{RESET}")
    backend_process = subprocess.Popen(
        [sys.executable, "main.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=project_dir,
    )
    time.sleep(2)
    print(f"  {GREEN}✓ Target server running on port 8000.{RESET}")

    # ------------------------------------------------------------------
    # Step 4: Initialize detection engine (Module 2)
    # ------------------------------------------------------------------
    print(f"\n{CYAN}{BOLD}[Step 4] Starting Detection Engine (Module 2)...{RESET}")
    detection = DetectionEngine(model_dir=model_dir)
    detection.start_tailing()
    print(f"  {GREEN}✓ Detection engine tailing traffic.log.{RESET}")

    # ------------------------------------------------------------------
    # Step 5: Start deception orchestrator (Module 3)
    # ------------------------------------------------------------------
    print(f"\n{CYAN}{BOLD}[Step 5] Starting Deception Orchestrator (Module 3)...{RESET}")
    orchestrator.start()
    print(f"  {GREEN}✓ Orchestrator tailing alerts.log.{RESET}")

    # ------------------------------------------------------------------
    # Step 6: Start honeypot activity monitor (Module 3)
    # ------------------------------------------------------------------
    print(f"\n{CYAN}{BOLD}[Step 6] Starting Honeypot Activity Monitor...{RESET}")
    monitor = HoneypotMonitor(poll_interval=2.0)
    monitor.start()
    print(f"  {GREEN}✓ Monitor watching honeypot_logs/.{RESET}")

    # ------------------------------------------------------------------
    # Step 7: Start traffic simulator (Module 1)
    # ------------------------------------------------------------------
    print(f"\n{CYAN}{BOLD}[Step 7] Starting Traffic Simulator...{RESET}")
    generator_process = subprocess.Popen(
        [sys.executable, "log_generator.py"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        cwd=project_dir,
    )
    print(f"  {GREEN}✓ Traffic simulator generating mixed traffic.{RESET}")

    # ------------------------------------------------------------------
    # System is LIVE
    # ------------------------------------------------------------------
    print(f"\n{MAGENTA}{BOLD}{'='*60}{RESET}")
    print(f"{MAGENTA}{BOLD}  🍯  ACTIVE DEFENCE SYSTEM IS LIVE{RESET}")
    print(f"{MAGENTA}{BOLD}{'='*60}{RESET}")
    print(f"  {DIM}Traffic → Anomaly Detection → Honeypot Deployment{RESET}")
    print(f"  {DIM}Press Ctrl+C to stop the entire pipeline.{RESET}\n")

    # ------------------------------------------------------------------
    # Wait for Ctrl+C
    # ------------------------------------------------------------------
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print(f"\n{BOLD}Shutting down Module 3 pipeline...{RESET}")

        # Shutdown in reverse order
        monitor.stop()
        orchestrator.shutdown()
        detection.stop()
        backend_process.terminate()
        generator_process.terminate()

        # Wait for subprocesses to actually stop
        backend_process.wait(timeout=5)
        generator_process.wait(timeout=5)

        # ------------------------------------------------------------------
        # Session Summary
        # ------------------------------------------------------------------
        alert_count = len(detection.alerts)
        orch_summary = orchestrator.summary()
        mon_summary = monitor.summary()

        print(f"\n{CYAN}{BOLD}  Session Summary{RESET}")
        print(f"  {'─'*50}")
        print(f"  {CYAN}Detection Engine:{RESET}")
        print(f"    Anomaly alerts generated:  {alert_count}")
        if alert_count > 0:
            attack_types = {}
            for a in detection.alerts:
                t = a["attack_type"]
                attack_types[t] = attack_types.get(t, 0) + 1
            for atype, count in attack_types.items():
                print(f"      {atype}: {count}")

        print(f"  {MAGENTA}Deception Orchestrator:{RESET}")
        print(f"    Honeypots deployed:        {orch_summary['total_deployed']}")
        print(f"    Currently active:          {orch_summary['currently_active']}")

        print(f"  {GREEN}Honeypot Monitor:{RESET}")
        print(f"    Events captured:           {mon_summary['total_events']}")
        print(f"    Log files tracked:         {mon_summary['tracked_files']}")

        print(f"\n  {DIM}Logs persisted to:{RESET}")
        print(f"    {DIM}alerts.log            — Module 2 anomaly alerts{RESET}")
        print(f"    {DIM}honeypots.json        — Module 3 honeypot state{RESET}")
        print(f"    {DIM}honeypot_logs/        — Individual honeypot activity{RESET}")
        print(f"    {DIM}honeypot_activity.log — Aggregated honeypot events{RESET}")
        print(f"\n  {GREEN}{BOLD}Shutdown complete.{RESET}\n")


if __name__ == "__main__":
    run_module_3()
