"""
Module 4 Runner -- AI Investigation
=====================================
Can run in two modes:
  1. Full pipeline (M1+M2+M3+M4): python run_module4.py
  2. Investigation only:           python run_module4.py --investigate-only

In full pipeline mode, it runs Module 3 for a configurable duration,
then triggers the AI investigation on the collected logs.

In investigate-only mode, it runs the AI agents directly
against the existing alerts.log and honeypot_activity.log files.
"""

import sys
import asyncio
from ai_agents import run_investigation


def main():
    investigate_only = "--investigate-only" in sys.argv

    M = "\033[95m"
    B = "\033[1m"
    R = "\033[0m"

    if investigate_only:
        print(f"\n{M}{B}  Running AI Investigation on existing logs...{R}")
        asyncio.run(run_investigation())
    else:
        print(f"\n{M}{B}  Running full pipeline (M1+M2+M3) then investigating...{R}")
        print("  Tip: Use --investigate-only to skip the pipeline.\n")

        import subprocess
        import time
        import os
        from pathlib import Path
        from detection_engine import DetectionEngine
        from deception_orchestrator import DeceptionOrchestrator
        from honeypot_monitor import HoneypotMonitor

        project_dir = os.path.dirname(os.path.abspath(__file__))
        model_dir = Path(project_dir) / "model"

        C = "\033[96m"
        Y = "\033[93m"

        # Check Docker
        orchestrator = DeceptionOrchestrator(port_range_start=9000, port_range_end=9100, ttl_seconds=300)
        if not orchestrator.check_docker():
            print("\n\033[91m\033[1m  Cannot proceed without Docker. Exiting.\033[0m\n")
            sys.exit(1)

        try:
            orchestrator.prepare_images()
        except Exception:
            pass

        # Train model if needed
        if not (model_dir / "isolation_forest.pkl").exists():
            subprocess.run([sys.executable, "train_model.py"], cwd=project_dir, check=True)

        # Start pipeline
        backend = subprocess.Popen(
            [sys.executable, "main.py"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=project_dir,
        )
        time.sleep(2)

        detection = DetectionEngine(model_dir=model_dir)
        detection.start_tailing()

        orchestrator.start()

        monitor = HoneypotMonitor(poll_interval=2.0)
        monitor.start()

        generator = subprocess.Popen(
            [sys.executable, "log_generator.py"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=project_dir,
        )

        duration = 60
        print(f"\n{C}{B}  Pipeline running for {duration}s to collect attack data...{R}")
        print(f"  {Y}(Press Ctrl+C to stop early and begin investigation){R}\n")

        try:
            time.sleep(duration)
        except KeyboardInterrupt:
            pass

        # Shutdown pipeline
        print(f"\n{C}{B}  Stopping pipeline, starting investigation...{R}")
        monitor.stop()
        orchestrator.shutdown()
        detection.stop()
        backend.terminate()
        generator.terminate()
        backend.wait(timeout=5)
        generator.wait(timeout=5)

        # Now run the AI investigation
        asyncio.run(run_investigation())


if __name__ == "__main__":
    main()
