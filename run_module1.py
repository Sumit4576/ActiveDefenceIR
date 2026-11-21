import subprocess
import time
import sys
import os


def run_module_1():
    print("Starting Active Defence IR - Module 1")

    # 1. Start FastAPI Backend
    print("-> Starting FastAPI Backend...")
    backend_process = subprocess.Popen(
        [sys.executable, "main.py"],
        stdout=sys.stdout,
        stderr=sys.stderr,
        cwd=os.path.dirname(os.path.abspath(__file__)),
    )

    # Give it a second to initialize
    time.sleep(2)

    # 2. Start Log Generator
    print("-> Starting Traffic Simulator...")
    generator_process = subprocess.Popen(
        [sys.executable, "log_generator.py"],
        stdout=sys.stdout,
        stderr=sys.stderr,
        cwd=os.path.dirname(os.path.abspath(__file__)),
    )

    try:
        # Keep running until user stops
        backend_process.wait()
    except KeyboardInterrupt:
        print("\nShutting down Module 1...")
        backend_process.terminate()
        generator_process.terminate()
        print("Shutdown complete.")


if __name__ == "__main__":
    run_module_1()
