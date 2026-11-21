"""
Deception Orchestrator — Active Defence Engine (Module 3)
=========================================================
Consumes alerts from Module 2's detection engine (alerts.log) and
dynamically deploys Docker honeypot containers to trap attackers.

Honeypot types:
  - SSH honeypot (Cowrie)   → deployed for BRUTE_FORCE attacks
  - Web honeypot (custom)   → deployed for SQL_INJECTION / UNKNOWN attacks

Key features:
  - Tails alerts.log for new entries (same pattern as detection_engine.py)
  - One honeypot per unique attacker IP (deduplication)
  - Auto-teardown after configurable TTL with no new activity
  - Docker Desktop availability check with user alert
  - Persists honeypot state to honeypots.json
  - Graceful shutdown cleans up all containers
"""

import json
import time
import threading
from datetime import datetime
from pathlib import Path
from typing import Optional

try:
    import docker
    from docker.errors import (
        DockerException,
        ImageNotFound,
        APIError,
        BuildError,
    )

    DOCKER_SDK_AVAILABLE = True
except ImportError:
    DOCKER_SDK_AVAILABLE = False


# ======================================================================
# Paths
# ======================================================================

PROJECT_DIR = Path(__file__).parent
ALERT_LOG = PROJECT_DIR / "alerts.log"
HONEYPOT_STATE_FILE = PROJECT_DIR / "honeypots.json"
HONEYPOT_LOGS_DIR = PROJECT_DIR / "honeypot_logs"
WEB_HONEYPOT_DIR = PROJECT_DIR / "honeypots" / "web_honeypot"

# ======================================================================
# ANSI color codes
# ======================================================================

RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


# ======================================================================
# Deception Orchestrator
# ======================================================================


class DeceptionOrchestrator:
    """Monitors alerts.log and deploys Docker honeypot containers."""

    # Honeypot type mapping
    ATTACK_TO_HONEYPOT = {
        "SQL_INJECTION": "web",
        "BRUTE_FORCE": "ssh",
        "XSS": "web",
        "DIR_TRAVERSAL": "web",
        "UNKNOWN": "web",
    }

    def __init__(
        self,
        port_range_start: int = 9000,
        port_range_end: int = 9100,
        ttl_seconds: int = 300,
    ):
        self.port_range_start = port_range_start
        self.port_range_end = port_range_end
        self.ttl_seconds = ttl_seconds
        self._next_port = port_range_start

        # Active honeypots: attacker_ip -> honeypot_info dict
        self.active_honeypots: dict[str, dict] = {}
        self._deployed_history: list[dict] = []  # survives teardown
        self._total_deployed = 0
        self._lock = threading.Lock()
        self._stop_event = threading.Event()
        self._docker_client: Optional[object] = None

        # Ensure log directory exists
        HONEYPOT_LOGS_DIR.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Docker connection & checks
    # ------------------------------------------------------------------

    def check_docker(self) -> bool:
        """Check if Docker Engine is reachable. Alert user if not."""
        if not DOCKER_SDK_AVAILABLE:
            self._print_docker_alert("Docker SDK for Python is not installed.\n" "  Run: pip install docker")
            return False

        try:
            self._docker_client = docker.from_env()
            self._docker_client.ping()
            print(f"  {GREEN}✓ Docker Engine is running.{RESET}")
            return True
        except DockerException as e:
            self._print_docker_alert(str(e))
            return False
        except Exception as e:
            self._print_docker_alert(str(e))
            return False

    def _print_docker_alert(self, reason: str) -> None:
        """Print a prominent alert telling the user to open Docker Desktop."""
        print(f"\n{RED}{BOLD}╔══════════════════════════════════════════════════════════╗{RESET}")
        print(f"{RED}{BOLD}║          ⚠  DOCKER DESKTOP IS NOT RUNNING  ⚠            ║{RESET}")
        print(f"{RED}{BOLD}╠══════════════════════════════════════════════════════════╣{RESET}")
        print(f"{RED}{BOLD}║                                                          ║{RESET}")
        print(
            f"{RED}{BOLD}║{RESET}  {YELLOW}Module 3 requires Docker to deploy honeypot containers.{RESET} {RED}{BOLD}║{RESET}"
        )
        print(f"{RED}{BOLD}║{RESET}                                                          {RED}{BOLD}║{RESET}")
        print(
            f"{RED}{BOLD}║{RESET}  {CYAN}Please open Docker Desktop and try again.{RESET}               {RED}{BOLD}║{RESET}"
        )
        print(f"{RED}{BOLD}║{RESET}                                                          {RED}{BOLD}║{RESET}")
        print(f"{RED}{BOLD}║{RESET}  {DIM}Reason: {reason[:50]}{RESET}")
        print(f"{RED}{BOLD}║                                                          ║{RESET}")
        print(f"{RED}{BOLD}╚══════════════════════════════════════════════════════════╝{RESET}\n")

    # ------------------------------------------------------------------
    # Image management
    # ------------------------------------------------------------------

    def _ensure_web_image(self) -> str:
        """Build the web honeypot Docker image if not already cached."""
        image_tag = "activedefenceir/web-honeypot:latest"
        try:
            self._docker_client.images.get(image_tag)
            print(f"  {GREEN}✓ Web honeypot image found (cached).{RESET}")
        except ImageNotFound:
            print(f"  {YELLOW}Building web honeypot image...{RESET}")
            try:
                image, build_logs = self._docker_client.images.build(
                    path=str(WEB_HONEYPOT_DIR),
                    tag=image_tag,
                    rm=True,
                )
                for chunk in build_logs:
                    if "stream" in chunk:
                        line = chunk["stream"].strip()
                        if line:
                            print(f"    {DIM}{line}{RESET}")
                print(f"  {GREEN}✓ Web honeypot image built.{RESET}")
            except BuildError as e:
                print(f"  {RED}✗ Failed to build web honeypot image: {e}{RESET}")
                raise
        return image_tag

    def _ensure_ssh_image(self) -> str:
        """Pull the Cowrie SSH honeypot image if not already cached."""
        image_tag = "cowrie/cowrie:latest"
        try:
            self._docker_client.images.get(image_tag)
            print(f"  {GREEN}✓ Cowrie SSH honeypot image found (cached).{RESET}")
        except ImageNotFound:
            print(f"  {YELLOW}Pulling Cowrie SSH honeypot image (this may take a minute)...{RESET}")
            try:
                self._docker_client.images.pull("cowrie/cowrie", tag="latest")
                print(f"  {GREEN}✓ Cowrie SSH image pulled.{RESET}")
            except APIError as e:
                print(f"  {RED}✗ Failed to pull Cowrie image: {e}{RESET}")
                raise
        return image_tag

    # ------------------------------------------------------------------
    # Port allocation
    # ------------------------------------------------------------------

    def _allocate_port(self) -> int:
        """Allocate the next available port from the configured range."""
        used_ports = {hp["host_port"] for hp in self.active_honeypots.values()}
        for port in range(self.port_range_start, self.port_range_end + 1):
            if port not in used_ports:
                return port
        raise RuntimeError(f"No available ports in range {self.port_range_start}-{self.port_range_end}")

    # ------------------------------------------------------------------
    # Honeypot deployment
    # ------------------------------------------------------------------

    def deploy_honeypot(self, alert: dict) -> Optional[dict]:
        """Deploy a honeypot container for the given alert.

        Returns the honeypot info dict, or None if a honeypot already
        exists for this attacker IP.
        """
        attacker_ip = alert["source_ip"]
        attack_type = alert.get("attack_type", "UNKNOWN")
        honeypot_type = self.ATTACK_TO_HONEYPOT.get(attack_type, "web")

        with self._lock:
            # Deduplicate — one honeypot per attacker IP
            if attacker_ip in self.active_honeypots:
                hp = self.active_honeypots[attacker_ip]
                hp["last_alert_time"] = datetime.utcnow().isoformat() + "Z"
                hp["alert_count"] = hp.get("alert_count", 1) + 1
                print(
                    f"  {DIM}[Orchestrator] Alert for {attacker_ip} — "
                    f"honeypot already active (alerts: {hp['alert_count']}){RESET}"
                )
                return None

            # Allocate port
            host_port = self._allocate_port()

            # Container name
            container_name = f"honeypot-{alert['alert_id']}"

            # Create log directory for this honeypot
            log_dir = HONEYPOT_LOGS_DIR / container_name
            log_dir.mkdir(parents=True, exist_ok=True)

        # Deploy based on type
        try:
            if honeypot_type == "ssh":
                container = self._deploy_ssh_honeypot(container_name, host_port, log_dir, alert)
            else:
                container = self._deploy_web_honeypot(container_name, host_port, log_dir, alert)
        except Exception as e:
            print(f"  {RED}✗ Failed to deploy {honeypot_type} honeypot: {e}{RESET}")
            return None

        # Build honeypot record
        honeypot_info = {
            "container_id": container.id[:12],
            "container_name": container_name,
            "alert_id": alert["alert_id"],
            "source_ip": attacker_ip,
            "attack_type": attack_type,
            "honeypot_type": honeypot_type,
            "service_type": "ssh" if honeypot_type == "ssh" else "http",
            "host_port": host_port,
            "deployed_at": datetime.utcnow().isoformat() + "Z",
            "last_alert_time": datetime.utcnow().isoformat() + "Z",
            "alert_count": 1,
            "is_active": True,
            "log_dir": str(log_dir),
        }

        with self._lock:
            self.active_honeypots[attacker_ip] = honeypot_info
            self._deployed_history.append(honeypot_info)
            self._total_deployed += 1

        self._print_deployment(honeypot_info)
        self._persist_state()
        return honeypot_info

    def _deploy_web_honeypot(self, name: str, host_port: int, log_dir: Path, alert: dict):
        """Deploy a web honeypot container."""
        image_tag = "activedefenceir/web-honeypot:latest"
        container = self._docker_client.containers.run(
            image=image_tag,
            name=name,
            detach=True,
            ports={"8080/tcp": host_port},
            volumes={
                str(log_dir.resolve()): {
                    "bind": "/var/log/honeypot",
                    "mode": "rw",
                }
            },
            environment={
                "HONEYPOT_ID": name,
                "HONEYPOT_PORT": "8080",
            },
            labels={
                "activedefenceir": "true",
                "honeypot_type": "web",
                "alert_id": alert["alert_id"],
                "attacker_ip": alert["source_ip"],
            },
        )
        return container

    def _deploy_ssh_honeypot(self, name: str, host_port: int, log_dir: Path, alert: dict):
        """Deploy a Cowrie SSH honeypot container."""
        image_tag = "cowrie/cowrie:latest"
        container = self._docker_client.containers.run(
            image=image_tag,
            name=name,
            detach=True,
            ports={"2222/tcp": host_port},
            volumes={
                str(log_dir.resolve()): {
                    "bind": "/cowrie/var/log/cowrie",
                    "mode": "rw",
                }
            },
            environment={
                "COWRIE_LOG_PATH": "/cowrie/var/log/cowrie",
            },
            labels={
                "activedefenceir": "true",
                "honeypot_type": "ssh",
                "alert_id": alert["alert_id"],
                "attacker_ip": alert["source_ip"],
            },
        )
        return container

    def _print_deployment(self, hp: dict) -> None:
        """Print a color-coded deployment notification."""
        honeypot_color = MAGENTA if hp["honeypot_type"] == "ssh" else CYAN

        print(f"\n{GREEN}{BOLD}+{'='*58}+{RESET}")
        print(f"{GREEN}{BOLD}|  🍯 HONEYPOT DEPLOYED                                    |{RESET}")
        print(f"{GREEN}{BOLD}+{'='*58}+{RESET}")
        print(f"{GREEN}|  {CYAN}Container:{RESET}   {hp['container_name']}")
        print(
            f"{GREEN}|  {CYAN}Type:{RESET}        {honeypot_color}{hp['honeypot_type'].upper()}{RESET} ({hp['service_type']})"
        )
        print(f"{GREEN}|  {CYAN}Target IP:{RESET}   {hp['source_ip']}")
        print(f"{GREEN}|  {CYAN}Attack:{RESET}      {hp['attack_type']}")
        print(f"{GREEN}|  {CYAN}Port:{RESET}        localhost:{hp['host_port']}")
        print(f"{GREEN}|  {CYAN}Logs:{RESET}        {hp['log_dir']}")
        print(f"{GREEN}{BOLD}+{'='*58}+{RESET}\n")

    # ------------------------------------------------------------------
    # Auto-teardown
    # ------------------------------------------------------------------

    def _teardown_loop(self) -> None:
        """Background thread that tears down expired honeypots."""
        while not self._stop_event.is_set():
            self._stop_event.wait(30)  # Check every 30 seconds
            if self._stop_event.is_set():
                break
            self._check_expired()

    def _check_expired(self) -> None:
        """Remove honeypots that have exceeded their TTL."""
        now = datetime.utcnow()
        expired_ips = []

        with self._lock:
            for ip, hp in self.active_honeypots.items():
                last_alert = datetime.fromisoformat(hp["last_alert_time"].replace("Z", "+00:00")).replace(tzinfo=None)
                if (now - last_alert).total_seconds() > self.ttl_seconds:
                    expired_ips.append(ip)

        for ip in expired_ips:
            self.teardown_by_ip(ip, reason="TTL expired")

    def teardown_by_ip(self, attacker_ip: str, reason: str = "manual") -> None:
        """Stop and remove the honeypot container for a given attacker IP."""
        with self._lock:
            hp = self.active_honeypots.pop(attacker_ip, None)

        if hp is None:
            return

        container_name = hp["container_name"]
        try:
            container = self._docker_client.containers.get(container_name)
            container.stop(timeout=5)
            container.remove(force=True)
            print(f"  {YELLOW}[Orchestrator] Honeypot {container_name} " f"torn down ({reason}).{RESET}")
        except Exception as e:
            print(f"  {DIM}[Orchestrator] Could not remove {container_name}: {e}{RESET}")

        hp["is_active"] = False
        hp["torn_down_at"] = datetime.utcnow().isoformat() + "Z"
        hp["teardown_reason"] = reason
        self._persist_state()

    # ------------------------------------------------------------------
    # Alert tailing
    # ------------------------------------------------------------------

    def tail_alerts(self, alert_path: Optional[Path] = None, poll_interval: float = 0.5) -> None:
        """Tail alerts.log for new entries and deploy honeypots."""
        path = alert_path or ALERT_LOG

        # Wait for the file to exist
        while not path.exists() and not self._stop_event.is_set():
            time.sleep(0.5)

        with open(path, "r", encoding="utf-8") as f:
            # Seek to end — only process NEW alerts
            f.seek(0, 2)

            while not self._stop_event.is_set():
                line = f.readline()
                if line:
                    line = line.strip()
                    if line:
                        try:
                            alert = json.loads(line)
                            self.deploy_honeypot(alert)
                        except json.JSONDecodeError:
                            continue
                else:
                    time.sleep(poll_interval)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> tuple[threading.Thread, threading.Thread]:
        """Start the orchestrator: alert tailing + auto-teardown.

        Returns the (tail_thread, teardown_thread) tuple.
        """
        tail_thread = threading.Thread(
            target=self.tail_alerts,
            daemon=True,
            name="Orchestrator-Tail",
        )
        teardown_thread = threading.Thread(
            target=self._teardown_loop,
            daemon=True,
            name="Orchestrator-Teardown",
        )
        tail_thread.start()
        teardown_thread.start()
        return tail_thread, teardown_thread

    def shutdown(self) -> None:
        """Signal stop and tear down all active honeypots."""
        self._stop_event.set()

        print(f"\n  {YELLOW}[Orchestrator] Tearing down all active honeypots...{RESET}")
        ips = list(self.active_honeypots.keys())
        for ip in ips:
            self.teardown_by_ip(ip, reason="shutdown")

        print(f"  {GREEN}[Orchestrator] All honeypots cleaned up.{RESET}")

    # ------------------------------------------------------------------
    # State persistence
    # ------------------------------------------------------------------

    def _persist_state(self) -> None:
        """Save current honeypot state to honeypots.json."""
        with self._lock:
            state = {
                "last_updated": datetime.utcnow().isoformat() + "Z",
                "active_honeypots": dict(self.active_honeypots),
            }
        with open(HONEYPOT_STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)

    # ------------------------------------------------------------------
    # Initialization (image pre-build)
    # ------------------------------------------------------------------

    def prepare_images(self) -> None:
        """Pre-build/pull all honeypot images so deployment is fast."""
        print(f"\n  {CYAN}Preparing honeypot images...{RESET}")
        self._ensure_web_image()
        self._ensure_ssh_image()
        print(f"  {GREEN}✓ All honeypot images ready.{RESET}")

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def summary(self) -> dict:
        """Return a summary of orchestrator activity."""
        with self._lock:
            active = {ip: hp for ip, hp in self.active_honeypots.items() if hp.get("is_active", False)}
        return {
            "total_deployed": self._total_deployed,
            "currently_active": len(active),
            "honeypots": list(self._deployed_history),
        }
