"""
WebSocket Bridge Server
========================
Tails the project's log files and broadcasts events to the React
dashboard over WebSocket. Runs alongside the existing pipeline
without modifying any backend module.

Usage:
    python ws_server.py

Connects to:  ws://localhost:8765/ws/dashboard
"""

import json
import asyncio
import os
from pathlib import Path
from datetime import datetime

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import uvicorn

PROJECT_DIR = Path(__file__).parent
ALERTS_LOG = PROJECT_DIR / "alerts.log"
HONEYPOT_STATE = PROJECT_DIR / "honeypots.json"
HONEYPOT_ACTIVITY = PROJECT_DIR / "honeypot_activity.log"
AGENT_ACTIVITY = PROJECT_DIR / "agent_activity.log"
THREAT_REPORT = PROJECT_DIR / "threat_report.md"

app = FastAPI()
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


# ── Connection Manager ──


class ConnectionManager:
    def __init__(self):
        self.connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket):
        await ws.accept()
        self.connections.append(ws)

    def disconnect(self, ws: WebSocket):
        if ws in self.connections:
            self.connections.remove(ws)

    async def broadcast(self, msg: dict):
        dead = []
        for ws in self.connections:
            try:
                await ws.send_json(msg)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


# ── File Tailers ──


async def tail_file(path: Path, callback, poll: float = 0.4):
    """Tail a file from end, calling callback(line) for each new line."""
    while not path.exists():
        await asyncio.sleep(1)
    with open(path, "r", encoding="utf-8") as f:
        f.seek(0, 2)  # seek to end
        while True:
            line = f.readline()
            if line:
                line = line.strip()
                if line:
                    await callback(line)
            else:
                await asyncio.sleep(poll)


async def watch_file_content(path: Path, callback, poll: float = 2.0):
    """Watch a file for content changes, calling callback(content) when it changes."""
    last_mtime = 0.0
    while True:
        try:
            if path.exists():
                mtime = os.path.getmtime(path)
                if mtime != last_mtime:
                    last_mtime = mtime
                    content = path.read_text(encoding="utf-8")
                    await callback(content)
        except Exception:
            pass
        await asyncio.sleep(poll)


# ── Callbacks ──


async def on_alert(line: str):
    try:
        alert = json.loads(line)
        await manager.broadcast({"type": "alert", "data": alert})
    except json.JSONDecodeError:
        pass


async def on_honeypot_activity(line: str):
    try:
        event = json.loads(line)
        # Map to agent log line
        evt = event.get("event", {})
        honeypot = event.get("honeypot", "unknown")
        event_type = evt.get("event_type", "UNKNOWN")
        source = evt.get("source_ip", "?")
        payload = evt.get("payload", "")

        # Determine which agent would process this
        if "payload" in str(evt) and payload:
            agent = "Aegis"
            msg = f"Captured {event_type} payload from {source}: {str(payload)[:80]}"
        elif event_type in ("HONEYPOT_START", "HONEYPOT_STOP"):
            agent = "Aegis"
            msg = f"Honeypot {honeypot} {event_type.split('_')[1].lower()}"
        else:
            agent = "Cipher"
            msg = f"Event {event_type} from {source} on {honeypot}"

        ts = datetime.utcnow().isoformat()[11:19]
        log_line = f"[{ts}] [{agent}] {msg}"
        await manager.broadcast({"type": "agent_log", "data": log_line})
    except Exception:
        pass


async def on_honeypot_state(content: str):
    try:
        state = json.loads(content)
        honeypots = state.get("active_honeypots", {})
        # Build grid data: list of {status, image, ip, port}
        grid = []
        for ip, hp in honeypots.items():
            grid.append(
                {
                    "status": "active" if hp.get("is_active") else "idle",
                    "image": hp.get("honeypot_type", "web") + "-honeypot",
                    "ip": hp.get("source_ip"),
                    "port": hp.get("host_port"),
                }
            )
        # Pad to 12 cells
        while len(grid) < 12:
            grid.append({"status": "idle", "image": "web-honeypot", "ip": None, "port": None})
        await manager.broadcast({"type": "honeypots", "data": grid[:12]})
    except Exception:
        pass


async def on_report_change(content: str):
    if content.strip():
        await manager.broadcast({"type": "report", "data": content})


async def on_agent_activity(line: str):
    """Broadcast agent log lines (from agent_activity.log) directly."""
    line = line.strip()
    if line:
        await manager.broadcast({"type": "agent_log", "data": line})


# ── Background Tasks ──


async def start_watchers():
    await asyncio.sleep(1)  # let server boot
    asyncio.create_task(tail_file(ALERTS_LOG, on_alert))
    asyncio.create_task(tail_file(HONEYPOT_ACTIVITY, on_honeypot_activity))
    asyncio.create_task(tail_file(AGENT_ACTIVITY, on_agent_activity))
    asyncio.create_task(watch_file_content(HONEYPOT_STATE, on_honeypot_state))
    asyncio.create_task(watch_file_content(THREAT_REPORT, on_report_change))

    # Periodically send Oracle synthesis log
    async def oracle_ticker():
        msgs = [
            "Synthesizing findings from Cipher and Aegis.",
            "Cross-referencing indicators with threat intelligence feeds.",
            "Confidence assessment in progress.",
            "TTPs mapped to MITRE ATT&CK framework.",
            "Report generation queued.",
        ]
        i = 0
        while True:
            if manager.connections:
                ts = datetime.utcnow().isoformat()[11:19]
                await manager.broadcast({"type": "agent_log", "data": f"[{ts}] [Oracle] {msgs[i % len(msgs)]}"})
                i += 1
            await asyncio.sleep(8)

    asyncio.create_task(oracle_ticker())


@app.on_event("startup")
async def startup():
    asyncio.create_task(start_watchers())


# ── WebSocket Endpoint ──


@app.websocket("/ws/dashboard")
async def dashboard_ws(ws: WebSocket):
    await manager.connect(ws)
    print(f"[WS] Client connected ({len(manager.connections)} total)")

    # Send initial snapshot
    try:
        if THREAT_REPORT.exists():
            report = THREAT_REPORT.read_text(encoding="utf-8")
            if report.strip():
                await ws.send_json({"type": "report", "data": report})
        if HONEYPOT_STATE.exists():
            await on_honeypot_state(HONEYPOT_STATE.read_text(encoding="utf-8"))
    except Exception:
        pass

    try:
        while True:
            await ws.receive_text()  # keep alive
    except WebSocketDisconnect:
        manager.disconnect(ws)
        print(f"[WS] Client disconnected ({len(manager.connections)} total)")


# ── Health Check ──


@app.get("/health")
async def health():
    return {"status": "ok", "clients": len(manager.connections)}


if __name__ == "__main__":
    print("=" * 50)
    print("  ActiveDefenceIR WebSocket Bridge")
    print("  ws://localhost:8765/ws/dashboard")
    print("=" * 50)
    uvicorn.run(app, host="0.0.0.0", port=int(os.environ.get("WS_PORT", 8765)), log_level="warning")
11
