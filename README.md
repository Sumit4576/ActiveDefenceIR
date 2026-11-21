# ActiveDefenseIR

An active-defense incident-response lab. ActiveDefenseIR simulates a target web service, detects malicious traffic with an ML anomaly model, steers attackers into containerized honeypots, and uses AI agents to write a threat-intelligence report. A React dashboard streams all of it live.

## Architecture

```
 traffic simulator ──► Mock target (main.py :8000) ──► traffic.log
   (log_generator.py)                                      │
                                                           ▼
                                  Detection engine (detection_engine.py)
                                  Isolation Forest + feature_extractor.py
                                                           │ alerts.log
                                                           ▼
                                  Deception orchestrator ──► Docker honeypots
                                  (deception_orchestrator.py)   (honeypots/web_honeypot, Cowrie SSH)
                                                           │ honeypot_activity.log
                                                           ▼
                                  AI agents Cipher / Aegis / Oracle (ai_agents.py, Gemini)
                                                           │ threat_report.md
                                                           ▼
            WebSocket bridge (ws_server.py :8765) ──► React dashboard (frontend/ :3001)
```

| Module | Purpose | Entry point |
|---|---|---|
| 1. Target environment | Mock login API plus benign and malicious traffic generator | `main.py`, `log_generator.py`, `run_module1.py` |
| 2. Detection engineering | Feature extraction and Isolation Forest anomaly detection | `train_model.py`, `detection_engine.py`, `run_module2.py` |
| 3. Active defense | Deploys a honeypot container per attacker and aggregates its logs | `deception_orchestrator.py`, `honeypot_monitor.py`, `run_module3.py` |
| 4. AI investigation | Multi-agent analysis and a Markdown threat report | `ai_agents.py`, `run_module4.py` |
| Dashboard | Live alerts, honeypot grid, agent log, report | `ws_server.py`, `frontend/` |

## Quick start (local)

**Requirements:** Python 3.14, Node.js 22 LTS (20.19+ also works), and Docker (needed only for Module 3 honeypots).

```bash
# 1. Backend
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cp .env.example .env               # then set GEMINI_API_KEY (optional)

# 2. Train the anomaly model (model files are not committed)
python train_model.py --synthesize 500

# 3. Start the services (separate terminals)
python main.py                     # mock target   -> http://localhost:8000
python ws_server.py                # WS bridge     -> ws://localhost:8765/ws/dashboard

# 4. Frontend
cd frontend
npm install
npm run dev                        # dashboard     -> http://localhost:3001
```

When the WebSocket bridge is unreachable, the dashboard falls back to built-in mock data.

To run the full attack pipeline, use `python run_module3.py` (requires Docker), then `python run_module4.py --investigate-only` to generate `threat_report.md`.

## Docker deployment

`docker-compose.yml` is at the repository root.

```bash
docker compose up -d --build
```

| Service | URL |
|---|---|
| `backend` (mock target) | http://localhost:8000 |
| `ws-bridge` | ws://localhost:8765/ws/dashboard, health at http://localhost:8765/health |
| `frontend` (nginx serving the Vite build) | http://localhost:3001 |

The dashboard's WebSocket URL is set at build time from `VITE_WS_URL`. Stop the stack with `docker compose down`.

## Configuration

All settings are environment variables. See [.env.example](.env.example).

| Variable | Default | Used by |
|---|---|---|
| `GEMINI_API_KEY` | *(empty: falls back to a programmatic report)* | `ai_agents.py` |
| `GEMINI_MODEL` | `gemini-3.5-flash-lite` | `ai_agents.py` |
| `TARGET_PORT` | `8000` | `main.py` |
| `TRAFFIC_LOG_FILE` | `./traffic.log` | `logger.py` |
| `WS_PORT` | `8765` | `ws_server.py` |
| `VITE_WS_URL` | `ws://localhost:8765/ws/dashboard` | frontend build |

## Tests and linting

```bash
pip install -r requirements-dev.txt
pytest                 # unit tests in tests/
flake8 .               # lint
black --check .        # formatting (run `black .` to fix)

cd frontend
npm run lint           # oxlint
npm run build          # type-check and production build
```

GitHub Actions ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs all of these, then builds the Docker images and smoke-tests the stack. Publishing images to GHCR is turned off by default. To turn it on, set the repository variable `PUBLISH_IMAGES=true`.

## Security notice

This project deliberately runs vulnerable-looking honeypot services. Run it only on networks you control and never expose the honeypots to the internet without isolation. Keep API keys in `.env`, which git ignores.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

## License

Released under the [MIT License](LICENSE).
