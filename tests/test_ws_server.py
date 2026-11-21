from fastapi.testclient import TestClient

import ws_server


def test_health_endpoint():
    with TestClient(ws_server.app) as client:
        resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"
