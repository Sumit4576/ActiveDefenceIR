import json
import threading
import urllib.error
import urllib.request
from http.server import HTTPServer

import pytest

from main import MockTargetHandler


@pytest.fixture()
def server():
    httpd = HTTPServer(("127.0.0.1", 0), MockTargetHandler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{httpd.server_address[1]}"
    httpd.shutdown()
    httpd.server_close()


def _request(url, data=None):
    body = json.dumps(data).encode() if data is not None else None
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as err:
        return err.code, json.loads(err.read())


def test_root_returns_200(server):
    status, body = _request(server + "/")
    assert status == 200
    assert body == {"status": "Target Environment Running"}


def test_login_returns_401(server):
    status, body = _request(server + "/api/login", {"username": "admin", "password": "x"})
    assert status == 401
    assert body["message"] == "Invalid credentials"


def test_unknown_paths_return_404(server):
    assert _request(server + "/nope")[0] == 404
    assert _request(server + "/nope", {"a": 1})[0] == 404
