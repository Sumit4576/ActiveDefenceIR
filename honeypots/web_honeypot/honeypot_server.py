"""
Web Honeypot Server (Module 3)
===============================
A deliberately vulnerable-looking web application designed to lure and
log SQL injection attackers. Presents fake login and admin pages, responds
to injection attempts with realistic-looking "database errors" to keep
the attacker engaged, and logs every interaction as JSON lines.

Runs inside a Docker container. Logs are written to a volume-mounted
path so the host can collect them for Module 4 AI analysis.
"""

import json
import os
import re
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlparse

# Log file path — mounted as a Docker volume to the host
LOG_DIR = Path(os.environ.get("HONEYPOT_LOG_DIR", "/var/log/honeypot"))
LOG_FILE = LOG_DIR / "activity.log"
HONEYPOT_ID = os.environ.get("HONEYPOT_ID", "web-unknown")

# Ensure log directory exists
LOG_DIR.mkdir(parents=True, exist_ok=True)


# ======================================================================
# SQL injection detection patterns (for realistic responses)
# ======================================================================

SQLI_PATTERNS = [
    r"('|\"|;|--)",
    r"(\bOR\b|\bAND\b)\s+\d+\s*=\s*\d+",
    r"\bUNION\b\s+\bSELECT\b",
    r"\bDROP\b\s+\bTABLE\b",
    r"\bINSERT\b\s+\bINTO\b",
    r"\bDELETE\b\s+\bFROM\b",
    r"\bSELECT\b\s+.*\bFROM\b",
    r"1\s*=\s*1",
    r"/\*.*\*/",
]


def _is_sqli(text: str) -> bool:
    """Check if text contains SQL injection patterns."""
    for pattern in SQLI_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    return False


def _log_activity(event_type: str, details: dict) -> None:
    """Append a JSON log entry to the activity log."""
    entry = {
        "honeypot_id": HONEYPOT_ID,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "event_type": event_type,
        **details,
    }
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


# ======================================================================
# Fake HTML pages (designed to look like a real vulnerable app)
# ======================================================================

LOGIN_PAGE = """<!DOCTYPE html>
<html>
<head><title>SecureCorp Internal Portal</title></head>
<body style="font-family:Arial; background:#1a1a2e; color:#eee; display:flex; justify-content:center; align-items:center; height:100vh; margin:0;">
<div style="background:#16213e; padding:40px; border-radius:10px; box-shadow:0 0 20px rgba(0,0,0,0.5); width:350px;">
  <h2 style="color:#e94560; text-align:center;">SecureCorp Portal</h2>
  <form method="POST" action="/api/login">
    <label>Username:</label><br>
    <input type="text" name="username" style="width:100%; padding:8px; margin:8px 0; box-sizing:border-box; background:#0f3460; color:#eee; border:1px solid #e94560;"><br>
    <label>Password:</label><br>
    <input type="password" name="password" style="width:100%; padding:8px; margin:8px 0; box-sizing:border-box; background:#0f3460; color:#eee; border:1px solid #e94560;"><br><br>
    <button type="submit" style="width:100%; padding:10px; background:#e94560; color:white; border:none; cursor:pointer; border-radius:5px;">Login</button>
  </form>
  <p style="font-size:11px; color:#888; margin-top:20px;">SecureCorp v3.2.1 | Internal Use Only</p>
</div>
</body>
</html>"""

ADMIN_PAGE = """<!DOCTYPE html>
<html>
<head><title>Admin Dashboard - SecureCorp</title></head>
<body style="font-family:Arial; background:#1a1a2e; color:#eee; padding:40px;">
  <h1 style="color:#e94560;">Admin Dashboard</h1>
  <p>Welcome, admin. You have access to the following:</p>
  <ul>
    <li><a href="/admin/users" style="color:#e94560;">User Management</a></li>
    <li><a href="/admin/database" style="color:#e94560;">Database Console</a></li>
    <li><a href="/admin/logs" style="color:#e94560;">System Logs</a></li>
    <li><a href="/admin/config" style="color:#e94560;">Server Configuration</a></li>
  </ul>
  <p style="font-size:11px; color:#888;">Server: PROD-DB-01 | MySQL 5.7.42</p>
</body>
</html>"""

DATABASE_ERROR_TEMPLATE = """<!DOCTYPE html>
<html>
<head><title>Error - SecureCorp</title></head>
<body style="font-family:monospace; background:#1a1a2e; color:#eee; padding:40px;">
  <h2 style="color:#e94560;">Database Error</h2>
  <div style="background:#0f3460; padding:20px; border-left:4px solid #e94560; margin:20px 0;">
    <p><strong>MySQL Error 1064:</strong> You have an error in your SQL syntax;</p>
    <p>check the manual that corresponds to your MySQL server version for the right syntax to use near</p>
    <p style="color:#ff6b6b;">'{input_snippet}'</p>
    <p>at line 1</p>
  </div>
  <p style="font-size:11px; color:#888;">Query: SELECT * FROM users WHERE username='{username}' AND password='{password}'</p>
  <p style="font-size:11px; color:#888;">Server: PROD-DB-01 | MySQL 5.7.42 | SecureCorp v3.2.1</p>
</body>
</html>"""

FAKE_USERS_PAGE = """<!DOCTYPE html>
<html>
<head><title>User Management - SecureCorp</title></head>
<body style="font-family:Arial; background:#1a1a2e; color:#eee; padding:40px;">
  <h2 style="color:#e94560;">User Management</h2>
  <table style="width:100%; border-collapse:collapse; margin-top:20px;">
    <tr style="background:#16213e;"><th style="padding:10px; border:1px solid #333;">ID</th><th style="padding:10px; border:1px solid #333;">Username</th><th style="padding:10px; border:1px solid #333;">Role</th><th style="padding:10px; border:1px solid #333;">Email</th></tr>
    <tr><td style="padding:8px; border:1px solid #333;">1</td><td style="padding:8px; border:1px solid #333;">admin</td><td style="padding:8px; border:1px solid #333;">Administrator</td><td style="padding:8px; border:1px solid #333;">admin@securecorp.internal</td></tr>
    <tr><td style="padding:8px; border:1px solid #333;">2</td><td style="padding:8px; border:1px solid #333;">jsmith</td><td style="padding:8px; border:1px solid #333;">Manager</td><td style="padding:8px; border:1px solid #333;">j.smith@securecorp.internal</td></tr>
    <tr><td style="padding:8px; border:1px solid #333;">3</td><td style="padding:8px; border:1px solid #333;">dbadmin</td><td style="padding:8px; border:1px solid #333;">DBA</td><td style="padding:8px; border:1px solid #333;">db.admin@securecorp.internal</td></tr>
  </table>
  <p style="font-size:11px; color:#888; margin-top:20px;">Showing 3 of 3 users</p>
</body>
</html>"""


# ======================================================================
# HTTP Request Handler
# ======================================================================


class HoneypotHandler(BaseHTTPRequestHandler):
    """HTTP handler for the web honeypot."""

    def _send_html(self, html: str, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.end_headers()
        self.wfile.write(html.encode("utf-8"))

    def _send_json(self, data: dict, status: int = 200) -> None:
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Server", "Apache/2.4.41 (Ubuntu)")
        self.end_headers()
        self.wfile.write(json.dumps(data).encode("utf-8"))

    def do_GET(self):
        client_ip = self.client_address[0]
        path = urlparse(self.path).path

        _log_activity(
            "HTTP_GET",
            {
                "source_ip": client_ip,
                "path": self.path,
                "headers": dict(self.headers),
            },
        )

        if path == "/" or path == "/login":
            self._send_html(LOGIN_PAGE)
        elif path == "/admin" or path == "/admin/":
            self._send_html(ADMIN_PAGE)
        elif path == "/admin/users":
            self._send_html(FAKE_USERS_PAGE)
        elif path == "/admin/database":
            self._send_html(
                '<html><body style="font-family:monospace; background:#1a1a2e; color:#eee; padding:40px;">'
                '<h2 style="color:#e94560;">Database Console</h2>'
                '<form method="POST" action="/admin/database/query">'
                '<textarea name="query" style="width:100%; height:150px; background:#0f3460; color:#eee; border:1px solid #e94560; padding:10px;" '
                'placeholder="Enter SQL query..."></textarea><br><br>'
                '<button type="submit" style="padding:10px 30px; background:#e94560; color:white; border:none; cursor:pointer;">Execute Query</button>'
                "</form></body></html>"
            )
        elif path.startswith("/admin/"):
            self._send_html(
                '<html><body style="background:#1a1a2e; color:#eee; padding:40px;">'
                '<h2 style="color:#e94560;">Access Denied</h2>'
                "<p>You need elevated privileges for this section.</p>"
                "</body></html>",
                status=403,
            )
        else:
            self._send_html(
                '<html><body style="background:#1a1a2e; color:#eee; padding:40px;">'
                "<h2>404 Not Found</h2></body></html>",
                status=404,
            )

    def do_POST(self):
        client_ip = self.client_address[0]
        path = urlparse(self.path).path

        # Read request body
        content_length = int(self.headers.get("Content-Length", 0))
        body = ""
        payload = {}
        if content_length > 0:
            body = self.rfile.read(content_length).decode("utf-8", errors="replace")
            try:
                payload = json.loads(body)
            except json.JSONDecodeError:
                # Try URL-encoded form data
                payload = {k: v[0] if len(v) == 1 else v for k, v in parse_qs(body).items()}

        # Detect injection attempts
        injection_detected = False
        for value in payload.values():
            if isinstance(value, str) and _is_sqli(value):
                injection_detected = True
                break

        _log_activity(
            "HTTP_POST",
            {
                "source_ip": client_ip,
                "path": self.path,
                "payload": payload,
                "raw_body": body[:500],
                "injection_detected": injection_detected,
                "headers": dict(self.headers),
            },
        )

        if path == "/api/login":
            username = str(payload.get("username", ""))
            password = str(payload.get("password", ""))

            if injection_detected:
                # Return a realistic database error to keep attacker engaged
                _log_activity(
                    "SQLI_ATTEMPT",
                    {
                        "source_ip": client_ip,
                        "payload": payload,
                        "severity": "CRITICAL",
                    },
                )
                error_html = DATABASE_ERROR_TEMPLATE.format(
                    input_snippet=username[:50],
                    username=username[:80],
                    password=password[:30],
                )
                self._send_html(error_html, status=500)
            else:
                self._send_json(
                    {"status": "error", "message": "Invalid credentials"},
                    status=401,
                )

        elif path == "/admin/database/query":
            query = str(payload.get("query", ""))
            _log_activity(
                "DB_QUERY_ATTEMPT",
                {
                    "source_ip": client_ip,
                    "query": query,
                    "injection_detected": _is_sqli(query),
                    "severity": "CRITICAL" if _is_sqli(query) else "INFO",
                },
            )

            if _is_sqli(query):
                # Return fake data to keep them engaged
                self._send_html(
                    '<html><body style="font-family:monospace; background:#1a1a2e; color:#eee; padding:40px;">'
                    '<h2 style="color:#e94560;">Query Result</h2>'
                    '<div style="background:#0f3460; padding:20px; border:1px solid #333;">'
                    '<p style="color:#ff6b6b;">Warning: Query execution partially failed.</p>'
                    '<table style="border-collapse:collapse; margin-top:10px;">'
                    '<tr style="background:#16213e;"><th style="padding:8px; border:1px solid #333;">id</th>'
                    '<th style="padding:8px; border:1px solid #333;">username</th>'
                    '<th style="padding:8px; border:1px solid #333;">password_hash</th></tr>'
                    '<tr><td style="padding:8px; border:1px solid #333;">1</td>'
                    '<td style="padding:8px; border:1px solid #333;">admin</td>'
                    '<td style="padding:8px; border:1px solid #333;">$2b$12$fakehashvalue...</td></tr>'
                    "</table>"
                    '<p style="font-size:11px; color:#888;">1 row returned (0.023 sec)</p>'
                    "</div></body></html>",
                    status=200,
                )
            else:
                self._send_json({"status": "error", "message": "Permission denied"}, status=403)
        else:
            self._send_json({"status": "error", "message": "Not found"}, status=404)

    def log_message(self, format, *args):
        """Suppress default HTTP server logging — we do our own."""
        pass


# ======================================================================
# Main
# ======================================================================


def main():
    port = int(os.environ.get("HONEYPOT_PORT", 8080))
    server = HTTPServer(("0.0.0.0", port), HoneypotHandler)
    print(f"[WebHoneypot] {HONEYPOT_ID} listening on port {port}")
    _log_activity("HONEYPOT_START", {"port": port})

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        _log_activity("HONEYPOT_STOP", {})
        print(f"[WebHoneypot] {HONEYPOT_ID} shutting down.")
        server.shutdown()


if __name__ == "__main__":
    main()
