import json
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from logger import log_request


class MockTargetHandler(BaseHTTPRequestHandler):
    def _set_headers(self, status=200):
        self.send_response(status)
        self.send_header("Content-type", "application/json")
        self.end_headers()

    def _log_and_respond(self, payload, status_code=200, response_data=None):
        if response_data is None:
            response_data = {"status": "error", "message": "Invalid credentials"}

        # Use X-Forwarded-For if available to simulate proxy/load balancer
        source_ip = self.headers.get("X-Forwarded-For", self.client_address[0])

        # Log it using our structured logger
        log_request(
            source_ip=source_ip, http_method=self.command, endpoint=self.path, payload=payload, status_code=status_code
        )

        self._set_headers(status_code)
        self.wfile.write(json.dumps(response_data).encode("utf-8"))

    def do_GET(self):
        if self.path == "/":
            self._log_and_respond({}, 200, {"status": "Target Environment Running"})
        else:
            self._log_and_respond({}, 404, {"status": "Not found"})

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        payload = {}
        if content_length > 0:
            post_data = self.rfile.read(content_length)
            try:
                payload = json.loads(post_data.decode("utf-8"))
            except Exception:
                payload = {"raw_body": post_data.decode("utf-8")}

        if self.path == "/api/login":
            self._log_and_respond(payload, 401, {"status": "error", "message": "Invalid credentials"})
        else:
            self._log_and_respond(payload, 404, {"status": "Not found"})

    # Suppress default HTTP server logging to stdout to keep terminal clean
    def log_message(self, format, *args):
        pass


def run(server_class=HTTPServer, handler_class=MockTargetHandler, port=8000):
    server_address = ("0.0.0.0", port)
    httpd = server_class(server_address, handler_class)
    print(f"Starting mock target server on port {port}...")
    httpd.serve_forever()


if __name__ == "__main__":
    run(port=int(os.environ.get("TARGET_PORT", 8000)))
