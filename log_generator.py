import time
import random
import urllib.request
import urllib.error
import json
import threading

TARGET_URL = "http://localhost:8000/api/login"
HEALTH_URL = "http://localhost:8000/"

BENIGN_IPS = ["192.168.1.10", "192.168.1.15", "10.0.0.5"]
MALICIOUS_IPS = ["203.0.113.45", "198.51.100.22"]

SQLI_PAYLOADS = ["' OR '1'='1", "admin' --", "'; DROP TABLE users--"]

XSS_PAYLOADS = [
    '<script>alert("XSS")</script>',
    "<img src=x onerror=alert(1)>",
    "<svg onload=alert(document.cookie)>",
    "javascript:alert(1)",
]

DIR_TRAVERSAL_PATHS = [
    "/../../../etc/passwd",
    "/..%2f..%2f..%2fetc%2fpasswd",
    "/../../../windows/system32/config/sam",
    "/....//....//etc/shadow",
]


def make_request(url, payload=None, headers=None):
    if headers is None:
        headers = {}
    data = None
    if payload:
        data = json.dumps(payload).encode("utf-8")
        headers["Content-Type"] = "application/json"

    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        urllib.request.urlopen(req)
        return True
    except urllib.error.HTTPError:
        return True  # It connected, just got a non-200 response (expected for honeypot)
    except Exception:
        return False


def wait_for_server():
    print("Generator: Waiting for server to start...")
    while True:
        if make_request(HEALTH_URL):
            print("Generator: Server is up! Starting traffic generation...")
            break
        time.sleep(1)


def send_benign_traffic():
    while True:
        ip = random.choice(BENIGN_IPS)
        headers = {"X-Forwarded-For": ip}
        payload = {"username": "user", "password": "password123"}
        make_request(TARGET_URL, payload, headers)
        time.sleep(random.uniform(1.0, 3.0))


def send_malicious_traffic():
    while True:
        time.sleep(random.uniform(5.0, 15.0))
        attack_type = random.choice(["brute_force", "sqli", "xss", "dir_traversal"])
        ip = random.choice(MALICIOUS_IPS)
        headers = {"X-Forwarded-For": ip}

        print(f"Generator: Launching {attack_type} attack from {ip}!")

        if attack_type == "brute_force":
            for _ in range(20):
                payload = {"username": "admin", "password": f"pass{random.randint(100, 999)}"}
                make_request(TARGET_URL, payload, headers)
                time.sleep(0.05)

        elif attack_type == "sqli":
            for payload_str in SQLI_PAYLOADS:
                payload = {"username": payload_str, "password": "any"}
                make_request(TARGET_URL, payload, headers)
                time.sleep(0.5)

        elif attack_type == "xss":
            for payload_str in XSS_PAYLOADS:
                payload = {"username": payload_str, "password": "test"}
                make_request(TARGET_URL, payload, headers)
                time.sleep(0.3)

        elif attack_type == "dir_traversal":
            base_url = "http://localhost:8000"
            for path in DIR_TRAVERSAL_PATHS:
                make_request(base_url + path, headers=headers)
                time.sleep(0.4)


if __name__ == "__main__":
    wait_for_server()
    t1 = threading.Thread(target=send_benign_traffic, daemon=True)
    t2 = threading.Thread(target=send_malicious_traffic, daemon=True)
    t1.start()
    t2.start()
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("Generator: Stopping traffic.")
