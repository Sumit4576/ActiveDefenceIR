import json

import logger


def test_log_request_writes_json_and_notifies_subscribers():
    received = []
    logger.subscribe(received.append)
    try:
        logger.log_request("10.0.0.5", "POST", "/api/login", {"username": "bob"}, 401)
    finally:
        logger._subscribers.remove(received.append)

    assert len(received) == 1
    entry = received[0]
    assert entry["source_ip"] == "10.0.0.5"
    assert entry["http_method"] == "POST"
    assert entry["status_code"] == 401
    assert entry["timestamp"].endswith("Z")

    for handler in logger.logger.handlers:
        handler.flush()
    last_line = logger.LOG_FILE.read_text(encoding="utf-8").strip().splitlines()[-1]
    assert json.loads(last_line) == entry


def test_subscriber_errors_are_swallowed():
    def boom(_entry):
        raise ValueError("bad subscriber")

    logger.subscribe(boom)
    try:
        logger.log_request("1.2.3.4", "GET", "/", {}, 200)  # must not raise
    finally:
        logger._subscribers.remove(boom)
