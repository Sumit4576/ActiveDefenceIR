import json

import pytest

from feature_extractor import FeatureExtractor, load_log_file


def _entry(ts, ip="8.8.8.8", username="admin", status=401):
    return {
        "timestamp": ts,
        "source_ip": ip,
        "http_method": "POST",
        "endpoint": "/api/login",
        "payload": {"username": username, "password": "pw"},
        "status_code": status,
    }


def test_single_entry_features():
    f = FeatureExtractor().extract(_entry("2026-01-01T00:00:00Z"))
    assert f["request_rate"] == 1.0
    assert f["is_private_ip"] == 0.0
    assert f["failure_rate"] == 1.0
    assert f["time_delta_mean"] == 0.0
    assert f["payload_length"] == len("admin") + len("pw")


def test_sliding_window_and_time_delta():
    fx = FeatureExtractor(window_seconds=60)
    fx.extract(_entry("2026-01-01T00:00:00Z", status=200))
    f = fx.extract(_entry("2026-01-01T00:00:10Z", username="root"))
    assert f["request_rate"] == 2.0
    assert f["unique_payloads"] == 2.0
    assert f["failure_rate"] == 0.5
    assert f["time_delta_mean"] == pytest.approx(10.0)

    # An entry outside the window prunes the older ones
    f = fx.extract(_entry("2026-01-01T00:05:00Z"))
    assert f["request_rate"] == 1.0


def test_private_ip_and_entropy():
    assert FeatureExtractor._is_private_ip("192.168.1.10") == 1.0
    assert FeatureExtractor._is_private_ip("not-an-ip") == 0.0
    assert FeatureExtractor._shannon_entropy("") == 0.0
    assert FeatureExtractor._shannon_entropy("aaaa") == 0.0
    assert FeatureExtractor._shannon_entropy("ab") == pytest.approx(1.0)


def test_extract_batch_returns_dataframe():
    df = FeatureExtractor().extract_batch([_entry("2026-01-01T00:00:00Z"), _entry("2026-01-01T00:00:01Z")])
    assert len(df) == 2
    assert "request_rate" in df.columns


def test_load_log_file_skips_bad_lines(tmp_path):
    p = tmp_path / "traffic.log"
    p.write_text(json.dumps(_entry("2026-01-01T00:00:00Z")) + "\nnot json\n\n", encoding="utf-8")
    assert len(load_log_file(p)) == 1
