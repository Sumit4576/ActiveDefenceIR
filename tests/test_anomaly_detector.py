import numpy as np
import pandas as pd
import pytest

from anomaly_detector import FEATURE_COLS, AnomalyDetector


@pytest.fixture()
def trained():
    rng = np.random.default_rng(0)
    df = pd.DataFrame(rng.normal(1.0, 0.1, size=(200, len(FEATURE_COLS))), columns=FEATURE_COLS)
    det = AnomalyDetector(contamination=0.05, n_estimators=50)
    stats = det.train(df)
    return det, stats


def test_train_stats(trained):
    _, stats = trained
    assert stats["total_samples"] == 200
    assert stats["anomalies_detected"] + stats["normal_detected"] == 200


def test_predict_flags_outlier(trained):
    det, _ = trained
    normal = {c: 1.0 for c in FEATURE_COLS}
    outlier = {c: 50.0 for c in FEATURE_COLS}
    assert det.predict(normal)[0] is False
    is_anomaly, score = det.predict(outlier)
    assert is_anomaly is True
    assert score < 0


def test_predict_without_model_raises():
    with pytest.raises(RuntimeError):
        AnomalyDetector().predict({c: 0.0 for c in FEATURE_COLS})


def test_save_and_load_roundtrip(trained, tmp_path):
    det, _ = trained
    det.save(tmp_path)
    loaded = AnomalyDetector()
    loaded.load(tmp_path)
    sample = {c: 1.0 for c in FEATURE_COLS}
    assert loaded.predict(sample) == det.predict(sample)


@pytest.mark.parametrize(
    "entry,expected",
    [
        ({"endpoint": "/../../etc/passwd", "payload": {}}, "DIR_TRAVERSAL"),
        ({"endpoint": "/api/login", "payload": {"username": "<script>alert(1)</script>"}}, "XSS"),
        ({"endpoint": "/api/login", "payload": {"username": "' OR 1=1 --"}}, "SQL_INJECTION"),
        ({"endpoint": "/api/login", "payload": {"username": "admin", "password": "123"}}, "BRUTE_FORCE"),
        ({"endpoint": "/api/login", "payload": {"username": "alice"}}, "UNKNOWN"),
    ],
)
def test_classify_attack_type(entry, expected):
    assert AnomalyDetector().classify_attack_type(entry) == expected
