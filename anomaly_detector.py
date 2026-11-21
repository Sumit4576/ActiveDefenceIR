"""
Anomaly Detector — Isolation Forest Wrapper (Module 2)
======================================================
Provides a clean API around Scikit-Learn's IsolationForest for
training, prediction, and model persistence.
"""

from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# Feature columns in the order the model expects
FEATURE_COLS = [
    "request_rate",
    "unique_payloads",
    "payload_entropy",
    "payload_length",
    "is_private_ip",
    "failure_rate",
    "time_delta_mean",
]

# Default directory for persisted model artifacts
MODEL_DIR = Path(__file__).parent / "model"


class AnomalyDetector:
    """Wraps IsolationForest with training, prediction, and persistence."""

    def __init__(
        self,
        contamination: float = 0.15,
        n_estimators: int = 150,
        random_state: int = 42,
    ):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.random_state = random_state

        self._model: Optional[IsolationForest] = None
        self._scaler: Optional[StandardScaler] = None

    # ------------------------------------------------------------------
    # Training
    # ------------------------------------------------------------------

    def train(self, features_df: pd.DataFrame) -> dict:
        """Fit the Isolation Forest on the provided feature DataFrame.

        Returns a dict of training statistics.
        """
        X = features_df[FEATURE_COLS].values

        # Fit scaler
        self._scaler = StandardScaler()
        X_scaled = self._scaler.fit_transform(X)

        # Fit Isolation Forest
        self._model = IsolationForest(
            contamination=self.contamination,
            n_estimators=self.n_estimators,
            random_state=self.random_state,
        )
        self._model.fit(X_scaled)

        # Compute training stats
        predictions = self._model.predict(X_scaled)
        scores = self._model.decision_function(X_scaled)

        n_anomalies = int(np.sum(predictions == -1))
        n_normal = int(np.sum(predictions == 1))

        stats = {
            "total_samples": len(X),
            "anomalies_detected": n_anomalies,
            "normal_detected": n_normal,
            "anomaly_pct": round(n_anomalies / len(X) * 100, 2),
            "score_min": round(float(np.min(scores)), 4),
            "score_max": round(float(np.max(scores)), 4),
            "score_mean": round(float(np.mean(scores)), 4),
        }
        return stats

    # ------------------------------------------------------------------
    # Prediction
    # ------------------------------------------------------------------

    def predict(self, features: dict) -> tuple[bool, float]:
        """Predict whether a single feature vector is anomalous.

        Args:
            features: dict with keys matching FEATURE_COLS.

        Returns:
            (is_anomaly, anomaly_score) where anomaly_score is the raw
            decision function value (more negative = more anomalous).
        """
        if self._model is None or self._scaler is None:
            raise RuntimeError("Model not loaded. Call train() or load() first.")

        x = np.array([[features[col] for col in FEATURE_COLS]])
        x_scaled = self._scaler.transform(x)

        prediction = self._model.predict(x_scaled)[0]  # 1 = normal, -1 = anomaly
        score = self._model.decision_function(x_scaled)[0]

        is_anomaly = prediction == -1
        return bool(is_anomaly), float(score)

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, model_dir: Optional[Path] = None) -> Path:
        """Persist the trained model and scaler to disk."""
        if self._model is None or self._scaler is None:
            raise RuntimeError("No trained model to save.")

        dest = model_dir or MODEL_DIR
        dest.mkdir(parents=True, exist_ok=True)

        model_path = dest / "isolation_forest.pkl"
        scaler_path = dest / "scaler.pkl"

        joblib.dump(self._model, model_path)
        joblib.dump(self._scaler, scaler_path)

        print(f"  Model saved to {model_path}")
        print(f"  Scaler saved to {scaler_path}")
        return model_path

    def load(self, model_dir: Optional[Path] = None) -> None:
        """Load a previously trained model and scaler from disk."""
        src = model_dir or MODEL_DIR

        model_path = src / "isolation_forest.pkl"
        scaler_path = src / "scaler.pkl"

        if not model_path.exists() or not scaler_path.exists():
            raise FileNotFoundError(f"Model artifacts not found in {src}. " "Run train_model.py first.")

        self._model = joblib.load(model_path)
        self._scaler = joblib.load(scaler_path)
        print(f"  Model loaded from {model_path}")

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def classify_attack_type(self, log_entry: dict) -> str:
        """Heuristic classification of the attack type based on payload
        content. This supplements the anomaly score with human-readable
        labels."""
        payload = log_entry.get("payload", {})
        username = str(payload.get("username", "")).lower()
        endpoint = str(log_entry.get("endpoint", "")).lower()
        raw_payload = str(payload).lower()

        # Check for directory traversal patterns
        traversal_indicators = ["..", "%2e%2e", "/etc/", "/windows/", "..\\"]
        if any(ind in endpoint for ind in traversal_indicators):
            return "DIR_TRAVERSAL"

        # Check for XSS patterns
        xss_indicators = ["<script", "javascript:", "onerror", "onload", "alert(", "<img", "<svg"]
        if any(ind in raw_payload for ind in xss_indicators):
            return "XSS"

        # Check for SQL injection patterns
        sqli_indicators = ["'", "--", "or ", "drop ", "select ", "union ", "1=1"]
        if any(indicator in username for indicator in sqli_indicators):
            return "SQL_INJECTION"

        # Check for brute-force pattern (username=admin with varying passwords)
        if username == "admin" and payload.get("password", ""):
            return "BRUTE_FORCE"

        return "UNKNOWN"
