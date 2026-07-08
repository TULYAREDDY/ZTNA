"""Lightweight wrapper around the trained sklearn pipeline.

Loads lazily on first use so the API can boot even before training has
been run (in which case predictions degrade gracefully to 0.0).
"""

from __future__ import annotations

import json
import threading
from pathlib import Path
from typing import Any, Optional

import joblib

from app.core.config import get_settings
from app.core.logging import get_logger
from app.models.schemas import AccessFeatures

logger = get_logger("ztna.ml")

_FEATURE_ORDER = [
    "request_rate",
    "ip_change",
    "failed_attempts",
    "device_trust",
    "time_of_day",
    "location_risk",
    "posture_score",
    "session_age_min",
]


class MLService:
    def __init__(self) -> None:
        self._model: Optional[Any] = None
        self._metrics: dict | None = None
        self._lock = threading.Lock()
        self._load_attempted = False

    def is_trained(self) -> bool:
        if self._metrics is None:
            self._load()
        if self._metrics is not None:
            return bool(self._metrics.get("trained"))
        cfg = get_settings()
        return cfg.ml_model_path.exists()

    def ensure_model(self) -> bool:
        """Train the classifier if artifacts are missing."""
        if self.is_trained():
            return True
        cfg = get_settings()
        if not cfg.ml_auto_train:
            return False
        logger.warning("ML model missing — running training pipeline")
        from app.ml.train import main as train_main

        train_main()
        self._model = None
        self._metrics = None
        self._load_attempted = False
        self._load()
        return self.is_trained()

    def _load(self) -> None:
        if self._load_attempted:
            return
        self._load_attempted = True
        cfg = get_settings()
        model_path: Path = cfg.ml_model_path
        metrics_path: Path = cfg.ml_metrics_path
        if not model_path.exists():
            logger.warning("ML model not found at %s — predictions will be 0", model_path)
            return
        with self._lock:
            self._model = joblib.load(model_path)
            if metrics_path.exists():
                self._metrics = json.loads(metrics_path.read_text())
            logger.info("Loaded ML model — accuracy=%.3f",
                        self._metrics.get("accuracy", 0.0) if self._metrics else 0.0)

    def predict_probability(self, f: AccessFeatures) -> float:
        if self._model is None:
            self._load()
        if self._model is None:
            return 0.0
        row = [[
            f.request_rate, f.ip_change, f.failed_attempts, f.device_trust,
            f.time_of_day, f.location_risk, f.posture_score, f.session_age_min,
        ]]
        proba = self._model.predict_proba(row)[0]
        return float(proba[1])

    def metrics(self) -> dict:
        if self._metrics is None:
            self._load()
        return self._metrics or {
            "accuracy": 0.0,
            "precision": 0.0,
            "recall": 0.0,
            "f1": 0.0,
            "feature_importance": [],
            "confusion_matrix": [[0, 0], [0, 0]],
            "trained": False,
        }


ml_service = MLService()
