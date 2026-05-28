"""Feature engineering used by both the training pipeline and the runtime
inference service.

`engineer` MUST be importable from a stable module path because joblib
serialises a reference to it inside the calibrated pipeline. Anything
else (training-script main, lambda, nested function) breaks
`joblib.load` from a fresh process.
"""

from __future__ import annotations

import numpy as np

# Order must match the schema's AccessFeatures and dataset columns.
RAW_FEATURES = [
    "request_rate",
    "ip_change",
    "failed_attempts",
    "device_trust",
    "time_of_day",
    "location_risk",
    "posture_score",
    "session_age_min",
]


def engineer(X: np.ndarray) -> np.ndarray:
    """Project the raw 8-tuple into a 9-column feature vector.

    Operations:
      - log1p(`request_rate`) — heavy-tailed, lognormal at the source.
      - cyclical encoding of `time_of_day` as (sin, cos), so hour 23 and
        hour 0 are neighbours instead of 23 units apart.

    Returned column order (used by permutation importance and the
    standard scaler that follows in the pipeline):
      [log_request_rate, ip_change, failed_attempts, device_trust,
       tod_sin, tod_cos, location_risk, posture_score, session_age_min]
    """
    X = np.asarray(X, dtype=float)
    request_rate = np.log1p(X[:, 0])
    ip_change = X[:, 1]
    failed_attempts = X[:, 2]
    device_trust = X[:, 3]
    hour = X[:, 4]
    tod_sin = np.sin(2 * np.pi * hour / 24.0)
    tod_cos = np.cos(2 * np.pi * hour / 24.0)
    location_risk = X[:, 5]
    posture_score = X[:, 6]
    session_age_min = X[:, 7]
    return np.column_stack([
        request_rate,
        ip_change,
        failed_attempts,
        device_trust,
        tod_sin,
        tod_cos,
        location_risk,
        posture_score,
        session_age_min,
    ])
