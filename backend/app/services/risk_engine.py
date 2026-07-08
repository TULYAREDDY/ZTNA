"""Hybrid risk engine.

Final risk score is a weighted blend:
    risk = clamp( 0.6 * rule_component + 0.4 * (ml_probability * 100) )

A purely ML-driven decision is dangerous in a security context — it
gives no auditable rationale. A purely rule-driven decision misses
emerging behavioural anomalies. The hybrid model gives us both: every
decision ships with an auditable list of `reasons` plus a
machine-learned probability.
"""

from __future__ import annotations

import time
from datetime import datetime
from typing import Tuple

from app.core.config import get_settings
from app.models.schemas import AccessFeatures
from app.services.geo_service import compute_location_risk, resolve_country
from app.services.session_store import Session


def compute_features(
    session: Session,
    current_ip: str,
    *,
    geo_country: str | None = None,
) -> AccessFeatures:
    now = time.time()
    recent = [t for t in session.request_history if now - t < 60]
    request_rate = len(recent) / 60.0 if recent else 0.0
    ip_change = 0 if session.ip_address == current_ip else 1
    device_trust = round(session.posture_score / 100.0, 3)
    current_geo = resolve_country(
        current_ip,
        session_geo=session.geo_country,
        geo_hint=geo_country,
    )
    location_risk = compute_location_risk(
        session.geo_country,
        current_geo,
        bool(ip_change),
    )
    session_age_min = (now - session.created_at) / 60.0

    return AccessFeatures(
        request_rate=round(request_rate, 3),
        ip_change=ip_change,
        failed_attempts=session.failed_attempts,
        device_trust=device_trust,
        time_of_day=datetime.now().hour,
        location_risk=location_risk,
        posture_score=float(session.posture_score),
        session_age_min=round(session_age_min, 2),
    )


def rule_component(
    features: AccessFeatures,
    session: Session,
    *,
    current_ip: str,
    geo_country: str | None = None,
) -> Tuple[int, list[str]]:
    """Deterministic, auditable risk contribution (0–100)."""
    score = 0
    reasons: list[str] = []
    current_geo = resolve_country(
        current_ip,
        session_geo=session.geo_country,
        geo_hint=geo_country,
    )

    if features.ip_change:
        score += 60
        reasons.append("ip_mismatch_session_hijack_suspected")

    if current_geo != session.geo_country.upper()[:2]:
        score += 15
        reasons.append(f"geo_mismatch:{session.geo_country}->{current_geo}")

    if features.failed_attempts >= 3:
        score += 25
        reasons.append(f"failed_attempts={features.failed_attempts}")

    if features.request_rate > 5:
        score += 20
        reasons.append(f"high_request_rate={features.request_rate:.2f}/s")
    elif features.request_rate > 2:
        score += 8
        reasons.append("elevated_request_rate")

    if features.device_trust < 0.5:
        score += 20
        reasons.append("low_device_trust")
    elif features.device_trust < 0.7:
        score += 8

    if features.time_of_day < 6 or features.time_of_day > 22:
        score += 10
        reasons.append("after_hours_access")

    if features.session_age_min > 360:  # > 6h
        score += 5
        reasons.append("long_running_session")

    return min(100, score), reasons


def decide(rule_score: int, ml_prob: float) -> tuple[int, str]:
    """Blend the rule and ML components.

    `0.6·rule + 0.4·100·p_ml` weights auditable evidence higher than the
    opaque ML probability. Additionally, when **both** signals agree
    (rule ≥ 60 AND p_ml ≥ 0.5) we apply a small confluence bonus — two
    independent detection channels pointing the same way is much
    stronger than either alone.
    """
    cfg = get_settings()
    blended = 0.6 * rule_score + 0.4 * (ml_prob * 100)
    if rule_score >= 60 and ml_prob >= 0.5:
        blended += 6
    final = max(0, min(100, int(round(blended))))
    if final >= cfg.risk_block_threshold:
        return final, "BLOCK"
    if final >= cfg.risk_monitor_threshold:
        return final, "MONITOR"
    return final, "ALLOW"
