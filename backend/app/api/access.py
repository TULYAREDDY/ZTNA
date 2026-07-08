"""Endpoint: per-request access decision (called by the proxy / PEP)."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter

from app.core.logging import get_logger
from app.models.schemas import AccessRequest, AccessResponse, EventView
from app.services.event_bus import bus
from app.services.ml_service import ml_service
from app.services.risk_engine import compute_features, decide, rule_component
from app.services.session_store import store

router = APIRouter(tags=["access"])
logger = get_logger("ztna.access")


@router.post("/access", response_model=AccessResponse)
async def access(req: AccessRequest) -> AccessResponse:
    sess = store.get(req.session_id)

    if sess is None:
        await bus.publish(EventView(
            id=str(uuid.uuid4()),
            ts=datetime.now(timezone.utc),
            kind="ACCESS",
            decision="BLOCK",
            ip_address=req.ip_address,
            target_service=req.target_service,
            risk_score=100,
            reasons=["unknown_session"],
        ))
        return AccessResponse(
            decision="BLOCK",
            risk_score=100,
            ml_probability=1.0,
            rule_score=100,
            features=_zero_features(),
            reasons=["unknown_session"],
            session_status="UNKNOWN",
        )

    if sess.status != "ACTIVE":
        await bus.publish(EventView(
            id=str(uuid.uuid4()),
            ts=datetime.now(timezone.utc),
            kind="ACCESS",
            decision="BLOCK",
            session_id=sess.session_id,
            user_id=sess.user_id,
            ip_address=req.ip_address,
            target_service=req.target_service,
            risk_score=100,
            reasons=[f"session_{sess.status.lower()}"],
        ))
        return AccessResponse(
            decision="BLOCK",
            risk_score=100,
            ml_probability=1.0,
            rule_score=100,
            features=_zero_features(),
            reasons=[f"session_{sess.status.lower()}"],
            session_status=sess.status,
        )

    features = compute_features(sess, req.ip_address, geo_country=req.geo_country)
    rule_score, rule_reasons = rule_component(
        features,
        sess,
        current_ip=req.ip_address,
        geo_country=req.geo_country,
    )
    ml_prob = ml_service.predict_probability(features)
    if not ml_service.is_trained():
        rule_reasons.append("ml_model_inactive")
    final_score, decision = decide(rule_score, ml_prob)

    if ml_prob >= 0.7:
        rule_reasons.append(f"ml_anomaly_p={ml_prob:.2f}")

    sess.risk_score = final_score
    store.record_request(sess, decision)

    logger.info(
        "access sid=%s ip=%s -> %s risk=%d (rule=%d ml=%.2f) target=%s",
        sess.session_id[:8], req.ip_address, decision, final_score, rule_score, ml_prob,
        req.target_service or "-",
    )

    await bus.publish(EventView(
        id=str(uuid.uuid4()),
        ts=datetime.now(timezone.utc),
        kind="ACCESS",
        decision=decision,
        session_id=sess.session_id,
        user_id=sess.user_id,
        ip_address=req.ip_address,
        target_service=req.target_service,
        risk_score=final_score,
        reasons=rule_reasons or ["clean_request"],
    ))

    return AccessResponse(
        decision=decision,
        risk_score=final_score,
        ml_probability=round(ml_prob, 4),
        rule_score=rule_score,
        features=features,
        reasons=rule_reasons or ["clean_request"],
        session_status=sess.status,
    )


def _zero_features():
    from app.models.schemas import AccessFeatures
    return AccessFeatures(
        request_rate=0.0, ip_change=0, failed_attempts=0, device_trust=0.0,
        time_of_day=0, location_risk=0.0, posture_score=0.0, session_age_min=0.0,
    )
