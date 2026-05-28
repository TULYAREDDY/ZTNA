"""Endpoint: device posture evaluation → session issuance."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter

from app.core.logging import get_logger
from app.models.schemas import EventView, PostureRequest, PostureResponse
from app.services.event_bus import bus
from app.services.posture_validator import evaluate_posture
from app.services.session_store import store

router = APIRouter(tags=["posture"])
logger = get_logger("ztna.posture")


@router.post("/posture", response_model=PostureResponse)
async def posture(req: PostureRequest) -> PostureResponse:
    posture_score, reasons = evaluate_posture(req)

    if posture_score < 50:
        logger.warning("posture rejected user=%s score=%d", req.user_id, posture_score)
        await bus.publish(EventView(
            id=str(uuid.uuid4()),
            ts=datetime.now(timezone.utc),
            kind="POSTURE",
            decision="BLOCK",
            user_id=req.user_id,
            ip_address=req.ip_address,
            risk_score=100 - posture_score,
            reasons=reasons,
        ))
        return PostureResponse(
            decision="BLOCK",
            session_id=None,
            risk_score=100 - posture_score,
            posture_score=posture_score,
            reasons=reasons,
        )

    sess = store.create(
        user_id=req.user_id,
        device_id=req.device_id,
        ip_address=req.ip_address,
        geo_country=req.geo_country,
        os=req.os,
        user_agent=req.user_agent,
        posture_score=posture_score,
    )
    sess.risk_score = 100 - posture_score
    decision = "MONITOR" if posture_score < 75 else "ALLOW"

    logger.info("session issued user=%s sid=%s posture=%d",
                req.user_id, sess.session_id[:8], posture_score)

    await bus.publish(EventView(
        id=str(uuid.uuid4()),
        ts=datetime.now(timezone.utc),
        kind="POSTURE",
        decision=decision,
        session_id=sess.session_id,
        user_id=req.user_id,
        ip_address=req.ip_address,
        risk_score=sess.risk_score,
        reasons=reasons or ["posture_clean"],
    ))

    return PostureResponse(
        decision=decision,
        session_id=sess.session_id,
        risk_score=sess.risk_score,
        posture_score=posture_score,
        reasons=reasons or ["posture_clean"],
    )
