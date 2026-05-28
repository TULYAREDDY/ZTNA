"""Session listing and revocation endpoints."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException

from app.core.logging import get_logger
from app.models.schemas import EventView, RevokeRequest, SessionView
from app.services.event_bus import bus
from app.services.session_store import store

router = APIRouter(tags=["sessions"])
logger = get_logger("ztna.sessions")


def _to_view(s) -> SessionView:
    return SessionView(
        session_id=s.session_id,
        user_id=s.user_id,
        device_id=s.device_id,
        ip_address=s.ip_address,
        geo_country=s.geo_country,
        os=s.os,
        created_at=datetime.fromtimestamp(s.created_at, tz=timezone.utc),
        last_seen_at=datetime.fromtimestamp(s.last_seen_at, tz=timezone.utc),
        risk_score=s.risk_score,
        posture_score=s.posture_score,
        request_count=s.request_count,
        block_count=s.block_count,
        monitor_count=s.monitor_count,
        status=s.status,
    )


@router.get("/sessions", response_model=list[SessionView])
async def list_sessions(active_only: bool = False) -> list[SessionView]:
    sessions = store.all_active() if active_only else store.all()
    sessions.sort(key=lambda s: s.last_seen_at, reverse=True)
    return [_to_view(s) for s in sessions]


@router.get("/sessions/{session_id}", response_model=SessionView)
async def get_session(session_id: str) -> SessionView:
    sess = store.get(session_id)
    if not sess:
        raise HTTPException(404, "session not found")
    return _to_view(sess)


@router.post("/sessions/revoke")
async def revoke(req: RevokeRequest) -> dict:
    ok = store.revoke(req.session_id, req.reason)
    if not ok:
        raise HTTPException(404, "session not active")
    sess = store.get(req.session_id)
    logger.warning("session revoked sid=%s reason=%s", req.session_id[:8], req.reason)
    await bus.publish(EventView(
        id=str(uuid.uuid4()),
        ts=datetime.now(timezone.utc),
        kind="REVOKE",
        decision="BLOCK",
        session_id=req.session_id,
        user_id=sess.user_id if sess else None,
        ip_address=sess.ip_address if sess else None,
        risk_score=100,
        reasons=[req.reason],
    ))
    return {"ok": True, "session_id": req.session_id}
