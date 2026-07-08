"""WebSocket endpoint streaming live events to the dashboard."""

from __future__ import annotations

import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from app.core.logging import get_logger
from app.core.security import auth_enabled, validate_ws_token
from app.services.event_bus import bus

router = APIRouter()
logger = get_logger("ztna.ws")


@router.websocket("/ws/events")
async def event_stream(ws: WebSocket) -> None:
    if auth_enabled() and not validate_ws_token(ws):
        await ws.close(code=1008)
        return
    await ws.accept()
    queue = await bus.subscribe()
    try:
        for past in bus.history(limit=50):
            await ws.send_json(_serialize(past))

        while True:
            try:
                event = await asyncio.wait_for(queue.get(), timeout=15)
                await ws.send_json(_serialize(event))
            except asyncio.TimeoutError:
                await ws.send_json({"kind": "PING"})
    except WebSocketDisconnect:
        logger.debug("ws client disconnected")
    finally:
        await bus.unsubscribe(queue)


def _serialize(e) -> dict:
    return {
        "id": e.id,
        "ts": e.ts.isoformat(),
        "kind": e.kind,
        "decision": e.decision,
        "session_id": e.session_id,
        "user_id": e.user_id,
        "ip_address": e.ip_address,
        "target_service": e.target_service,
        "risk_score": e.risk_score,
        "reasons": e.reasons,
    }
