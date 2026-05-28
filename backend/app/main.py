"""Sentinel ZTNA — FastAPI application entrypoint.

The Policy Decision Point of the Adaptive Zero Trust Framework. Every
request received by the upstream proxy (Policy Enforcement Point)
crosses this service to receive an ALLOW / MONITOR / BLOCK verdict.
"""

from __future__ import annotations

import asyncio
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api import access, analytics, lab, posture, sessions, websocket
from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.models.schemas import EventView
from app.services.event_bus import bus
from app.services.ml_service import ml_service
from app.services.session_store import store

logger = get_logger("ztna.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    cfg = get_settings()
    logger.info("starting %s on :%d", cfg.app_name, cfg.api_port)
    ml_service.metrics()  # warm load
    sweeper_task = asyncio.create_task(_session_sweeper())
    yield
    sweeper_task.cancel()
    logger.info("shutdown complete")


async def _session_sweeper() -> None:
    """Periodically expire idle sessions and emit events."""
    while True:
        try:
            await asyncio.sleep(30)
            for sess in store.sweep_expired():
                await bus.publish(EventView(
                    id=str(uuid.uuid4()),
                    ts=datetime.now(timezone.utc),
                    kind="EXPIRE",
                    decision="BLOCK",
                    session_id=sess.session_id,
                    user_id=sess.user_id,
                    ip_address=sess.ip_address,
                    risk_score=0,
                    reasons=["session_expired"],
                ))
        except asyncio.CancelledError:
            break
        except Exception as e:  # noqa: BLE001
            logger.exception("sweeper error: %s", e)


def create_app() -> FastAPI:
    cfg = get_settings()
    app = FastAPI(
        title=cfg.app_name,
        version="1.0.0",
        description="Adaptive Zero Trust Framework — Policy Decision Point",
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        allow_origins=cfg.cors_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(posture.router, prefix="/api")
    app.include_router(access.router, prefix="/api")
    app.include_router(sessions.router, prefix="/api")
    app.include_router(analytics.router, prefix="/api")
    app.include_router(lab.router, prefix="/api")
    app.include_router(websocket.router, prefix="/api")

    @app.get("/api/health", tags=["health"])
    async def health() -> dict:
        return {
            "ok": True,
            "service": cfg.app_name,
            "active_sessions": len(store.all_active()),
        }

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    cfg = get_settings()
    uvicorn.run("app.main:app", host=cfg.api_host, port=cfg.api_port, reload=False)
