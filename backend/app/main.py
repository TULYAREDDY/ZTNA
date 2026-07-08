"""Sentinel ZTNA — FastAPI application entrypoint.

The Policy Decision Point of the Adaptive Zero Trust Framework. Every
request received by the upstream proxy (Policy Enforcement Point)
crosses this service to receive an ALLOW / MONITOR / BLOCK verdict.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

from app.api import access, analytics, lab, posture, sessions, websocket
from app.core.config import get_settings
from app.core.logging import configure_logging, get_logger
from app.core.security import auth_enabled, is_exempt_path, validate_http_token
from app.models.schemas import EventView
from app.services.event_bus import bus
from app.services.metrics_service import REQUEST_LATENCY, REQUESTS_TOTAL, metrics_response
from app.services.ml_service import ml_service
from app.services.rate_limiter import rate_limiter
from app.services.session_store import store

logger = get_logger("ztna.main")


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging()
    cfg = get_settings()
    if cfg.auth_enabled and not cfg.auth_token:
        raise RuntimeError("ZTNA_AUTH_ENABLED=true requires ZTNA_AUTH_TOKEN")
    logger.info("starting %s on :%d", cfg.app_name, cfg.api_port)
    if not ml_service.ensure_model():
        logger.warning("ML model unavailable — access decisions will be rule-only")
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

    @app.middleware("http")
    async def auth_and_observability(request: Request, call_next):
        cfg = get_settings()

        # API token auth (optional, production hardening).
        if auth_enabled():
            path = request.url.path
            if path.startswith("/api") and not is_exempt_path(path):
                if not validate_http_token(
                    request.headers.get("Authorization"),
                    request.headers.get("X-API-Key"),
                ):
                    return JSONResponse({"detail": "unauthorized"}, status_code=401)

        # Rate limit high-risk endpoints by client IP.
        if cfg.rate_limit_enabled:
            client_ip = (request.headers.get("x-forwarded-for", "").split(",")[0].strip()
                         or (request.client.host if request.client else "unknown"))
            path = request.url.path
            if path == "/api/posture":
                ok = rate_limiter.allow(f"posture:{client_ip}", limit=cfg.rate_limit_posture_per_min)
                if not ok:
                    return JSONResponse({"detail": "rate limit exceeded"}, status_code=429)
            elif path == "/api/access":
                ok = rate_limiter.allow(f"access:{client_ip}", limit=cfg.rate_limit_access_per_min)
                if not ok:
                    return JSONResponse({"detail": "rate limit exceeded"}, status_code=429)

        # Basic request metrics.
        start = time.perf_counter()
        response = await call_next(request)
        elapsed = time.perf_counter() - start
        if cfg.metrics_enabled:
            method = request.method
            path = request.url.path
            status = str(response.status_code)
            REQUESTS_TOTAL.labels(method=method, path=path, status=status).inc()
            REQUEST_LATENCY.labels(method=method, path=path).observe(elapsed)
        return response

    @app.get("/api/health", tags=["health"])
    async def health() -> dict:
        metrics = ml_service.metrics()
        return {
            "ok": True,
            "service": cfg.app_name,
            "active_sessions": len(store.all_active()),
            "ml": {
                "trained": ml_service.is_trained(),
                "model": metrics.get("model"),
                "accuracy": metrics.get("accuracy"),
            },
        }

    @app.get("/api/metrics", tags=["health"])
    async def metrics():
        if not get_settings().metrics_enabled:
            return JSONResponse({"detail": "metrics disabled"}, status_code=404)
        return metrics_response()

    return app


app = create_app()


if __name__ == "__main__":
    import uvicorn

    cfg = get_settings()
    uvicorn.run("app.main:app", host=cfg.api_host, port=cfg.api_port, reload=False)
