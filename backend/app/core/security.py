"""Authentication helpers for API and WebSocket endpoints."""

from __future__ import annotations

from fastapi import WebSocket

from app.core.config import get_settings

_EXEMPT_PATHS = {
    "/api/health",
    "/openapi.json",
    "/docs",
    "/docs/oauth2-redirect",
    "/redoc",
}


def auth_enabled() -> bool:
    cfg = get_settings()
    return cfg.auth_enabled and bool(cfg.auth_token)


def is_exempt_path(path: str) -> bool:
    if path in _EXEMPT_PATHS:
        return True
    return path.startswith("/docs")


def _extract_token(authorization: str | None, x_api_key: str | None) -> str:
    if x_api_key:
        return x_api_key.strip()
    if not authorization:
        return ""
    value = authorization.strip()
    if value.lower().startswith("bearer "):
        return value[7:].strip()
    return value


def validate_http_token(authorization: str | None, x_api_key: str | None) -> bool:
    cfg = get_settings()
    token = _extract_token(authorization, x_api_key)
    return bool(token) and token == cfg.auth_token


def validate_ws_token(ws: WebSocket) -> bool:
    cfg = get_settings()
    token = ws.query_params.get("token", "").strip()
    return bool(token) and token == cfg.auth_token
