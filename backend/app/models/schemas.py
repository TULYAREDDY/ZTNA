"""Pydantic schemas exchanged at the API boundary."""

from __future__ import annotations

from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, Field

Decision = Literal["ALLOW", "MONITOR", "BLOCK"]


class PostureRequest(BaseModel):
    user_id: str = Field(..., description="Stable user identifier (e.g. corp SSO id).")
    device_id: str
    os: str = Field(..., description="Operating system, e.g. macOS-15, Windows-11.")
    os_patched: bool
    antivirus_active: bool
    firewall_active: bool
    disk_encrypted: bool
    screen_lock_enabled: bool = True
    is_managed_device: bool = True
    process_count: int = 0
    ip_address: str
    geo_country: str = "IN"
    user_agent: str = "ztna-client/1.0"


class PostureResponse(BaseModel):
    decision: Decision
    session_id: Optional[str]
    risk_score: int
    posture_score: int
    reasons: list[str]


class AccessRequest(BaseModel):
    session_id: str
    ip_address: str
    geo_country: str | None = Field(
        default=None,
        description="Optional ISO-3166 alpha-2 country for the client IP.",
    )
    target_service: str = ""
    method: str = "GET"
    path: str = "/"
    user_agent: str = ""


class AccessFeatures(BaseModel):
    request_rate: float
    ip_change: int
    failed_attempts: int
    device_trust: float
    time_of_day: int
    location_risk: float
    posture_score: float
    session_age_min: float


class AccessResponse(BaseModel):
    decision: Decision
    risk_score: int
    ml_probability: float
    rule_score: int
    features: AccessFeatures
    reasons: list[str]
    session_status: str


class SessionView(BaseModel):
    session_id: str
    user_id: str
    device_id: str
    ip_address: str
    geo_country: str
    os: str
    created_at: datetime
    last_seen_at: datetime
    risk_score: int
    posture_score: int
    request_count: int
    block_count: int
    monitor_count: int
    status: Literal["ACTIVE", "REVOKED", "EXPIRED"]


class EventView(BaseModel):
    id: str
    ts: datetime
    kind: Literal["POSTURE", "ACCESS", "REVOKE", "EXPIRE"]
    decision: Optional[Decision] = None
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    ip_address: Optional[str] = None
    target_service: Optional[str] = None
    risk_score: Optional[int] = None
    reasons: list[str] = []


class AnalyticsSnapshot(BaseModel):
    active_sessions: int
    total_decisions: int
    allow_count: int
    monitor_count: int
    block_count: int
    block_rate: float
    avg_risk_score: float
    decisions_per_minute: float
    top_blocked_ips: list[dict]
    decision_timeline: list[dict]


class RevokeRequest(BaseModel):
    session_id: str
    reason: str = "manual revocation"
