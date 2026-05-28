"""Analytics endpoints powering the dashboard KPI cards & charts."""

from __future__ import annotations

import time
from collections import Counter, defaultdict
from datetime import datetime, timezone

from fastapi import APIRouter

from app.models.schemas import AnalyticsSnapshot, EventView
from app.services.event_bus import bus
from app.services.ml_service import ml_service
from app.services.session_store import store

router = APIRouter(tags=["analytics"])


@router.get("/analytics/snapshot", response_model=AnalyticsSnapshot)
async def snapshot() -> AnalyticsSnapshot:
    history = bus.history(limit=500)
    access_events = [e for e in history if e.kind == "ACCESS"]

    allow = sum(1 for e in access_events if e.decision == "ALLOW")
    monitor = sum(1 for e in access_events if e.decision == "MONITOR")
    block = sum(1 for e in access_events if e.decision == "BLOCK")
    total = len(access_events)
    block_rate = (block / total) if total else 0.0

    risks = [e.risk_score for e in access_events if e.risk_score is not None]
    avg_risk = sum(risks) / len(risks) if risks else 0.0

    now = time.time()
    last_minute = [e for e in access_events
                   if (now - e.ts.timestamp()) < 60]
    dpm = float(len(last_minute))

    blocked = Counter(
        e.ip_address for e in access_events
        if e.decision == "BLOCK" and e.ip_address
    )
    top_blocked = [
        {"ip": ip, "count": cnt}
        for ip, cnt in blocked.most_common(5)
    ]

    buckets: dict[int, dict[str, int]] = defaultdict(lambda: {"ALLOW": 0, "MONITOR": 0, "BLOCK": 0})
    for e in access_events:
        bucket = int(e.ts.timestamp() // 10) * 10
        if e.decision in buckets[bucket]:
            buckets[bucket][e.decision] += 1
    timeline = [
        {
            "ts": datetime.fromtimestamp(b, tz=timezone.utc).isoformat(),
            **counts,
        }
        for b, counts in sorted(buckets.items())
    ][-30:]

    return AnalyticsSnapshot(
        active_sessions=len(store.all_active()),
        total_decisions=total,
        allow_count=allow,
        monitor_count=monitor,
        block_count=block,
        block_rate=round(block_rate, 4),
        avg_risk_score=round(avg_risk, 2),
        decisions_per_minute=dpm,
        top_blocked_ips=top_blocked,
        decision_timeline=timeline,
    )


@router.get("/analytics/ml")
async def ml_metrics() -> dict:
    return ml_service.metrics()


@router.get("/analytics/events", response_model=list[EventView])
async def recent_events(limit: int = 100) -> list[EventView]:
    return bus.history(limit=limit)
