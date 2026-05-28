"""Attack Lab — fire pre-built traffic scenarios from the dashboard.

Each scenario internally calls the same /posture and /access logic the
proxy would use, so events show up live on the WebSocket feed.
"""

from __future__ import annotations

import asyncio
import random
import time
from datetime import datetime, timezone
from typing import Awaitable, Callable

from fastapi import APIRouter, HTTPException

from app.api.access import access as do_access
from app.api.posture import posture as do_posture
from app.models.schemas import AccessRequest, PostureRequest

router = APIRouter(tags=["lab"])


def _user(*, geo: str = "IN", clean: bool = True, ip: str | None = None,
          managed: bool | None = None) -> PostureRequest:
    base = ip or f"10.0.{random.randint(0, 8)}.{random.randint(2, 250)}"
    return PostureRequest(
        user_id=f"user-{random.randint(1000, 9999)}",
        device_id=f"dev-{random.randint(10000, 99999)}",
        os=random.choice(["macOS-15", "Windows-11", "Ubuntu-24.04"]),
        os_patched=clean,
        antivirus_active=clean,
        firewall_active=clean,
        disk_encrypted=clean,
        screen_lock_enabled=clean,
        is_managed_device=clean if managed is None else managed,
        process_count=random.randint(80, 400),
        ip_address=base,
        geo_country=geo,
        user_agent="ztna-client/1.0",
    )


async def _normal_baseline() -> dict:
    summary = {"sessions": 0, "requests": 0}
    for _ in range(6):
        u = _user()
        p = await do_posture(u)
        if not p.session_id:
            continue
        summary["sessions"] += 1
        for _ in range(random.randint(3, 6)):
            await do_access(AccessRequest(
                session_id=p.session_id,
                ip_address=u.ip_address,           # same IP → ALLOW
                target_service=random.choice(["payroll", "wiki", "git", "jira"]),
            ))
            summary["requests"] += 1
            await asyncio.sleep(0.04)
    return summary


async def _token_theft() -> dict:
    u = _user()
    p = await do_posture(u)
    if not p.session_id:
        return {"error": "posture failed"}
    owner_ip = u.ip_address                        # legitimate user keeps their IP
    for _ in range(3):
        await do_access(AccessRequest(session_id=p.session_id, ip_address=owner_ip,
                                      target_service="git"))
        await asyncio.sleep(0.08)
    attacker_ip = f"185.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(2, 250)}"
    for _ in range(5):
        await do_access(AccessRequest(session_id=p.session_id, ip_address=attacker_ip,
                                      target_service="production-db"))
        await asyncio.sleep(0.08)
    return {"session_id": p.session_id, "owner_ip": owner_ip, "attacker_ip": attacker_ip}


async def _brute_force() -> dict:
    """Posture should reject before we even get a session."""
    u = _user(clean=False)
    p = await do_posture(u)
    if not p.session_id:
        return {"stopped_at": "posture", "reasons": p.reasons,
                "decision": p.decision, "posture_score": p.posture_score}
    # if it slipped through, hammer
    for _ in range(20):
        await do_access(AccessRequest(session_id=p.session_id,
                                      ip_address=u.ip_address,
                                      target_service="auth-service"))
        await asyncio.sleep(0.02)
    return {"session_id": p.session_id}


async def _recon() -> dict:
    """Unmanaged but otherwise compliant device probes slowly."""
    user = _user(clean=True, managed=False)
    p = await do_posture(user)
    if not p.session_id:
        return {"stopped_at": "posture", "reasons": p.reasons}
    for _ in range(8):
        await do_access(AccessRequest(session_id=p.session_id,
                                      ip_address=user.ip_address,
                                      target_service=random.choice(["admin-panel", "internal-api", "k8s"])))
        await asyncio.sleep(0.25)
    return {"session_id": p.session_id}


async def _geo_anomaly() -> dict:
    p = await do_posture(_user(geo="KP"))
    return {"decision": p.decision, "posture_score": p.posture_score, "reasons": p.reasons}


SCENARIOS: dict[str, dict] = {
    "normal": {
        "label": "Normal Baseline",
        "description": "Healthy traffic across 6 users.",
        "runner": _normal_baseline,
    },
    "token_theft": {
        "label": "Token Theft (T1078)",
        "description": "Stolen session reused from a foreign IP — IP-mismatch should fire.",
        "runner": _token_theft,
    },
    "brute_force": {
        "label": "Brute Force (T1110)",
        "description": "Rapid attempts from a non-compliant device — posture should reject.",
        "runner": _brute_force,
    },
    "recon": {
        "label": "Recon — Low & Slow (T1595)",
        "description": "Stealthy probing from an unmanaged device — risk drifts upward.",
        "runner": _recon,
    },
    "geo_anomaly": {
        "label": "Geo Anomaly",
        "description": "Login from a high-risk geography — posture rejects at the door.",
        "runner": _geo_anomaly,
    },
}


@router.get("/lab/scenarios")
async def list_scenarios() -> list[dict]:
    return [{"key": k, "label": v["label"], "description": v["description"]}
            for k, v in SCENARIOS.items()]


@router.post("/lab/run/{key}")
async def run_scenario(key: str) -> dict:
    spec = SCENARIOS.get(key)
    if not spec:
        raise HTTPException(404, f"unknown scenario: {key}")
    t0 = time.time()
    result = await spec["runner"]()
    return {
        "ok": True,
        "scenario": key,
        "label": spec["label"],
        "started_at": datetime.now(timezone.utc).isoformat(),
        "elapsed_ms": int((time.time() - t0) * 1000),
        "result": result,
    }
