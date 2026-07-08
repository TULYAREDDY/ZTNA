"""Device posture validation.

We score the device on a 0-100 scale where 100 = pristine. Each missing
control deducts a fixed weight derived from CIS / NIST 800-53 controls
(rough mapping).
"""

from __future__ import annotations

from app.core.risk_constants import HIGH_RISK_GEOS
from app.models.schemas import PostureRequest

WEIGHTS = {
    "antivirus_active": 20,
    "firewall_active": 15,
    "disk_encrypted": 20,
    "screen_lock_enabled": 5,
    "is_managed_device": 15,
    "os_patched": 25,
}

def evaluate_posture(p: PostureRequest) -> tuple[int, list[str]]:
    """Return (posture_score 0-100, reasons[])."""
    score = 100
    reasons: list[str] = []

    for field, weight in WEIGHTS.items():
        if not getattr(p, field):
            score -= weight
            reasons.append(f"missing_control:{field}")

    if p.geo_country.upper() in HIGH_RISK_GEOS:
        score -= 30
        reasons.append(f"high_risk_geo:{p.geo_country}")

    if p.process_count > 800:
        score -= 5
        reasons.append("process_count_outlier")

    if "outdated" in p.user_agent.lower():
        score -= 10
        reasons.append("outdated_user_agent")

    return max(0, min(100, score)), reasons
