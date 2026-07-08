"""Geo resolution and continuous location-risk scoring.

Private/lab IPs fall back to the session's registered country. Public
prefixes used in the attack lab (e.g. 185.x for token theft) map to
distinct countries so geo drift is detectable without an external API.
"""

from __future__ import annotations

import ipaddress
from functools import lru_cache

from app.core.risk_constants import HIGH_RISK_GEOS

# Longest-prefix wins; used when the client does not send geo_country.
_PUBLIC_PREFIX_COUNTRIES: tuple[tuple[str, str], ...] = (
    ("185.", "RU"),   # token-theft lab scenario
    ("91.", "DE"),
    ("203.", "AU"),
    ("41.", "ZA"),
    ("177.", "BR"),
    ("1.", "US"),
)


def resolve_country(
    ip_address: str,
    *,
    session_geo: str,
    geo_hint: str | None = None,
) -> str:
    """Resolve an ISO-3166 alpha-2 country for an IP address."""
    if geo_hint:
        return geo_hint.strip().upper()[:2]

    try:
        addr = ipaddress.ip_address(ip_address)
    except ValueError:
        return session_geo.upper()[:2]

    if addr.is_private or addr.is_loopback or addr.is_link_local:
        return session_geo.upper()[:2]

    for prefix, country in _PUBLIC_PREFIX_COUNTRIES:
        if ip_address.startswith(prefix):
            return country

    # Unknown public IP: treat as distinct from the session home geo.
    return "XX"


@lru_cache(maxsize=4096)
def compute_location_risk(
    session_geo: str,
    current_geo: str,
    ip_changed: bool,
) -> float:
    """Return a continuous location-risk signal in [0, 1]."""
    home = session_geo.upper()[:2]
    here = current_geo.upper()[:2]
    same_country = home == here and here != "XX"

    if not ip_changed and same_country:
        base = 0.08
    elif not ip_changed:
        base = 0.12
    elif same_country:
        base = 0.32
    elif here == "XX":
        base = 0.48
    else:
        base = 0.58

    if here in HIGH_RISK_GEOS:
        base = min(1.0, base + 0.35)
    elif home in HIGH_RISK_GEOS:
        base = min(1.0, base + 0.12)

    return round(base, 3)
