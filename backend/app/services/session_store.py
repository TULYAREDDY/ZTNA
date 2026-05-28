"""In-memory session store with idle and absolute expiry.

For a production deployment this would be Redis with TTL — the API
deliberately mirrors the operations Redis would expose so swapping is
trivial.
"""

from __future__ import annotations

import time
import uuid
from dataclasses import dataclass, field
from threading import RLock
from typing import Optional

from app.core.config import get_settings


@dataclass
class Session:
    session_id: str
    user_id: str
    device_id: str
    ip_address: str
    geo_country: str
    os: str
    user_agent: str
    posture_score: int
    created_at: float
    last_seen_at: float
    request_count: int = 0
    block_count: int = 0
    monitor_count: int = 0
    failed_attempts: int = 0
    risk_score: int = 0
    status: str = "ACTIVE"
    request_history: list[float] = field(default_factory=list)

    @property
    def age_seconds(self) -> float:
        return time.time() - self.created_at

    def touch(self) -> None:
        self.last_seen_at = time.time()


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, Session] = {}
        self._lock = RLock()

    def create(
        self,
        *,
        user_id: str,
        device_id: str,
        ip_address: str,
        geo_country: str,
        os: str,
        user_agent: str,
        posture_score: int,
    ) -> Session:
        sid = str(uuid.uuid4())
        now = time.time()
        sess = Session(
            session_id=sid,
            user_id=user_id,
            device_id=device_id,
            ip_address=ip_address,
            geo_country=geo_country,
            os=os,
            user_agent=user_agent,
            posture_score=posture_score,
            created_at=now,
            last_seen_at=now,
        )
        with self._lock:
            self._sessions[sid] = sess
        return sess

    def get(self, session_id: str) -> Optional[Session]:
        with self._lock:
            return self._sessions.get(session_id)

    def all_active(self) -> list[Session]:
        self.sweep_expired()
        with self._lock:
            return [s for s in self._sessions.values() if s.status == "ACTIVE"]

    def all(self) -> list[Session]:
        with self._lock:
            return list(self._sessions.values())

    def revoke(self, session_id: str, reason: str = "revoked") -> bool:
        with self._lock:
            sess = self._sessions.get(session_id)
            if not sess or sess.status != "ACTIVE":
                return False
            sess.status = "REVOKED"
        return True

    def expire(self, session_id: str) -> None:
        with self._lock:
            sess = self._sessions.get(session_id)
            if sess and sess.status == "ACTIVE":
                sess.status = "EXPIRED"

    def sweep_expired(self) -> list[Session]:
        cfg = get_settings()
        now = time.time()
        expired: list[Session] = []
        with self._lock:
            for s in self._sessions.values():
                if s.status != "ACTIVE":
                    continue
                idle = now - s.last_seen_at
                age = now - s.created_at
                if idle > cfg.session_ttl_seconds or age > cfg.session_hard_ttl_seconds:
                    s.status = "EXPIRED"
                    expired.append(s)
        return expired

    def record_request(self, session: Session, decision: str) -> None:
        now = time.time()
        with self._lock:
            session.touch()
            session.request_count += 1
            session.request_history.append(now)
            session.request_history = [t for t in session.request_history if now - t < 60]
            if decision == "BLOCK":
                session.block_count += 1
                session.failed_attempts += 1
            elif decision == "MONITOR":
                session.monitor_count += 1
            else:
                session.failed_attempts = max(0, session.failed_attempts - 1)


store = SessionStore()
