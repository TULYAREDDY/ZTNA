"""Session store abstraction with memory and Redis backends."""

from __future__ import annotations

import time
import uuid
import json
from dataclasses import dataclass, field
from threading import RLock
from typing import Optional, Protocol

import redis

from app.core.logging import get_logger
from app.core.config import get_settings

logger = get_logger("ztna.sessions.store")


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

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "device_id": self.device_id,
            "ip_address": self.ip_address,
            "geo_country": self.geo_country,
            "os": self.os,
            "user_agent": self.user_agent,
            "posture_score": self.posture_score,
            "created_at": self.created_at,
            "last_seen_at": self.last_seen_at,
            "request_count": self.request_count,
            "block_count": self.block_count,
            "monitor_count": self.monitor_count,
            "failed_attempts": self.failed_attempts,
            "risk_score": self.risk_score,
            "status": self.status,
            "request_history": self.request_history,
        }

    @classmethod
    def from_dict(cls, raw: dict) -> "Session":
        return cls(
            session_id=raw["session_id"],
            user_id=raw["user_id"],
            device_id=raw["device_id"],
            ip_address=raw["ip_address"],
            geo_country=raw["geo_country"],
            os=raw["os"],
            user_agent=raw["user_agent"],
            posture_score=int(raw["posture_score"]),
            created_at=float(raw["created_at"]),
            last_seen_at=float(raw["last_seen_at"]),
            request_count=int(raw.get("request_count", 0)),
            block_count=int(raw.get("block_count", 0)),
            monitor_count=int(raw.get("monitor_count", 0)),
            failed_attempts=int(raw.get("failed_attempts", 0)),
            risk_score=int(raw.get("risk_score", 0)),
            status=str(raw.get("status", "ACTIVE")),
            request_history=[float(t) for t in raw.get("request_history", [])],
        )


class SessionStoreProtocol(Protocol):
    def create(self, *, user_id: str, device_id: str, ip_address: str, geo_country: str,
               os: str, user_agent: str, posture_score: int) -> Session:
        ...
    def get(self, session_id: str) -> Optional[Session]:
        ...
    def all_active(self) -> list[Session]:
        ...
    def all(self) -> list[Session]:
        ...
    def revoke(self, session_id: str, reason: str = "revoked") -> bool:
        ...
    def expire(self, session_id: str) -> None:
        ...
    def sweep_expired(self) -> list[Session]:
        ...
    def record_request(self, session: Session, decision: str) -> None:
        ...


class InMemorySessionStore:
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


class RedisSessionStore:
    def __init__(self, redis_url: str, key_prefix: str = "ztna") -> None:
        self._cfg = get_settings()
        self._r = redis.Redis.from_url(redis_url, decode_responses=True)
        self._key_prefix = key_prefix

    def _k(self, sid: str) -> str:
        return f"{self._key_prefix}:session:{sid}"

    def _remaining_hard_ttl(self, s: Session) -> int:
        age = int(time.time() - s.created_at)
        return max(1, self._cfg.session_hard_ttl_seconds - age)

    def _save(self, s: Session) -> None:
        self._r.set(self._k(s.session_id), json.dumps(s.to_dict()), ex=self._remaining_hard_ttl(s))

    def create(self, *, user_id: str, device_id: str, ip_address: str, geo_country: str,
               os: str, user_agent: str, posture_score: int) -> Session:
        sid = str(uuid.uuid4())
        now = time.time()
        s = Session(
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
        self._save(s)
        return s

    def get(self, session_id: str) -> Optional[Session]:
        raw = self._r.get(self._k(session_id))
        if not raw:
            return None
        return Session.from_dict(json.loads(raw))

    def all(self) -> list[Session]:
        sessions: list[Session] = []
        for key in self._r.scan_iter(match=f"{self._key_prefix}:session:*"):
            raw = self._r.get(key)
            if raw:
                sessions.append(Session.from_dict(json.loads(raw)))
        return sessions

    def all_active(self) -> list[Session]:
        self.sweep_expired()
        return [s for s in self.all() if s.status == "ACTIVE"]

    def revoke(self, session_id: str, reason: str = "revoked") -> bool:
        s = self.get(session_id)
        if not s or s.status != "ACTIVE":
            return False
        s.status = "REVOKED"
        self._save(s)
        return True

    def expire(self, session_id: str) -> None:
        s = self.get(session_id)
        if s and s.status == "ACTIVE":
            s.status = "EXPIRED"
            self._save(s)

    def sweep_expired(self) -> list[Session]:
        now = time.time()
        expired: list[Session] = []
        for s in self.all():
            if s.status != "ACTIVE":
                continue
            idle = now - s.last_seen_at
            age = now - s.created_at
            if idle > self._cfg.session_ttl_seconds or age > self._cfg.session_hard_ttl_seconds:
                s.status = "EXPIRED"
                self._save(s)
                expired.append(s)
        return expired

    def record_request(self, session: Session, decision: str) -> None:
        s = self.get(session.session_id)
        if not s:
            return
        now = time.time()
        s.last_seen_at = now
        s.request_count += 1
        s.risk_score = session.risk_score
        s.request_history.append(now)
        s.request_history = [t for t in s.request_history if now - t < 60]
        if decision == "BLOCK":
            s.block_count += 1
            s.failed_attempts += 1
        elif decision == "MONITOR":
            s.monitor_count += 1
        else:
            s.failed_attempts = max(0, s.failed_attempts - 1)
        self._save(s)


def _build_store() -> SessionStoreProtocol:
    cfg = get_settings()
    if cfg.session_store_backend.lower() != "redis":
        logger.info("session store backend=memory")
        return InMemorySessionStore()
    try:
        store = RedisSessionStore(cfg.redis_url, cfg.redis_key_prefix)
        store._r.ping()
        logger.info("session store backend=redis")
        return store
    except Exception as exc:  # noqa: BLE001
        logger.warning("redis unavailable (%s), falling back to memory", exc)
        return InMemorySessionStore()


store: SessionStoreProtocol = _build_store()
