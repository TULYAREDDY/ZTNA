"""Runtime configuration loaded from environment variables."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_prefix="ZTNA_", extra="ignore")

    app_name: str = "Sentinel ZTNA"
    api_host: str = "0.0.0.0"
    api_port: int = 8000

    # Session policy
    session_ttl_seconds: int = 1800              # 30 min idle
    session_hard_ttl_seconds: int = 28800        # 8 h hard cap
    max_failed_attempts: int = 5
    session_store_backend: str = "memory"        # memory | redis
    redis_url: str = "redis://localhost:6379/0"
    redis_key_prefix: str = "ztna"

    # Risk thresholds: continuous, monitor, block
    risk_monitor_threshold: int = 45
    risk_block_threshold: int = 70

    # ML
    ml_model_path: Path = Path("app/ml/artifacts/model.joblib")
    ml_metrics_path: Path = Path("app/ml/artifacts/metrics.json")
    ml_dataset_path: Path = Path("app/ml/artifacts/dataset.csv")
    ml_auto_train: bool = True

    # API security
    auth_enabled: bool = False
    auth_token: str = ""

    # Observability / traffic controls
    metrics_enabled: bool = True
    rate_limit_enabled: bool = True
    rate_limit_posture_per_min: int = 30
    rate_limit_access_per_min: int = 180

    # CORS
    cors_origins: list[str] = [
        "http://localhost:5173",
        "http://localhost:4173",
        "http://127.0.0.1:5173",
    ]


@lru_cache
def get_settings() -> Settings:
    return Settings()
