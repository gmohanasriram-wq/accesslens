"""Application configuration.

Two settings deserve explanation because they shape the whole system:

``analysis_as_of``
    The instant the analysis pretends "now" is. The fixture set and the Phase 2
    oracles are anchored to 2026-09-29T06:00:00Z, and the lookback window is
    derived by subtracting ``lookback_days`` from it. If any analysis code read
    the wall clock instead, Bob's 90-day window would slide forward, his events
    would fall out of it, and the oracles would start failing next month for no
    reason a reader could see. Pinning the clock is what makes a dated fixture
    set reproducible.

``protected_role_patterns`` / ``always_protected_roles``
    Break-glass classification is *configuration*, not logic. Which roles are
    protected during an access review is a policy decision owned by the
    organisation, and it has to be changeable and reviewable without editing
    detection code -- a security rule that can only be changed by shipping a
    release is a rule that will be worked around.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from app.core.enums import ActivitySource
from app.core.time import ensure_utc, utcnow

# <repo>/backend/app/core/config.py -> <repo>
_REPO_ROOT = Path(__file__).resolve().parents[3]

__all__ = ["Settings", "get_settings"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="ACCESSLENS_",
        extra="ignore",
        case_sensitive=False,
    )

    # --- application ------------------------------------------------------ #
    app_name: str = "AccessLens"
    app_version: str = "0.1.0"
    environment: Literal["local", "test", "demo"] = "local"
    debug: bool = False
    api_prefix: str = "/api"

    # --- data sources ----------------------------------------------------- #
    # `data/` holds stand-ins for the upstream systems (Workday, Okta, AWS,
    # GitHub). It is read-only input; the application never writes to it.
    data_dir: Path = _REPO_ROOT / "data"
    enabled_activity_sources: tuple[ActivitySource, ...] = (
        ActivitySource.AWS_CLOUDTRAIL,
        ActivitySource.GITHUB_AUDIT,
        ActivitySource.PROXY_ZSCALER,
    )

    # --- persistence ------------------------------------------------------ #
    # SQLite by default because no PostgreSQL server is available in this
    # environment. Every model uses portable SQLAlchemy types only, so pointing
    # this at PostgreSQL (postgresql+psycopg://...) requires no code change.
    database_url: str = "sqlite+pysqlite:///./accesslens.db"
    auto_ingest_on_startup: bool = True

    # --- analysis window -------------------------------------------------- #
    lookback_days: int = 90
    analysis_as_of: datetime | None = None  # None -> utcnow(); pinned in tests

    # --- thresholds ------------------------------------------------------- #
    # Consumed by the Phase 2 engine. Defined here in Phase 1 so that the
    # oracle files and the engine agree on one source of truth for defaults.
    low_utilization_threshold: float = 0.25
    min_observed_events_for_confidence: int = 3

    # --- risk classification by role name --------------------------------- #
    high_risk_entitlement_roles: tuple[str, ...] = (
        "AdministratorAccess",
        "PowerUserAccess",
        "org:admin",
        "repo:admin",
    )
    critical_risk_entitlement_roles: tuple[str, ...] = (
        "AdministratorAccess",
        "org:admin",
    )

    # --- break-glass / protection (Rule C) -------------------------------- #
    protected_role_patterns: tuple[str, ...] = (
        "break-glass",
        "break_glass",
        "emergency",
        "disaster-recovery",
        "dr-operator",
        "backup-recovery",
    )
    always_protected_roles: tuple[str, ...] = (
        "break-glass-emergency-admin",
        "disaster-recovery-operator",
    )

    # --- ghost access (Rule D) -------------------------------------------- #
    ghost_access_min_post_deactivation_events: int = 1
    # Grace window for clock skew between systems. 0 = strict ordering.
    ghost_access_grace_hours: int = 0

    # --- CORS ------------------------------------------------------------- #
    cors_origins: tuple[str, ...] = (
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    )

    # --- logging ---------------------------------------------------------- #
    log_level: str = "INFO"

    @field_validator("analysis_as_of")
    @classmethod
    def _normalise_as_of(cls, value: datetime | None) -> datetime | None:
        return ensure_utc(value) if value is not None else None

    @field_validator("data_dir")
    @classmethod
    def _resolve_data_dir(cls, value: Path) -> Path:
        """Resolve a relative ``data_dir`` against the repository root.

        Without this, the path would resolve against whatever directory the
        process happened to start in, which differs between ``uvicorn`` (run
        from ``backend/``) and ``pytest`` (run from the repo root).
        """
        return value if value.is_absolute() else (_REPO_ROOT / value).resolve()

    def effective_analysis_as_of(self) -> datetime:
        """The analysis instant: the pinned value, or now if unset."""
        return self.analysis_as_of if self.analysis_as_of is not None else utcnow()

    def window(self) -> tuple[datetime, datetime]:
        """The ``(start, end)`` of the lookback window, as aware UTC datetimes."""
        end = self.effective_analysis_as_of()
        return end - timedelta(days=self.lookback_days), end


@lru_cache
def get_settings() -> Settings:
    """Cached settings accessor.

    Cached so the ``.env`` file is read once per process. Tests that need
    different values should construct ``Settings(...)`` directly and inject it
    rather than mutating the environment, which would leak between tests.
    """
    return Settings()
