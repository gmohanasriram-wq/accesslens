"""HTTP layer.

Phase 1 exposes health and a persona listing -- enough to prove the stack
end-to-end. Analysis, findings and remediation endpoints arrive in Phase 3, and
none of them will perform a security-changing action: the blueprint keeps human
approval in the loop, so this layer is read-only by construction.
"""

from __future__ import annotations

from app.api.deps import (
    AppState,
    DatasetDep,
    SessionDep,
    SettingsDep,
    StateDep,
    get_app_state,
    get_session,
    get_settings,
    require_dataset,
)

__all__ = [
    "AppState",
    "DatasetDep",
    "SessionDep",
    "SettingsDep",
    "StateDep",
    "get_app_state",
    "get_session",
    "get_settings",
    "require_dataset",
]
