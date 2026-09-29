"""AccessLens backend.

Telemetry-informed access review and deprovisioning investigation.

The security-relevant conclusions in this system are produced by deterministic
Python (Phase 2, ``app.engine``) from normalised data. The AI layer (Phase 4)
explains and challenges those conclusions; it never makes them.
"""

__version__ = "0.1.0"
