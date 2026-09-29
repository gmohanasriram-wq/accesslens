"""Shared test fixtures.

Two rules govern everything here.

**Hermetic.** Every ``Settings`` is constructed explicitly with ``_env_file=None``
so a developer's ``.env`` cannot change a test result. Without that, a stray
``ACCESSLENS_LOW_UTILIZATION_THRESHOLD`` in someone's working copy would make the
suite pass locally and fail in CI, which is the worst possible failure mode for
tests that are supposed to be the security oracle.

**Pinned clock.** ``ANALYSIS_AS_OF`` is the fixture set's own date. Deriving it
from ``utcnow()`` would make the window slide daily until the fixtured events
fell outside it and every coverage assertion started failing for a reason no
reader could see.
"""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.db import build_engine, build_session_factory, create_all, session_scope
from app.ingestion import InMemoryDataset, IngestPipeline
from app.ingestion.pipeline import _Loaded
from app.schemas.ingest import IngestReport

#: The date the bundled fixture set is anchored to. Must match the
#: ``generated_at`` and coverage windows inside ``data/*.json``.
ANALYSIS_AS_OF = "2026-09-29T06:00:00Z"

REPO_ROOT = Path(__file__).resolve().parents[2]
DATA_DIR = REPO_ROOT / "data"
ORACLE_DIR = Path(__file__).resolve().parent / "fixtures" / "oracles"
INVALID_DIR = Path(__file__).resolve().parent / "fixtures" / "invalid"


@pytest.fixture(scope="session")
def analysis_as_of() -> datetime:
    return datetime(2026, 9, 29, 6, 0, tzinfo=UTC)


@pytest.fixture
def settings(tmp_path: Path) -> Settings:
    """Pinned settings on a throwaway database."""
    return Settings(
        analysis_as_of=ANALYSIS_AS_OF,
        database_url=f"sqlite+pysqlite:///{tmp_path / 'accesslens-test.db'}",
        _env_file=None,  # type: ignore[call-arg]  # pydantic-settings init kwarg
    )


@pytest.fixture
def pipeline(settings: Settings) -> IngestPipeline:
    return IngestPipeline(settings)


@pytest.fixture
def loaded(pipeline: IngestPipeline) -> _Loaded:
    return pipeline.load_sources()


@pytest.fixture
def dataset(pipeline: IngestPipeline) -> InMemoryDataset:
    """The normalized fixtures, assembled without touching a database.

    Built rather than loaded through ``run()`` so the pure-normalization tests
    cannot accidentally depend on persistence.
    """
    return pipeline.build_dataset(pipeline.load_sources())


@pytest.fixture
def ingesting(pipeline: IngestPipeline, settings: Settings):
    """Run the full pipeline against a real (temporary) database.

    Returns ``(session_factory, report, dataset)`` so a test can inspect both
    what was written and what was concluded from it.
    """
    engine = build_engine(settings)
    create_all(engine)
    factory = build_session_factory(engine)
    with session_scope(factory) as session:
        report, built = pipeline.run(session)
    yield factory, report, built
    engine.dispose()


@pytest.fixture
def client(settings: Settings):
    """A TestClient with the app's real lifespan run.

    Not ``TestClient(app)`` on the import-time singleton: that app was built
    from whatever ``.env`` happened to be on disk. This builds a fresh app from
    the pinned settings so the API tests are hermetic too.
    """
    from app.main import create_app

    with TestClient(create_app(settings)) as test_client:
        yield test_client


@pytest.fixture
def oracle() -> dict:
    import json

    path = ORACLE_DIR / "expected_findings.json"
    return json.loads(path.read_text(encoding="utf-8"))
