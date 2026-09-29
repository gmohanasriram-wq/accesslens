"""Leaf layer: vocabulary, configuration, errors and time discipline.

Nothing in ``app.core`` imports from elsewhere in ``app``. Schemas, ORM models,
ingestion, the API and (in Phase 2) the engine all depend on this package, so it
must stay dependency-free to keep the import graph acyclic -- and to keep pure
validation from dragging in SQLAlchemy or FastAPI.
"""
