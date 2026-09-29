"""Ingestion: turn upstream exports into a normalized, coverage-qualified dataset.

The public surface is small on purpose. Almost everything in this package is an
implementation detail of one idea -- *read the fixtures, and be honest about what
could not be read* -- and only three things are meant to be used from outside:

* :func:`load_dataset` for callers that just want the facts;
* :class:`IngestPipeline` for callers that also want the report, persistence, or
  control over the data directory;
* :class:`InMemoryDataset`, the immutable value the Phase 2 engine consumes.

``loaders``, ``normalizer``, ``repository`` and ``resolution`` are imported
directly where needed rather than re-exported here, so that the import graph
stays readable and nothing accidentally depends on a stage it should not know
about.
"""

from app.ingestion.dataset import InMemoryDataset
from app.ingestion.pipeline import SOURCE_FILENAMES, IngestPipeline, load_dataset

__all__ = ["InMemoryDataset", "IngestPipeline", "SOURCE_FILENAMES", "load_dataset"]
