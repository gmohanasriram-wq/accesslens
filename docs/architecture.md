# AccessLens — Architecture

This document explains the decisions that are load-bearing: the ones where a
reasonable-looking alternative would produce a product that reports "clean" when
the truth is "unknown", or that quietly recommends removing access a person
needs. [`README.md`](../README.md) covers setup and the repository layout;
[`AccessLens_Architecture_and_Implementation_Blueprint.md`](../AccessLens_Architecture_and_Implementation_Blueprint.md)
is the specification these decisions implement.

---

## The four rules that shaped the design

Most of what follows is a consequence of four rules from the brief. They are
worth stating plainly, because every non-obvious decision below traces back to
one of them.

1. **"Unused" does not mean "unnecessary".** A break-glass role that nobody has
   used is working correctly. Its inactivity is the feature.
2. **Missing evidence is not safe.** "We could not see" and "we saw nothing" are
   different facts, and only one of them supports a conclusion.
3. **Python decides; AI explains.** Detection is deterministic and independently
   testable. The AI layer never makes the security call.
4. **A human approves every security-changing action.**

Rules 1 and 2 are the hard ones. Both are cases where the naive implementation
is *more confident* than the evidence allows, and where the wrong answer looks
like a correct one on the screen.

---

## Layers and data flow

```text
data/*.json          ingest feeds -- stand-ins for Workday, Okta, AWS, GitHub
      |
      v
ingestion/loaders    stage 1  read each source independently; reject bad records
      |
      v
ingestion/resolution stage 2  map IdP logins and account ids onto HR people
      |
      v
ingestion/normalizer stages 3-4  entitlements, events, and per-user activity slices
      |
      v
InMemoryDataset      a fully-built, immutable view of the review population
      |
      +--> models/ + db     persisted (idempotent; SQLite by default)
      |
      +--> api/             GET /api/health, GET /api/personas
      |
      +--> engine/          PHASE 2: consumes the dataset, produces findings
```

The important property of this shape is that **the engine takes the
`InMemoryDataset` and nothing else**. No database handle, no HTTP request, no
filesystem. That is what makes detection deterministically testable, and it is
why the pipeline runs happily with `session=None` — a fact the test suite uses.

Ingestion establishes *facts and their completeness*. It contains no rule from
blueprint §8 and does not know what a finding is. That line is deliberate: the
moment ingestion starts interpreting, the engine stops being testable in
isolation.

`app/core/enums.py` is a leaf module with no imports, so schemas, models and the
future engine share one set of enums without an import cycle.

---

## Decision 1 — Coverage gates the usage verdict

**This is the central modelling decision.**

Blueprint §16 requires two scenarios that a naive model gets wrong: *missing
activity logs → insufficient evidence*, and *invalid timestamp → insufficient
evidence*. A plain `activity: []` on a user record conflates three different
worlds:

| What the data says | What is true |
|---|---|
| `activity: []` | We watched, and they did nothing |
| (no telemetry file at all) | We could not watch |
| `activity: [4 events]`, 1 record rejected | We watched imperfectly |

Under rule 2 the system must not report the second and third as clean.

So coverage is modelled explicitly, not inferred:

- Each source declares a `Coverage` verdict — `COMPLETE`, `PARTIAL`, `MISSING`
  or `NOT_QUERIED` — per window, in a coverage manifest.
- Coverage is scoped **per user**, to the sources that could actually have
  observed them (`ENTITLEMENT_SOURCE_TO_ACTIVITY`, unioned with any source that
  did produce an event for them). Gina holds no AWS entitlement, so CloudTrail's
  state is not her problem; her relevant source is the proxy, and the proxy
  export was never delivered.
- `build_activity_slices` returns a determinate `UsageObservation` **only** when
  coverage is `COMPLETE`. Every other value yields `UNKNOWN`.

The gate is symmetric on purpose. It is tempting to let `PARTIAL` through as
"probably fine, they clearly used it a bit" — but that would let a truncated
export be read as well-evidenced low usage, which is exactly the false positive
rule 1 and rule 2 both exist to prevent.

The result is that **Alice and Gina have identical event counts and opposite
verdicts**, and the API exposes the coverage fields so a client cannot render
Gina's `0` as if it meant the same thing as Alice's. A UI that showed only
`observed_event_count` would call an unobserved account clean.

### Gaps are evidence

Every hole comes with a `GapReason` — `SOURCE_MISSING`, `WINDOW_TRUNCATED`,
`RECORDS_REJECTED`, `SOURCE_NOT_QUERIED`, `IDENTITY_UNMAPPED` — and free text.
`EvidenceKind.COVERAGE_STATEMENT` exists so that "we could not see X" is
recordable evidence rather than the silent absence of a row. A gap a reviewer
cannot read is a gap they will ignore.

---

## Decision 2 — The capability vocabulary must not fail silently

Rule A compares granted capabilities against observed ones. AWS actions
(`s3:GetObject`) and GitHub actions (`repo.clone`) are different vocabularies, so
`core/capabilities.py` maps both into a shared coarse `Capability` set.

The subtle part is what happens to a value that is *not* in that map, and the
answer differs by side:

- An unclassifiable **permission** shrinks the denominator. The utilisation ratio
  rises, and privilege hides.
- An unclassifiable **action** shrinks the numerator. The ratio falls, and the
  system manufactures a low-usage finding against a real person.

Both are silent corruption of the number the finding rests on. So
`capabilities_for_actions` returns `{UNKNOWN}` for an unrecognised action rather
than an empty set, and `classify_permission` does the same on the granted side.

`frozenset()` still means something precise, and the two must stay
distinguishable: `sts:GetCallerIdentity` is *deliberately* mapped to the empty
set, because it is a known action that confers no capability — it only reports
who you already are. "Known to achieve nothing" and "not known at all" are
different facts about a person's evidence.

`tests/test_capabilities.py` holds this line. No action or permission in the
fixture set may reach the `UNKNOWN` fallback, so the vocabulary cannot drift away
from the data unnoticed — a fixture author who invents an unmapped action fails
a test instead of quietly corrupting a ratio.

---

## Decision 3 — Timezones fail loudly at the boundary

Ghost-access detection compares HR termination against IdP deactivation against
downstream activity. Silent timezone drift across those three would produce false
findings, so naive datetimes are rejected at ingest (`AwareDatetime` plus a
normalising validator), and `UTCModel._normalise_datetimes` converts to UTC
uniformly.

Storage is the part that is easy to get wrong. SQLite does not preserve
timezone offsets, so a `datetime` written as aware comes back **naive** — and
Phase 2's ghost-access rule performs `event.timestamp > deactivation`, which
raises `TypeError` on a naive/aware comparison. A runtime crash in the middle of
the rule that catches deprovisioning failures.

A `UTCDateTime` `TypeDecorator` re-tags values on the way out.
`tests/test_datetime_discipline.py` proves the round trip — and reads back
through a **fresh session** on purpose, because re-reading in the writing
session returns the cached object and would pass even with the decorator
deleted.

---

## Decision 4 — "No automatic revocation" is enforced, not promised

AccessLens suggests; a human decides. Two structural choices make that hard to
violate by accident:

- **`Recommendation` has no revoke-like member.** The enum contains
  `MANUAL_REVIEW`, `SUGGEST_DOWNSCOPE_MANUAL_APPROVAL`,
  `NO_ACTION_DOCUMENT_JUSTIFICATION`, `INVESTIGATE_GHOST_ACCESS` and
  `GATHER_MORE_EVIDENCE`. A Phase 4 AI layer literally cannot express "revoke"
  using this contract.
- **The API has no write route, and a test asserts it.**
  `test_no_endpoint_can_change_anyones_access` enumerates the OpenAPI path table
  and fails if any method outside `GET`/`HEAD`/`OPTIONS` appears, or if the path
  set drifts beyond `{"/api/health", "/api/personas"}`. An accidental
  `POST /api/access/revoke` would break the product promise, and no test of the
  existing routes would notice it appear.

`RecommendationDecision` (`PENDING`/`APPROVED`/`REJECTED`/`DEFERRED`) is a
separate field from `Recommendation` deliberately: the system *suggests*, a
person *decides*, and the two must never be the same field.

---

## Decision 5 — Rejections are subtracted, not waved away

The declared-versus-parsed arithmetic for each source is:

```text
unexplained = declared_records - parsed_count - rejected_count
```

Only `unexplained > 0` means truncation. Rejections *explain* part of a
shortfall, so they are accounted for twice over: they reduce the unexplained
remainder (keeping a single bad row from reading as a truncated export, which
would degrade coverage for *every* user of that source and destroy findings the
data fully supports) and they produce per-user `RECORDS_REJECTED` gaps.

Both categories of activity rejection feed this calculation — records the loader
could not parse, and records the normalizer parsed but could not attribute to a
person. `_verdict_for_source` subtracts rejections from the shortfall, so passing
only one kind would leave the other looking like records that simply vanished.

A record that cannot be attributed to a person at all (a shared role ARN, a
service principal) is *recorded* as unattributable rather than dropped. It
degrades no individual's coverage, because it was never theirs to begin with —
but its existence is part of the dataset's record of itself.

---

## Decision 6 — Ingestion is idempotent and cites itself

Every natural key is stable, so re-running over unchanged inputs is a no-op:
`content_hash` (SHA-256 over the source files *plus* the analysis window)
short-circuits the run to `IngestStatus.SKIPPED_UNCHANGED`. The window is in the
hash because the same files analysed over a different lookback are not the same
dataset — Bob's events could fall inside one window and outside the next.

Domain rows, coverage rows, rejection rows and the run row commit **together**.
A run row that survived a rolled-back data write would claim evidence exists that
does not, and coverage rows are what a finding cites for "we could not see this".

The counts stored on the run row are taken *after* the coverage and rejection
rows are written. They are the run's permanent record of what it wrote, so
taking them earlier made every run report zero of both — an audit trail
contradicting the two tables it describes. `tests/test_ingestion.py` pins this.

A failed ingest does **not** abort startup. The process stays up so it can be
asked what went wrong: `/api/health` reports `degraded` with the reason and the
analysis routes refuse to answer. What it must never do is start *successfully*
and serve an empty review as though it were a clean one, so `dataset` stays
`None` and every route that needs it returns 503 rather than an empty list.

---

## What Phase 1 deliberately does not do

- **No detection logic.** `app/engine/` holds only `__init__.py`. Rules A–D are
  Phase 2.
- **No AI.** `app/ai/` holds only `__init__.py`. There is no LLM call anywhere in
  the codebase.
- **No write path.** No endpoint, service or model operation changes anyone's
  access.
- **No live integrations.** `data/` holds realistic structured fixtures. Nothing
  calls Workday, Okta, AWS or GitHub.

The `Finding` and `Evidence` contracts and the oracles in
`backend/tests/fixtures/oracles/expected_findings.json` are fixed now, on
purpose. The oracle was written before the engine exists so the engine can fail
honestly rather than be fitted to whatever the code happens to do. It records one
correction to its own expectations visibly (`_observed_capabilities_correction`)
rather than silently — an oracle quietly edited to match the implementation is no
longer an oracle.

---

## Known issues

**`StarletteDeprecationWarning` on every test run.** Starlette 1.7.0 deprecates
`httpx` in favour of `httpx2`, which `TestClient` triggers. The remedy is
`uv add httpx2`. It has **not** been applied: `httpx` works, the warning is
cosmetic, and adding a second HTTP client to silence a warning is precisely the
kind of unnecessary dependency rule 10 exists to prevent. Fix it when `httpx`
support is actually removed.

**The `.env` freshness sharp edge.** See the warning in
[`README.md`](../README.md#1-backend). Without a pinned
`ACCESSLENS_ANALYSIS_AS_OF`, the fixture window slides and the demo degrades from
findings to a clean report without anything visibly breaking.
