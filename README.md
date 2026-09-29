# AccessLens

Telemetry-informed access review.

A traditional access review shows *what permissions someone has*. AccessLens also
answers *what they actually used*, and *whether their access is still live after
they left*. It joins HR records, IdP state, entitlements and activity telemetry
into deterministic, explainable, audit-ready findings.

**AccessLens never revokes anything.** It produces findings for a human to act
on, and that is enforced structurally rather than by convention — see
[`docs/architecture.md`](docs/architecture.md).

---

## Status: Phase 1 (Foundation) complete

The blueprint at the repository root,
[`AccessLens_Architecture_and_Implementation_Blueprint.md`](AccessLens_Architecture_and_Implementation_Blueprint.md),
is the implementation source of truth. Phase 1 establishes the skeleton the
later phases are built on:

| Phase | Scope | State |
|---|---|---|
| **1 — Foundation** | Repository, data contracts, fixtures, ingestion, persistence, two read-only endpoints, one status page | **done** |
| 2 — Security engine | Rules A–D, structured findings | not started (`backend/app/engine/` is empty) |
| 3 — API + UI | Analysis endpoints, review dashboard, ghost-access forensics, evidence view | not started |
| 4 — AI layer | Finding explanation, adversarial questions, auditor dossier | not started (`backend/app/ai/` is empty) |

Phase 1 deliberately ships **no detection logic and no AI**. The `Finding` and
`Evidence` contracts and the expected-outcome oracles are fixed now so Phase 2
can be written test-first against a written specification rather than fitted to
whatever the code happens to do.

---

## Quickstart

Two processes: the FastAPI backend, and the Next.js frontend that reads it.

### 1. Backend

```bash
cd backend
uv venv
uv pip install -r requirements.txt

cp .env.example .env        # <- do not skip this; see below

uv run uvicorn app.main:app --host 127.0.0.1 --port 8000
```

**Copying `.env` is not optional for the bundled fixtures.** `.env` is
gitignored, and `.env.example` is the file that pins
`ACCESSLENS_ANALYSIS_AS_OF=2026-09-29T06:00:00Z`. The fixture set in `data/` is a
dated, hand-built world anchored to that instant. Without the pin, the 90-day
lookback window ends at the current time and slides forward one day at a time —
the fixtured events fall out of it one by one, and the demo quietly changes from
*"here are the findings"* to *"everyone is clean"*. That failure looks like
success, which is why it is called out here rather than left to the comments in
the file.

Leave `ACCESSLENS_ANALYSIS_AS_OF` unset for real data; a live deployment wants
the window to end at the current time.

### 2. Frontend

```bash
cd frontend
npm install
npm run dev
```

Open <http://localhost:3000>. The page fetches the backend **server-side**, so
the backend must be running and `API_BASE_URL` (default
`http://127.0.0.1:8000`) must point at it. That URL is deliberately not
`NEXT_PUBLIC_`-prefixed, so it never reaches the browser bundle and there is no
CORS surface to configure.

### 3. Tests

```bash
cd backend
uv run pytest
```

The suite runs against the real fixture set with no mocks: it loads the same
`data/` files the application does, so a change to the fixtures that breaks an
expectation fails a test rather than silently changing what the demo proves.

---

## What the backend serves

Two endpoints, both read-only.

| Endpoint | Purpose |
|---|---|
| `GET /api/health` | Not a bare liveness ping — answers "can we review anyone?" Reports ingest status, row counts, the dataset content hash, and the rejection count. |
| `GET /api/personas` | Every person in the review population with their identities, entitlements, and per-source activity coverage. |

The database is **derived**. It is rebuilt from `data/` on startup and is
gitignored; ingestion is idempotent, so a restart over unchanged inputs is a
no-op (`ingest_status: SKIPPED_UNCHANGED`). `data/` holds ingest *feeds* —
stand-ins for Workday, Okta, AWS and GitHub — not the application's storage, and
the API reads the database rather than the files.

SQLite is the default (`ACCESSLENS_DATABASE_URL`). Every model uses portable
SQLAlchemy types only, so PostgreSQL is a URL change with no code change.

---

## The fixture population

Nine personas, each mapped to a row of blueprint §16's testing matrix. The set is
built so that a naive implementation fails on specific, named people rather than
in the abstract.

| Person | The case they exist to make |
|---|---|
| `bob.chen` | Holds `AdministratorAccess` (13 capabilities), exercised 2. High privilege, low usage — a review candidate, never an automatic removal. |
| `alice.nguyen` | Break-glass / DR. Coverage is complete, her usage is a *provable* zero, and nothing should be removed: inactivity is the intended state of the role. |
| `carol.diaz` | Terminated, IdP disabled, and then GitHub activity using a token nobody revoked. Ghost access. |
| `frank.moreau` | Terminated and disabled with nothing afterwards — the negative control for Carol. |
| `dave.okonkwo` | Uses every capability he was granted. Any finding here is a false positive. |
| `erin.walsh` | High overall utilisation, but never touches the destructive half of what she holds. |
| `gina.patel` | Zero events, exactly like Alice — but her only possible source of telemetry never arrived. A hole, not a fact. |
| `ivan.petrov` | One record rejected at ingest for a truncated timestamp. The rejection is the kind of record that would have shown activity. |
| `henry.okafor` | Two Okta accounts share one login; the legacy one was never decommissioned. |

Three records are deliberately malformed and rejected. They are not noise: the
coverage arithmetic uses them to tell a truncated export apart from a single bad
row, because those two facts mean very different things about everyone else on
that source.

The expected outcome for every persona lives in
[`backend/tests/fixtures/oracles/expected_findings.json`](backend/tests/fixtures/oracles/expected_findings.json).
It is a test oracle, not product data, which is why it sits with the tests.

---

## Repository layout

```text
backend/            FastAPI application
  app/
    core/           enums, settings, capability vocabulary, time discipline
    schemas/        Pydantic contracts (input feeds and normalized domain)
    ingestion/      loaders, identity resolution, normalizer, persistence
    models/         SQLAlchemy tables
    api/            read-only routes
    engine/         Phase 2 — empty by design
    ai/             Phase 4 — empty by design
  tests/            includes fixtures/oracles/
frontend/           Next.js + TypeScript + Tailwind
data/               ingest feeds (stand-ins for the real source systems)
docs/               architecture.md
reports/            generated output; gitignored except for .gitkeep
```

`app/core/enums.py` is a leaf module with no imports, so the schemas, the models
and the future engine can all share one set of enums without an import cycle.

---

## Technology

Python 3.14 · FastAPI · SQLAlchemy 2 · Pydantic 2 · pytest · `uv`<br>
Node 24 · Next.js 16 (App Router) · React 19 · TypeScript · Tailwind 4

Tailwind 4 needs no `tailwind.config.js`; theme tokens live in CSS via
`@theme`. No technology is present that is not load-bearing — see rule 10 in the
architectural rules in [`docs/architecture.md`](docs/architecture.md).
