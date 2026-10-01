# AccessLens — Executive Demo Guide & Technical Audit

> **Target Audience:** VP of Security, Chief Information Security Officer (CISO), VP of Compliance / GRC, Enterprise Security Architects.  
> **Document Purpose:** Complete product walkthrough, architectural verification, live demonstration script, and demo-readiness audit based strictly on the actual code implementation.  
> **Repository Root:** `c:\Users\sriram\acsess lens`  
> **Audit Status:** Verified against actual backend Python engine, FastAPI routes, Next.js 16 frontend, and SQLite/in-memory data models.

---

## 1. Executive Summary & The Big Picture

### Simple Explanation (Zero Jargon)
Traditional identity governance tools (like SailPoint, Saviynt, or native Okta/AWS dashboards) periodically ask managers: *"Does Bob still need AWS AdministratorAccess?"*  
The manager sees the permission, has no time or context to investigate, and clicks **"Approve"**. This is called **"rubber-stamping"**, and it leaves companies full of accounts with massive, unnecessary privileges. Worse, when an employee leaves the company and their main single sign-on (SSO) account is disabled, downstream API tokens, SSH keys, or cloud credentials often remain active because no one revoked them.

**AccessLens** solves both problems by bringing **runtime activity telemetry** into the access review. It doesn't just ask *"What permissions does this person hold?"* It asks:
1. **"What did they actually do with those permissions over the last 90 days?"**
2. **"Are there dangerous permissions they were granted but never once exercised?"**
3. **"Is any credential still performing actions after the person was fired and disabled?"**
4. **"Can we actually trust our log data, or are there blind spots that make conclusions impossible?"**

### 30-Second Elevator Pitch (What to Say to Your Uncle / VP)
> *"AccessLens turns access reviews from blind rubber-stamping into evidence-backed investigations. Instead of guessing whether an engineer needs root privileges, we correlate HR status, identity provider state, granted entitlements, and actual cloud activity logs. Our deterministic engine catches over-privileged accounts, rarely used destructive permissions, duplicate directory identities, and ghost access from terminated employees. We use AI strictly as an investigative assistant to explain evidence and challenge assumptions, while preserving human authority: the system never revokes access automatically, and every finding is backed by an auditable chain of proof."*

### Key High-Level Questions Answered
1. **What is AccessLens?**  
   A telemetry-informed identity governance and deprovisioning forensics platform that combines HR records, IdP accounts, cloud entitlements, and runtime activity logs into deterministic, audit-ready security findings.
2. **What problem does it solve?**  
   - Excessive privilege accumulation ("privilege creep").
   - Rubber-stamping in periodic access reviews due to lack of usage context.
   - Ghost access / lingering credentials after employee offboarding.
   - False conclusions caused by incomplete or truncated audit logs.
   - Accidental revocation of legitimate disaster recovery / break-glass accounts.
3. **Who is the intended user?**  
   Security engineers, identity & access management (IAM) analysts, GRC / compliance managers, internal auditors, and department managers conducting quarterly access certifications.
4. **What information does it take as input?**  
   - **HR Records:** Employee status, termination dates, departments (`users_hr.json` / Workday).
   - **Identity Provider State:** Account status, logins, deactivation timestamps (`idp_state.json` / Okta).
   - **Entitlements:** Cloud roles, permissions, administrative tags (`entitlements.json` / AWS IAM, GitHub).
   - **Activity Telemetry:** Audit events, timestamps, credentials, actions (`activity_logs.json` / AWS CloudTrail, GitHub Audit).
   - **Coverage Manifest:** Declared status of telemetry feeds across the lookback window.
5. **What does it analyze?**  
   The mathematical intersection between *granted capabilities* and *observed capabilities*, the temporal sequence between *account deactivation* and *subsequent credential activity*, and the directory consistency of identity records.
6. **What does it produce?**  
   - Deterministic security findings with severity, risk, and status.
   - Comprehensive evidence chains with verifiable exhibits.
   - Forensic timelines of deprovisioning failures.
   - AI-generated structured forensic dossiers separating facts from inferences.
   - Exportable, audit-ready JSON dossiers recording human reviewer decisions.
7. **What role does AI play?**  
   The AI is an **investigative trial lawyer and explanation layer**. It translates complex technical telemetry into readable prose, highlights evidence gaps, separates facts from inferences, and drafts adversarial cross-examination questions. It is downstream of the security engine.
8. **What role does the human reviewer play?**  
   The human reviewer is the **sole decision-maker**. The reviewer evaluates the findings, inspects the exhibits, reviews the AI questions, selects an attested decision (`APPROVED`, `REJECTED`, or `DEFERRED`), inputs their audit rationale, and exports the attested dossier.
9. **What does AccessLens deliberately NOT do?**  
   - **It NEVER automatically revokes or modifies access.** There is no automated revocation endpoint in the API.
   - **It NEVER equates "unused" with "unnecessary".** Emergency and break-glass roles are explicitly protected.
   - **It NEVER invents conclusions when data is missing.** If telemetry is missing or truncated, it explicitly reports `INSUFFICIENT_EVIDENCE` instead of declaring an account clean.
   - **It NEVER allows AI to make security determinations or alter finding severities.**

---

## 2. Documentation vs. Implementation Audit (Discrepancies)

A strict audit of the actual codebase revealed significant differences between early repository documentation and the completed system:

| Topic | Documentation Claim (e.g. root README.md) | Actual Implementation Reality | Audit Notes |
|---|---|---|---|
| **Project Status** | `README.md` states: *"Phase 1 Complete. Phase 2 (Security engine) not started. Phase 3 (API + UI) not started. Phase 4 (AI layer) not started."* | **Phases 1, 2, 3, and 4 are fully implemented and verified.** | The top-level `README.md` and `backend/app/ai/README.md` were written during Phase 1 foundation setup and never updated. The engine, full API, Next.js UI, AI investigator, and end-to-end tests are complete. |
| **Rule Numbering & Architecture** | Blueprint §8 & §16 lists "Rule A", "Rule B" (low-usage privileged), "Rule C" (break-glass), and "Rule D" (ghost access). | Rules are implemented across 4 dedicated modules: `utilization.py` (Rule A: low utilization, break-glass, insufficient evidence), `privileged_usage.py` (Rule B: rarely used privileged capability subset), `duplicate_identity.py` (Rule C: duplicate IdP accounts), and `ghost_access.py` (Rule D: post-deactivation activity). | Documented in `backend/app/engine/README.md`. Unifying utilization and break-glass into `utilization.py` prevents conflicting ratio calculations. |
| **AI LLM Integration** | Blueprint mentions connecting to a real external LLM API (e.g., Gemini or OpenAI). | **Uses `MockLLMProvider` in `app/ai/provider.py`.** No external network calls to third-party LLM providers are made. | The system uses a deterministic, rule-based mock provider that outputs schema-valid `StructuredInvestigationResult` objects (`provider_info="deterministic-mock-v1"`). An abstract `LLMProvider` interface is ready for live model wiring. |
| **Finding Persistence** | `models/finding.py` defines `FindingRow` and `EvidenceRow` SQLAlchemy tables. | **The `findings` and `evidence` tables in SQLite are completely empty by design.** | Verified via `test_findings_are_derived_and_never_written_to_the_database`. Findings are computed on-the-fly as pure functional transformations of the immutable `InMemoryDataset`. Persisting them would risk stale review records. |
| **Reviewer Decision Storage** | Mentioned as part of the review workflow. | **Stored exclusively client-side in browser `sessionStorage`.** | Reviewer decisions (`PENDING`, `APPROVED`, `REJECTED`, `DEFERRED`) and rationale notes do not mutate the backend database. They are persisted across page reloads in the browser and exported via client-side JSON downloads. |
| **Auditor Dossier Cryptography** | Blueprint references audit-ready dossiers. | **Exported JSON dossiers are plaintext and NOT cryptographically signed.** | The exported dossier contains dataset content hashes and timestamps, but does not include asymmetric digital signatures or PKI certificates. |

---

## 3. Complete Data Flow

```text
RAW DATA FEEDS (data/*.json)
   │  [Workday HR, Okta IdP, AWS/GitHub Entitlements, CloudTrail/GitHub Telemetry]
   ▼
1. INGESTION & VALIDATION (app/ingestion/loaders/)
   │  • Parses JSON feeds independently
   │  • Enforces UTC aware datetimes
   │  • Rejects malformed records (quarantined with IngestRejection)
   ▼
2. IDENTITY RESOLUTION (app/ingestion/resolution.py)
   │  • IdentityResolver maps IdP logins, account IDs, and ARNs to HR user_ids
   │  • Resolves assumed-role session ARNs and credential IDs
   ▼
3. NORMALIZATION & COVERAGE GATING (app/ingestion/normalizer.py)
   │  • Maps permissions & actions into normalized Capability enum
   │  • Evaluates declared telemetry coverage vs parsed events vs rejections
   │  • Constructs ActivitySlice per user: COMPLETE, PARTIAL, MISSING, or NOT_QUERIED
   ▼
4. IN-MEMORY DATASET (app/ingestion/dataset.py: InMemoryDataset)
   │  • Immutable, validated view of population, identities, entitlements, activity slices
   │  • Rebuilt on startup; computes SHA-256 content_hash and dataset_fingerprint
   │  • Persists domain rows (users, identities, entitlements, events) to SQLite
   ▼
5. DETERMINISTIC SECURITY ENGINE (app/engine/analyzer.py: analyze())
   │  • Consumes InMemoryDataset + Settings ONLY (pure function, no DB/network)
   │  • Evaluates 4 deterministic rules in fixed order (A -> B -> C -> D)
   │  • Sorts findings stably: User-major, Severity-descending, Finding ID
   ▼
6. FINDINGS & EVIDENCE (app/schemas/domain/finding.py: Finding, Evidence)
   │  • Produces structured findings with verifiable exhibits
   │  • Enforces FORBIDDEN_CONCLUSION_PHRASES denylist
   ▼
7. ANALYSIS API (app/api/v1/analysis.py)
   │  • GET /api/analysis (Queue summary with subject metadata)
   │  • GET /api/analysis/findings/{id} (Full dossier with exhibits)
   │  • GET /api/analysis/findings/{id}/investigation (AI investigation endpoint)
   ▼
8. AI INVESTIGATION LAYER (app/ai/investigator.py: investigate_finding())
   │  • Bundles finding + subject context into immutable InvestigationPacket
   │  • Executes MockLLMProvider (deterministic structured analysis)
   │  • Enforces safety denylist (app/ai/safety.py) before returning
   ▼
9. FRONTEND PRESENTATION (frontend/app/)
   │  • Review Queue (/), Deprovisioning Forensics (/forensics), Data & Coverage (/data)
   │  • Auditor Dossier (/findings/[id]) rendering findings, exhibits, and AI panel
   ▼
10. HUMAN REVIEWER ADJUDICATION (frontend/components/ReviewerDecisionCard.tsx)
   │  • Reviewer evaluates evidence and records Attested Decision + Rationale
   │  • Saved to sessionStorage (zero backend mutation)
   ▼
11. EXPORTABLE AUDITOR DOSSIER (Client-side JSON Download)
      • Generates accesslens-dossier-{finding_id}.json containing findings, exhibits,
        AI analysis, attested decision, rationale, and timestamps.
```

### Detailed Breakdown of Every Stage

#### Stage 1: Raw Data Feeds
- **What Enters:** Four static JSON files in `data/`: `users_hr.json` (9 users), `idp_state.json` (10 accounts), `entitlements.json` (15 grants), `activity_logs.json` (44 events across AWS CloudTrail and GitHub Audit, plus coverage declarations).
- **What Happens:** Raw feeds act as stand-ins for Workday, Okta, AWS IAM, and audit log exports.
- **Why This Stage Exists:** Simulates heterogeneous enterprise IT and security systems without requiring fragile live SaaS connections during audit/evaluation.

#### Stage 2: Ingestion & Validation
- **What Enters:** Raw JSON records from `data/`.
- **What Happens:** `app/ingestion/loaders/` parses each feed independently. Pydantic raw models (`app/schemas/raw/`) validate schemas. Strict timezone validation (`app/core/time.py`) enforces aware UTC datetimes. Malformed records are captured as `IngestRejection` objects rather than crashing the process.
- **What Comes Out:** `LoadResult` containers holding valid records, manifest coverage declarations, and a list of rejections.
- **Implementing Files:**
  - `backend/app/ingestion/loaders/hr.py` (`WorkdayHRLoader`)
  - `backend/app/ingestion/loaders/idp.py` (`OktaIdPLoader`)
  - `backend/app/ingestion/loaders/entitlements.py` (`EntitlementsLoader`)
  - `backend/app/ingestion/loaders/activity.py` (`ActivityLoader`)
  - `backend/app/core/errors.py` (`IngestRejection`, `FatalIngestError`)
- **Why This Stage Exists:** An unreadable record must not crash the pipeline or vanish; it must be recorded as an audit gap.

#### Stage 3: Identity Resolution
- **What Enters:** Valid HR users and IdP accounts.
- **What Happens:** `IdentityResolver` creates bidirectional lookups between HR employee IDs (`u_bob`), usernames (`bob.chen`), IdP account IDs (`00u_bob01`), email addresses, and downstream actor strings (such as AWS ARNs and GitHub usernames).
- **What Comes Out:** A populated resolver instance capable of mapping any event actor or entitlement holder back to an HR human.
- **Implementing Files:**
  - `backend/app/ingestion/resolution.py` (`IdentityResolver`)
- **Why This Stage Exists:** Telemetry logs cite AWS ARNs (`arn:aws:iam::123456789012:user/bob.chen`) or GitHub handles (`gh_bob`), while HR cites employee IDs. Telemetry cannot be analyzed until attributed to a specific person.

#### Stage 4: Normalization & Coverage Gating
- **What Enters:** Raw records and the resolved identity map.
- **What Happens:**
  1. `core/capabilities.py` normalizes vendor-specific permissions (`s3:GetObject`, `repo.clone`) into 19 coarse `Capability` enums (`S3_READ`, `REPO_READ`).
  2. Declared record counts in the manifest are checked against parsed records and rejections:  
     $$\text{unexplained} = \text{declared} - \text{parsed} - \text{rejected}$$
  3. Per-user `ActivitySlice` instances are generated. If a user's telemetry source has missing exports or rejected records, coverage is marked `PARTIAL` or `MISSING`, and `usage_observation` is set to `UNKNOWN`. Only `COMPLETE` coverage allows an observation of `OBSERVED` or `NONE_OBSERVED`.
- **What Comes Out:** Domain objects: `User`, `Identity`, `Entitlement`, `ActivityEvent`, and `ActivitySlice`.
- **Implementing Files:**
  - `backend/app/core/capabilities.py` (`capabilities_for_actions`, `capabilities_for_permissions`)
  - `backend/app/ingestion/normalizer.py` (`normalize_users`, `normalize_identities`, `normalize_entitlements`, `normalize_events`, `build_activity_slices`)
- **Why This Stage Exists:** This is the core architectural defense against false positives. "We could not watch" (missing telemetry) must never be conflated with "we watched and saw nothing" (clean review).

#### Stage 5: In-Memory Dataset Assembly & Persistence
- **What Enters:** Normalized domain objects.
- **What Happens:**
  - Assembles `InMemoryDataset`, calculating a SHA-256 `content_hash` over the source files and the analysis lookback window.
  - Generates a cryptographic `dataset_fingerprint`.
  - Persists domain tables (`users`, `identities`, `entitlements`, `activity_events`, `coverage`, `rejections`, `ingest_runs`) into SQLite idempotently.
- **What Comes Out:** Immutable `InMemoryDataset` instance attached to `app.state.accesslens.dataset`.
- **Implementing Files:**
  - `backend/app/ingestion/dataset.py` (`InMemoryDataset`)
  - `backend/app/ingestion/pipeline.py` (`IngestPipeline.run`)
  - `backend/app/ingestion/repository.py`
  - `backend/app/db.py`
- **Why This Stage Exists:** The database stores the raw domain facts, but the security engine operates on the pure, immutable `InMemoryDataset`, ensuring zero side-effects.

#### Stage 6: Deterministic Security Engine
- **What Enters:** `InMemoryDataset` and `Settings`.
- **What Happens:**
  `analyzer.analyze()` executes four pure rule functions in fixed order (A $\rightarrow$ B $\rightarrow$ C $\rightarrow$ D):
  1. `utilization.detect_low_utilization`: Checks coverage first. Flags `INSUFFICIENT_EVIDENCE` for unmeasurable accounts (Gina, Ivan), `PROTECTED_BREAK_GLASS` for emergency roles (Alice), and `HIGH_PRIVILEGE_LOW_USAGE` for under-utilized admin roles (Bob).
  2. `privileged_usage.detect_rarely_used_privileged_permissions`: Identifies users with normal overall utilization who never touch high-risk destructive permissions (Erin, Carol).
  3. `duplicate_identity.detect_duplicate_identities`: Identifies users with multiple active accounts in the same directory provider (Henry).
  4. `ghost_access.detect_ghost_access`: Identifies post-deactivation activity for terminated employees (Carol).
- **What Comes Out:** A stably sorted list of 8 `Finding` objects with attached `Evidence` exhibits.
- **Implementing Files:**
  - `backend/app/engine/analyzer.py` (`analyze`)
  - `backend/app/engine/utilization.py` (`detect_low_utilization`, `evaluate_user`)
  - `backend/app/engine/privileged_usage.py` (`detect_rarely_used_privileged_permissions`)
  - `backend/app/engine/duplicate_identity.py` (`detect_duplicate_identities`)
  - `backend/app/engine/ghost_access.py` (`detect_ghost_access`)
- **Why This Stage Exists:** Guarantees 100% deterministic, reproducible security analysis with zero hallucination.

#### Stage 7: Analysis & Findings API
- **What Enters:** In-memory findings and stored persona projections.
- **What Happens:** Read-only FastAPI endpoints serialize findings into JSON DTOs:
  - `GET /api/analysis`: Returns the review queue with persona summaries and evidence counts.
  - `GET /api/analysis/findings/{finding_id}`: Returns the complete dossier, exhibits, subject details, and related findings.
  - `GET /api/analysis/findings/{finding_id}/investigation`: Triggers forensic analysis.
- **What Comes Out:** Strongly-typed JSON responses matching `app/schemas/api.py`.
- **Implementing Files:**
  - `backend/app/api/v1/analysis.py`
  - `backend/app/api/read_models.py`
- **Why This Stage Exists:** Exposes the review surface to the frontend while enforcing the strict absence of any write/mutating endpoints.

#### Stage 8: AI Investigation Layer
- **What Enters:** `Finding`, `PersonaSummary`, `InMemoryDataset`, and `Settings`.
- **What Happens:**
  1. `build_investigation_packet` packages context into an `InvestigationPacket`.
  2. `investigate_finding` calls `MockLLMProvider.investigate(packet)`.
  3. Generates structured output separating verified facts from inferences, citing valid exhibits, and providing adversarial questions.
  4. `validate_investigation_safety` runs output through the safety denylist.
- **What Comes Out:** Validated `StructuredInvestigationResult`.
- **Implementing Files:**
  - `backend/app/ai/packet.py`
  - `backend/app/ai/investigator.py`
  - `backend/app/ai/provider.py`
  - `backend/app/ai/safety.py`
  - `backend/app/ai/schemas.py`
- **Why This Stage Exists:** Assists human reviewers in understanding technical telemetry without allowing the model to make security conclusions or invent facts.

#### Stage 9: Frontend Review & Adjudication
- **What Enters:** Next.js Server Components fetch JSON data from FastAPI.
- **What Happens:**
  - `/` renders the review queue with 8 finding cards.
  - `/forensics` isolates deprovisioning failures (`GHOST_ACCESS`).
  - `/data` presents the audit record, coverage states, and rejected logs.
  - `/findings/[id]` displays the full dossier: subject card, finding details, exhibits, AI investigation panel, and reviewer decision card.
  - The human clicks an adjudication button (`APPROVED`, `REJECTED`, `DEFERRED`), enters their rationale, and exports the attested dossier.
- **Implementing Files:**
  - `frontend/app/page.tsx`
  - `frontend/app/forensics/page.tsx`
  - `frontend/app/data/page.tsx`
  - `frontend/app/findings/[id]/page.tsx`
  - `frontend/components/ReviewerDecisionCard.tsx`
  - `frontend/components/InvestigationPanel.tsx`
- **Why This Stage Exists:** Delivers an intuitive, accessible interface for human security reviewers to make defensible, audit-ready decisions.

---

## 4. The Data Model

### Entity-Relationship Conceptual Diagram

```text
User (HR System of Record)
 ├── Identity (IdP Accounts: Okta, Azure AD)
 │     └── [Tracks: login, status, deactivation timestamp, duplicate flags]
 ├── Entitlements (Granted Roles & Permissions: AWS IAM, GitHub)
 │     └── [Tracks: role, permissions, capabilities, risk_level, protected_role]
 ├── ActivitySlice (Observed Telemetry Window: 90 Days)
 │     ├── ActivityEvents (Individual audit actions: timestamp, action, resource, credential)
 │     ├── CoverageManifest (Per-source status: COMPLETE, PARTIAL, MISSING)
 │     └── GapRecords (Identified data holes: reason, missing source, rejected record)
 └── Findings (Deterministic Security Findings)
       ├── Evidence Exhibits (Verifiable proof items: grants, events, coverage, configs)
       └── InvestigationPacket (Forensic bundle supplied to AI)
             └── StructuredInvestigationResult (AI Analysis: facts, inferences, questions)
                   └── ReviewerDecision (Human Adjudication: status, rationale, timestamp)
```

### Core Entities & Field Specifications

#### 1. User (`app/schemas/domain/user.py` & `app/models/user.py`)
- **Purpose:** Represents the physical employee as recorded by HR (Workday).
- **Key Fields:** `id` (`u_bob`), `username` (`bob.chen`), `name` (`Bob Chen`), `email`, `department`, `employment_status` (`ACTIVE`, `TERMINATED`), `termination_date`, `termination_reason`, `hire_date`.
- **Usage:** Anchor entity for all identity mappings, entitlement grants, and review findings.

#### 2. Identity (`app/schemas/domain/identity.py` & `app/models/identity.py`)
- **Purpose:** Represents an account in a directory or identity provider (Okta).
- **Key Fields:** `account_id` (`00u_bob01`), `user_id` (`u_bob`), `provider` (`okta`), `login` (`bob.chen`), `status` (`ACTIVE`, `DISABLED`), `deactivated_at`, `deactivation_trigger`, `is_duplicate_of`.
- **Usage:** Evaluated by Rule D (Ghost Access) to determine the exact deprovisioning cutoff, and by Rule C (Duplicate Identity) to detect multiple directory accounts.

#### 3. Entitlement (`app/schemas/domain/entitlement.py` & `app/models/entitlement.py`)
- **Purpose:** Represents a permission or role granted in a downstream system (AWS IAM, GitHub).
- **Key Fields:** `entitlement_id`, `user_id`, `source` (`aws`, `github`), `role` (`AdministratorAccess`), `permissions` (raw strings), `risk_level` (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`), `protected_role` (boolean), `protection_reason`.
- **Usage:** Provides the *granted capability denominator* for Rule A and Rule B.

#### 4. ActivityEvent (`app/schemas/domain/activity.py` & `app/models/activity.py`)
- **Purpose:** Represents a single normalized runtime action observed in audit telemetry.
- **Key Fields:** `event_id` (`evt-aws-0001`), `actor` (ARN/login), `user_id`, `source` (`aws_cloudtrail`), `action` (`s3:GetObject`), `timestamp`, `credential_id` (`ghp_carol_legacy`), `denied` (boolean), `capabilities` (normalized `Capability` set).
- **Usage:** Provides the *observed capability numerator* for utilization, and the factual timeline for ghost access.

#### 5. Finding (`app/schemas/domain/finding.py` & `app/models/finding.py`)
- **Purpose:** The core output of the deterministic security engine.
- **Key Fields:** `id` (`fnd-u_bob-rule-a`), `user_id`, `type` (`FindingType`), `severity` (`Severity`), `status` (`FindingStatus`), `risk_level` (`RiskLevel`), `summary` (deterministic text), `recommendation` (`Recommendation`), `evidence` (list of `Evidence`), `evidence_completeness` (`EvidenceCompleteness`), `rules_triggered` (list of rule IDs), `created_at`.
- **Usage:** Displayed in the review queue, rendered in the auditor dossier, and fed to the AI layer.

#### 6. Evidence Exhibit (`app/schemas/domain/finding.py` & `app/models/finding.py`)
- **Purpose:** A single verifiable proof item attached to a finding.
- **Key Fields:** `evidence_id`, `finding_id`, `kind` (`ENTITLEMENT_GRANT`, `ACTIVITY_EVENT`, `TIMELINE_POINT`, `COVERAGE_STATEMENT`, `CONFIG_VALUE`, `IDENTITY_LINK`), `source`, `timestamp`, `description`, `detail` (raw structured dictionary).
- **Usage:** Allows an auditor or reviewer to verify the finding back to raw data without guessing.

#### 7. InvestigationPacket (`app/ai/packet.py`)
- **Purpose:** The immutable factual bundle provided to the AI investigator.
- **Key Fields:** `packet_id`, `finding`, `subject` (`PersonaSummary`), `analysis_as_of`, `window_start`, `window_end`, `dataset_fingerprint`, `valid_evidence_ids`.
- **Usage:** Isolates the AI from external inputs or raw DB connections, preventing prompt injection and data leakage.

#### 8. StructuredInvestigationResult (`app/ai/schemas.py`)
- **Purpose:** The structured output contract returned by the AI investigator.
- **Key Fields:** `finding_id`, `user_id`, `status` (`COMPLETED`, `INSUFFICIENT_EVIDENCE`, `ERROR`), `factual_summary`, `supporting_evidence` (list of `EvidenceCitation`), `uncertainty_and_contradictions`, `missing_or_unverified_evidence`, `evidence_vs_inference` (`FactVsInference`), `adversarial_questions`, `investigation_next_steps`, `provider_info`, `generated_at`.
- **Usage:** Rendered in `InvestigationPanel.tsx` on the dossier page.

#### 9. Reviewer Decision (`frontend/types/api.ts` & `ReviewerDecisionCard.tsx`)
- **Purpose:** The attested adjudication recorded by the human reviewer.
- **Key Fields:** `decision` (`PENDING`, `APPROVED`, `REJECTED`, `DEFERRED`), `rationale` (free-text string), `decided_at` (ISO timestamp).
- **Usage:** Managed client-side, persisted in `sessionStorage`, and embedded into the exported JSON dossier.

---

## 5. Frontend Pages & Routes

The frontend is built using Next.js 16 (App Router), React 19, and Tailwind CSS 4. It contains 4 user-facing pages:

| Page | URL | Purpose | Main Information Displayed | API / Data Source |
|---|---|---|---|---|
| **Access Review Queue** | `/` | Main dashboard & triage queue for all security findings. | Total findings count, affected user count, review window dates, ordered list of 8 finding cards with severity, status, and subjects. | `GET /api/analysis` (via `fetchAnalysis()`) |
| **Deprovisioning Forensics** | `/forensics` | Specialized investigation queue for offboarding failures. | Filtered list isolating `GHOST_ACCESS` findings where credentials remained active post-termination (Carol Diaz). | `GET /api/analysis` (filtered client-side for `type === "GHOST_ACCESS"`) |
| **Data & Coverage** | `/data` | Raw audit record, data provenance, and telemetry completeness. | Ingest health, database status, rejection counts, dataset hash, and full table of 9 personas with identities, entitlements, and coverage gap statements. | `GET /api/health` & `GET /api/personas` |
| **Auditor Dossier** | `/findings/[id]` | Comprehensive audit record for one specific finding. | Full finding details, subject profile, AI Forensic Panel, Human Reviewer Card, and complete list of verifiable exhibits. | `GET /api/analysis/findings/{id}` & `GET /api/analysis/findings/{id}/investigation` |

---

## 6. Page Deep-Dive: Home Page (`/`)

### Purpose
The entry point for security analysts. It answers: *"What needs my attention in this review period, how severe is it, and who is involved?"*

### What You See on the Screen
1. **Masthead Navigation:** Links to `Review` (`/`), `Forensics` (`/forensics`), and `Data` (`/data`).
2. **Page Heading & Lede:** Dynamic summary reading:  
   *"8 findings across 6 people, over Jul 1, 2026 to Sep 29, 2026. A finding is a reason to look at something, not an instruction to change it."*
3. **Findings Queue (8 Ordered Rows):**
   - Each row displays: Person name (`Alice Nguyen`, `Bob Chen`, `Carol Diaz`, `Erin Walsh`, `Gina Patel`, `Henry Okafor`, `Ivan Petrov`), username, department.
   - Finding classification tags: Status (`REVIEW_REQUIRED`, `PROTECTED`, `INVESTIGATION_REQUIRED`, `INSUFFICIENT_EVIDENCE`), Type (`HIGH_PRIVILEGE_LOW_USAGE`, `GHOST_ACCESS`, etc.), and Risk (`CRITICAL`, `HIGH`, `MEDIUM`).
   - Summary sentence explaining what occurred.
   - Recommended next step (`SUGGEST_DOWNSCOPE_MANUAL_APPROVAL`, `INVESTIGATE_GHOST_ACCESS`, `MANUAL_REVIEW`, `GATHER_MORE_EVIDENCE`, `NO_ACTION_DOCUMENT_JUSTIFICATION`).
   - Evidence counter badge (e.g. `8 exhibits`, `12 exhibits`).
4. **Dataset Strip (Sticky Footer):** Displays dataset content hash (`32fc732cf3d5...`), window end instant (`2026-09-29 06:00:00 UTC`), 9 people loaded, 3 rejected records, and ingest status (`SUCCEEDED_WITH_REJECTIONS`).

### Real Data vs. Static UI
- **100% Real Data:** Every finding, badge, count, and summary is dynamically fetched server-side from `GET /api/analysis`.
- **Presentation Ordering:** Rows are stably ordered by the backend: Person-major, Severity-descending (`CRITICAL` $\rightarrow$ `HIGH` $\rightarrow$ `MEDIUM` $\rightarrow$ `INFO`).

### Demonstration Script (What to Say & Click)
> **Action:** Open `http://localhost:3000/`. Point to the header.  
> **Say:** *"Welcome to AccessLens. This is our review queue. Unlike standard IAM consoles that dump thousands of raw entitlements on a manager, AccessLens presents 8 high-fidelity findings across 6 individuals over our 90-day review period. Notice the footer: every finding is anchored to a cryptographic content hash of our source data and accounts for 3 rejected records. Notice also our presentation ordering: findings are grouped per person, worst-severity first. For example, Carol Diaz has two findings: a Critical ghost-access issue and a Medium privileged permission issue. They appear together so an analyst understands her total risk profile."*

---

## 7. Page Deep-Dive: Data & Coverage (`/data`)

### Purpose
Proves the integrity of the underlying data. Answers: *"Where did this data come from, did any records fail validation, and are there blind spots in our telemetry?"*

### What You See on the Screen
1. **Ingest Panel:** Service status (`ok`), Database (`ok`), Environment (`local`), Users loaded (`9`), Rejected records (`3`), Dataset short hash.
2. **Rejection Notice:** Explicit explanation that 3 records failed validation and were quarantined rather than ignored.
3. **People, Access & Activity Evidence Table:**
   - **Person Column:** Name, username, department, and duplicate identity tags (e.g., Henry Okafor has a `duplicate account` stamp).
   - **Status Column:** Employment status (`ACTIVE`, `TERMINATED`), termination dates, and IdP account status (`okta · DISABLED · off 2026-08-15...`).
   - **Access Column:** Granted entitlements with risk badges (`CRITICAL`, `HIGH`) and protection tags (`protected`).
   - **Activity Evidence Column:** Usage observation (`OBSERVED`, `NONE_OBSERVED`, `UNKNOWN`), coverage badge (`COMPLETE`, `PARTIAL`, `MISSING`), successful event count, last active timestamp, queried sources, and highlighted **gap notices**.

### Why Data Quality Matters for Security Reviews
A naive security tool treats missing logs as zero activity and concludes: *"This person did nothing, so their access can be revoked."*  
In enterprise environments, log pipelines break, connectors lose authentication, and exports get truncated. If an IAM review tool doesn't track data completeness, a broken CloudTrail export results in stripping privileges from your entire engineering team.

### Intentionally Missing & Incomplete Values in Demo Data
1. **Gina Patel (`proxy_zscaler: MISSING`):** Gina has 0 events and an application entitlement. The Zscaler proxy export was never delivered because the connector was unauthenticated during a tenant migration. AccessLens refuses to call her clean; her coverage is `MISSING` and her usage is `UNKNOWN`.
2. **Ivan Petrov (`aws_cloudtrail: PARTIAL`):** Ivan has 4 valid events, but 1 record (`evt-aws-0028`) had a truncated timestamp (`2026-09-20T14:3`). The loader rejected that single record. Because the rejected record could have contained activity, Ivan's coverage is downgraded to `PARTIAL`, forcing an `INSUFFICIENT_EVIDENCE` finding.
3. **Orphaned Service Account (`00u_svcbackup`):** An Okta account exists with no matching HR employee. Quarantined as an unmapped identity rejection.
4. **Shared Role ARN (`role/PlatformAdmin`):** Event `evt-aws-0030` used a shared IAM role with no user session attribution. Recorded as an unattributable actor.

### Demonstration Script (What to Say & Click)
> **Action:** Click **Data** in the navigation. Scroll to Alice Nguyen, then Gina Patel.  
> **Say:** *"Here on the Data & Coverage page, we enforce our second cardinal rule: 'Missing evidence is not safe.' Compare Alice Nguyen and Gina Patel. Both show exactly zero activity events. In a traditional IAM tool, they look identical. But look at AccessLens: Alice's coverage is COMPLETE—we monitored CloudTrail for 90 days and prove she didn't use her emergency role. Gina's coverage is MISSING because the proxy log feed failed. AccessLens refuses to declare Gina inactive; it marks her usage as UNKNOWN and tells the reviewer that obtaining the missing export is required. We also visibly report 3 rejected records, including an invalid timestamp on Ivan Petrov, preventing bad data from turning into false security accusations."*

---

## 8. Page Deep-Dive: Deprovisioning Forensics (`/forensics`)

### Purpose
Dedicated workspace for investigating offboarding security failures. Answers: *"Did anyone who left the company continue to use credentials after their account was closed?"*

### What You See on the Screen
1. **Lede:** *"1 case where a credential was still usable after the account it belonged to was closed. Each one opens onto the sequence the rule recorded, in the order it happened."*
2. **Finding Card for Carol Diaz (`fnd-u_carol-rule-d`):**
   - Badges: `CRITICAL` severity, `INVESTIGATION_REQUIRED` status, `GHOST_ACCESS` type, `UNKNOWN` risk.
   - Summary: Carol's employment ended on 2026-08-14, her Okta account was disabled on 2026-08-15, but 3 successful GitHub clone actions followed using credential `ghp_carol_legacy`, plus a denied AWS attempt with `AKIACAROLKEY`.
   - Next Step: `INVESTIGATE_GHOST_ACCESS`.
   - Evidence badge: `8 exhibits`.

### Column & Field Breakdown
- **Severity (`CRITICAL`):** Post-termination access is an active breach indicator.
- **Risk Level (`UNKNOWN`):** Left `UNKNOWN` deliberately. Rule D evaluates temporal deprovisioning, not entitlement damage potential (which is Rule A/B's domain). Classifying privilege in two places causes rule conflicts.
- **Recommendation (`INVESTIGATE_GHOST_ACCESS`):** Directs the human to open a security incident rather than issuing an automated revocation.

---

## 9. Page Deep-Dive: Auditor Dossier (`/findings/[id]`)

### Purpose
The definitive courtroom dossier for a single finding. Contains every exhibit, subject metadata, AI analysis, human adjudication controls, and related findings.

### What You See on the Screen
1. **Dossier Header:** Finding ID, employee name, status badge, finding type, risk badge, summary narrative, and recommended action.
2. **"The Finding" Panel:** Metadata grid displaying Type, Severity, Status, Risk, Usage observation, Evidence completeness, Triggered rules, Creation timestamp, and Recommendation.
3. **"The Person" Panel (`SubjectPanel.tsx`):** Complete employment context, HR termination details, directory accounts, all granted entitlements, and activity slice stats.
4. **"AI Trial Lawyer — Forensic Analysis" Panel (`InvestigationPanel.tsx`):**
   - Mode banner: *"Investigative Support Only · Not an Autonomous Security Decision"*.
   - Factual summary.
   - Split view: **Verified Telemetry Facts** (green dot) vs. **Analytical Inferences** (amber dot).
   - Supporting Exhibits Cited (clickable evidence IDs).
   - Uncertainty & Coverage Gaps alert box.
   - Adversarial Cross-Examination Questions.
   - Investigative Next Steps.
   - Provider info (`deterministic-mock-v1`) and timestamp.
5. **"Human Reviewer Adjudication" Card (`ReviewerDecisionCard.tsx`):**
   - Four interactive decision buttons: `PENDING`, `APPROVED`, `REJECTED`, `DEFERRED`.
   - Rationale & audit notes textarea.
   - **"Export Auditor Dossier (.json)"** download button.
6. **"Exhibits" Panel (`Exhibit.tsx`):** Ordered list of all attached evidence items with raw JSON payload inspection.
7. **"Also Raised About This Person" Panel:** Quick-navigation links to any other findings associated with this employee.

---

## 10. The Findings Queue (Complete Inventory)

The fixture population produces **exactly 8 findings across 6 personas** (plus 2 clean control personas):

| Persona | Finding ID | Rule ID | Type | Severity | Risk | Status | Recommendation | Exhibits | Summary & Reason for Existence |
|---|---|---|---|---|---|---|---|---|---|
| **Alice Nguyen** | `fnd-u_alice-rule-a-protected` | `RULE_A_PRIVILEGE_UTILIZATION` | `PROTECTED_BREAK_GLASS` | `INFO` | `CRITICAL` | `PROTECTED` | `NO_ACTION_DOCUMENT_JUSTIFICATION` | 6 | **Disaster recovery break-glass role.** 12 capabilities granted, 0 used. Coverage COMPLETE. Proves inactivity is the intended state of emergency access. Prevents accidental removal. |
| **Bob Chen** | `fnd-u_bob-rule-a` | `RULE_A_PRIVILEGE_UTILIZATION` | `HIGH_PRIVILEGE_LOW_USAGE` | `HIGH` | `CRITICAL` | `REVIEW_REQUIRED` | `SUGGEST_DOWNSCOPE_MANUAL_APPROVAL` | 8 | **Over-privileged administrator.** Holds `AdministratorAccess` (13 capabilities), exercised only 2 (`S3_READ`, `EC2_READ`) across 4 events. Ratio 0.154 < 0.25 threshold. Review required, never auto-pruned. |
| **Carol Diaz** | `fnd-u_carol-rule-d` | `RULE_D_GHOST_ACCESS` | `GHOST_ACCESS` | `CRITICAL` | `UNKNOWN` | `INVESTIGATION_REQUIRED` | `INVESTIGATE_GHOST_ACCESS` | 8 | **Active token post-offboarding.** Terminated 2026-08-14, Okta disabled 2026-08-15, but 3 successful GitHub clones occurred using `ghp_carol_legacy`. Proves IdP disable failed to revoke downstream token. |
| **Carol Diaz** | `fnd-u_carol-rule-b` | `RULE_B_PRIVILEGED_PERMISSION_USAGE` | `RARELY_USED_PRIVILEGED_PERMISSION` | `MEDIUM` | `CRITICAL` | `REVIEW_REQUIRED` | `MANUAL_REVIEW` | 12 | **Unexercised destructive subset.** Holds AWS admin and GitHub repo admin (16 capabilities). Used 4 (ratio 0.250). Never touched `IAM_WRITE`, `KMS_WRITE`, `LOGS_WRITE`, `REPO_ADMIN`, `S3_DELETE`. Independent finding from ghost access. |
| **Erin Walsh** | `fnd-u_erin-rule-b` | `RULE_B_PRIVILEGED_PERMISSION_USAGE` | `RARELY_USED_PRIVILEGED_PERMISSION` | `MEDIUM` | `CRITICAL` | `REVIEW_REQUIRED` | `MANUAL_REVIEW` | 16 | **Narrow usage vs low usage.** Overall utilization is high (9/17 capabilities, ratio 0.529), but she never touched 6 destructive capabilities (`IAM_WRITE`, `KMS_WRITE`, `LOGS_WRITE`, `ORG_ADMIN`, `REPO_ADMIN`, `S3_DELETE`). |
| **Gina Patel** | `fnd-u_gina-rule-a-insufficient-evidence` | `RULE_A_PRIVILEGE_UTILIZATION` | `INSUFFICIENT_EVIDENCE` | `INFO` | `MEDIUM` | `INSUFFICIENT_EVIDENCE` | `GATHER_MORE_EVIDENCE` | 4 | **Missing telemetry feed.** Holds `DataPortalAdmin`. 0 events. Proxy export was never delivered. Refuses to report clean; flags missing feed as uncertainty. |
| **Henry Okafor** | `fnd-u_henry-rule-c-okta` | `RULE_C_DUPLICATE_IDENTITY` | `DUPLICATE_IDENTITY` | `MEDIUM` | `UNKNOWN` | `INVESTIGATION_REQUIRED` | `MANUAL_REVIEW` | 2 | **Orphaned duplicate directory account.** Holds two active Okta accounts (`00u_henry01` and legacy `00u_henry98-legacy`). Activity cannot be attributed to a single principal. |
| **Ivan Petrov** | `fnd-u_ivan-rule-a-insufficient-evidence` | `RULE_A_PRIVILEGE_UTILIZATION` | `INSUFFICIENT_EVIDENCE` | `INFO` | `HIGH` | `INSUFFICIENT_EVIDENCE` | `GATHER_MORE_EVIDENCE` | 4 | **Rejected record in audit feed.** Holds `PowerUserAccess`. 4 observed events, but 1 record was rejected for truncated timestamp (`2026-09-20T14:3`). Refuses to calculate ratio; flags data corruption. |
| **Dave Okonkwo** | *(None)* | *(None)* | `NO_FINDING` | — | — | — | — | — | **Negative Control 1 (Normal Active User).** Granted 4 capabilities across AWS and GitHub; exercised all 4 (ratio 1.0). Zero findings generated. |
| **Frank Moreau** | *(None)* | *(None)* | `NO_FINDING` | — | — | — | — | — | **Negative Control 2 (Clean Offboarding).** Terminated 2026-07-31, disabled same day. Zero activity after termination. Zero findings generated. |

---

## 11. All Security Rules (Deep Inspection)

### Summary Table of Deterministic Rules

| Rule Identifier | Module Name | Primary Objective | Key Input Data | Gated by Coverage? | Target Personas | Severity Assigned |
|---|---|---|---|---|---|---|
| `RULE_A_PRIVILEGE_UTILIZATION` | `utilization.py` | Detect low utilization of high-privilege roles; protect break-glass access; flag telemetry gaps. | Granted capabilities, observed capabilities, coverage status, role protection tags/patterns. | **Yes** (Strict: `COMPLETE` required for ratio; otherwise `INSUFFICIENT_EVIDENCE`) | Bob Chen, Alice Nguyen, Gina Patel, Ivan Petrov | `HIGH` (Low Usage), `INFO` (Protected & Insufficient) |
| `RULE_B_PRIVILEGED_PERMISSION_USAGE` | `privileged_usage.py` | Detect when high-risk destructive permissions are never exercised, even if overall utilization is high. | Granted capabilities, observed capabilities, `settings.privileged_capabilities`, reviewable ratio. | **Yes** (Requires `COMPLETE` coverage and $\ge 3$ events) | Erin Walsh, Carol Diaz | `MEDIUM` |
| `RULE_C_DUPLICATE_IDENTITY` | `duplicate_identity.py` | Detect multiple active accounts for a single human in the same directory provider. | IdP account records, provider name, user ID mapping. | **No** (Directory hygiene defect; ignores telemetry coverage) | Henry Okafor | `MEDIUM` |
| `RULE_D_GHOST_ACCESS` | `ghost_access.py` | Detect post-deactivation / post-termination activity by downstream credentials. | HR termination date, IdP deactivation timestamp, activity event timestamps, credential IDs. | **No** (Rests on observed events; coverage only affects completeness tag) | Carol Diaz | `CRITICAL` |

---

### Detailed Rule Specifications

#### Rule A: Privilege Utilization (`app/engine/utilization.py`)
1. **Problem Detected:** Employees holding massive cloud privileges (e.g. `AdministratorAccess`) who only use basic read/describe operations, accumulating idle risk. Also identifies emergency roles that must be protected, and unmeasured accounts that must not be judged.
2. **Conditions Required to Fire:**
   - User has granted reviewable capabilities.
   - Telemetry coverage is `COMPLETE`.
   - At least one grant is high-risk (`AdministratorAccess`, `PowerUserAccess`).
   - Observed utilization ratio $\text{used} / \text{granted} < \text{threshold}$ (default `0.25`).
   - Observed events $\ge \text{confidence floor}$ (default `3`).
   - Role is **not** protected.
3. **Data Inspected:** Entitlement permissions, normalized capabilities, CloudTrail audit events, coverage manifests.
4. **Data Deliberately NOT Used:** Denied audit events (refused attempts do not count as usage). Does not inspect job descriptions.
5. **False Positive / Negative Control Handling:**
   - If coverage is `PARTIAL` or `MISSING`, it aborts ratio calculation and emits `INSUFFICIENT_EVIDENCE` (prevents false findings on Gina and Ivan).
   - If role matches `protected_role_patterns` (e.g. `break-glass`), it diverts to `PROTECTED_BREAK_GLASS` (prevents false revocation on Alice).
   - If user exercises all capabilities (Dave Okonkwo: 4/4), ratio is 1.0 $\ge$ 0.25, emitting no finding.
6. **Tests Verifying:** `backend/tests/test_rule_a.py`.

#### Rule B: Rarely Used Privileged Permission (`app/engine/privileged_usage.py`)
1. **Problem Detected:** "Narrow usage" vs "Low usage". An engineer may use AWS daily (deploying containers, reading S3), but holds untouched destructive rights (deleting databases, creating IAM users, modifying KMS keys). A single ratio over all permissions hides this risk.
2. **Conditions Required to Fire:**
   - User holds reviewable (unprotected) grants.
   - Telemetry coverage is `COMPLETE` with $\ge 3$ events.
   - User's overall reviewable ratio is $\ge 0.25$ (the utilization rule declined to report them).
   - User holds capabilities in `settings.privileged_capabilities` (`IAM_WRITE`, `KMS_WRITE`, `LOGS_WRITE`, `S3_DELETE`, `REPO_ADMIN`, `ORG_ADMIN`).
   - At least one of those privileged capabilities has **zero observed use** in the window.
3. **Data Inspected:** Intersection of granted capabilities with configured privileged set, minus observed capabilities.
4. **Data Deliberately NOT Used:** Protected roles are excluded per-grant. Unmeasurable windows are ignored here because Rule A already spoke for them.
5. **False Positive / Negative Control Handling:** Complements Rule A strictly ($\ge 0.25$ vs $< 0.25$). Bob Chen is not double-reported here because Rule A already claimed him.
6. **Tests Verifying:** `backend/tests/test_rule_b.py`.

#### Rule C: Duplicate Identity (`app/engine/duplicate_identity.py`)
1. **Problem Detected:** Identity directory bloat. An employee has two active accounts in Okta (often an old unmigrated account alongside a new one). Audit logs cannot be reliably attributed to a single principal, and multi-factor authentication (MFA) policies are easily bypassed.
2. **Conditions Required to Fire:** A single HR person has $\ge 2$ accounts in the same `IdentityProvider` (e.g., two Okta accounts).
3. **Data Inspected:** `dataset.identities` grouped by `(provider, user_id)`.
4. **Data Deliberately NOT Used:** Telemetry events, lookback windows, and coverage manifests are completely ignored. A directory defect is a directory defect regardless of CloudTrail state.
5. **False Positive / Negative Control Handling:** Accounts across *different* providers (e.g., 1 Okta + 1 Google Workspace) are federated identities, not duplicates. Rejections for other users (like `svc.backup`) do not downgrade this user's completeness.
6. **Tests Verifying:** `backend/tests/test_rule_c.py`.

#### Rule D: Ghost Access (`app/engine/ghost_access.py`)
1. **Problem Detected:** Deprovisioning failure. An employee is terminated in HR and disabled in the IdP, but downstream API tokens, personal access tokens (PATs), or SSH keys continue to execute actions.
2. **Conditions Required to Fire:**
   - User has a deprovisioning cutoff timestamp (latest IdP deactivation timestamp, or HR termination date if no IdP account exists).
   - Successful downstream audit events occur strictly after the cutoff ($+ \text{grace window}$).
   - Successful post-deactivation events $\ge \text{threshold}$ (default `1`).
3. **Data Inspected:** HR termination dates, IdP deactivation triggers/timestamps, downstream event timestamps, credential IDs, and denied event flags.
4. **Data Deliberately NOT Used:** Denied events are recorded as evidence that credentials were live, but are **not** counted toward the threshold of successful access. Does not evaluate entitlement risk level.
5. **False Positive / Negative Control Handling:** Strict negative control tested against Frank Moreau: Frank was terminated and disabled, but had 0 events after deactivation. Zero finding generated.
6. **Tests Verifying:** `backend/tests/test_rule_d.py`.

---

## 12. Walkthrough of Demo Personas

| Persona | Employment Status | Identity Situation | Access Situation | Activity Situation | Finding(s) Generated | Demonstration Classification |
|---|---|---|---|---|---|---|
| **Bob Chen** (`bob.chen`) | `ACTIVE` | Single Okta account (`00u_bob01`), ACTIVE. | `AdministratorAccess` (AWS IAM, 13 capabilities). | 4 events in CloudTrail. Only used `S3_READ` and `EC2_READ`. Coverage COMPLETE. | `fnd-u_bob-rule-a` (`HIGH_PRIVILEGE_LOW_USAGE`) | **Privileged-Access Review Scenario** |
| **Alice Nguyen** (`alice.nguyen`) | `ACTIVE` | Single Okta account (`00u_alice01`), ACTIVE. | `break-glass-emergency-admin`, `disaster-recovery-operator` (12 capabilities). | 0 events. Coverage COMPLETE. Usage is determinate `NONE_OBSERVED`. | `fnd-u_alice-rule-a-protected` (`PROTECTED_BREAK_GLASS`) | **Protected / Break-Glass Scenario** |
| **Carol Diaz** (`carol.diaz`) | `TERMINATED` (resigned 2026-08-14) | Okta account disabled 2026-08-15 09:12 UTC (`hr_termination`). | `AdministratorAccess` (AWS), `repo:admin` (GitHub) (16 capabilities). | 3 successful GitHub clones after disable using `ghp_carol_legacy`. 1 denied AWS attempt using `AKIACAROLKEY`. | `fnd-u_carol-rule-d` (`GHOST_ACCESS`) & `fnd-u_carol-rule-b` (`RARELY_USED_PRIVILEGED_PERMISSION`) | **Ghost-Access / Deprovisioning Breach Scenario** |
| **Erin Walsh** (`erin.walsh`) | `ACTIVE` | Single Okta account (`00u_erin01`), ACTIVE. | `AdministratorAccess` (AWS), `org:admin` (GitHub) (17 capabilities). | 10 events. Active daily user (ratio 0.529). Never used 6 destructive capabilities. | `fnd-u_erin-rule-b` (`RARELY_USED_PRIVILEGED_PERMISSION`) | **Narrow-Usage / Destructive-Subset Scenario** |
| **Gina Patel** (`gina.patel`) | `ACTIVE` | Single Okta account (`00u_gina01`), ACTIVE. | `DataPortalAdmin` (Application, 1 capability). | 0 events. Telemetry source (`proxy_zscaler`) was never delivered. Coverage MISSING. | `fnd-u_gina-rule-a-insufficient-evidence` (`INSUFFICIENT_EVIDENCE`) | **Insufficient-Evidence / Missing-Feed Scenario** |
| **Henry Okafor** (`henry.okafor`) | `ACTIVE` | **Two Okta accounts:** `00u_henry01` (MFA) and `00u_henry98-legacy` (no MFA). | Engineering, AWS read-only (4 capabilities). | 4 events across AWS and GitHub. Utilization normal (0.75). | `fnd-u_henry-rule-c-okta` (`DUPLICATE_IDENTITY`) | **Duplicate-Identity / Directory-Hygiene Scenario** |
| **Ivan Petrov** (`ivan.petrov`) | `ACTIVE` | Single Okta account (`00u_ivan01`), ACTIVE. | `PowerUserAccess` (AWS, 10 capabilities). | 4 events visible, but 1 record rejected at ingest for truncated timestamp. Coverage PARTIAL. | `fnd-u_ivan-rule-a-insufficient-evidence` (`INSUFFICIENT_EVIDENCE`) | **Corrupted-Data / Ingest-Rejection Scenario** |
| **Dave Okonkwo** (`dave.okonkwo`) | `ACTIVE` | Single Okta account (`00u_dave01`), ACTIVE. | SupportReadOnlyAccess, repo:read (4 capabilities). | 8 events. Used all 4 capabilities granted (ratio 1.0). Coverage COMPLETE. | **None (`NO_FINDING`)** | **Negative Control Scenario (Legitimate Active User)** |
| **Frank Moreau** (`frank.moreau`) | `TERMINATED` (redundancy 2026-07-31) | Okta account disabled 2026-07-31 18:30 UTC. | Finance access (3 capabilities). | 5 events prior to termination; 0 events after deactivation. Coverage COMPLETE. | **None (`NO_FINDING`)** | **Negative Control Scenario (Clean Deprovisioning)** |

---

## 13. Walkthrough of Findings: Facts $\rightarrow$ Evidence $\rightarrow$ AI $\rightarrow$ Decision

### Concrete Walkthrough 1: Bob Chen (`fnd-u_bob-rule-a`)
1. **Raw Facts:** Bob holds AWS `AdministratorAccess`. In CloudTrail over 90 days, we observe 4 successful events: `s3:ListBucket`, `s3:GetObject`, `ec2:DescribeInstances`, and `sts:GetCallerIdentity`.
2. **Deterministic Rule (`utilization.py`):** Translates permissions into 13 capabilities. Translates events into 2 observed capabilities (`S3_READ`, `EC2_READ`). `sts:GetCallerIdentity` confers no capability. Ratio is $2/13 = 0.154$. Coverage is `COMPLETE`. $4 \text{ events} \ge 3$ confidence floor. $0.154 < 0.25$ threshold. Role is not protected.
3. **Finding Emitted:** `HIGH_PRIVILEGE_LOW_USAGE` (Severity: `HIGH`, Status: `REVIEW_REQUIRED`, Recommendation: `SUGGEST_DOWNSCOPE_MANUAL_APPROVAL`).
4. **Evidence Attached (8 Exhibits):**
   - `ev-u_bob-review-grant-1`: `AdministratorAccess` confers 13 capabilities, 2 used.
   - `ev-u_bob-review-aws_evt-aws-0001` through `0004`: Successful read calls.
   - `ev-u_bob-review-coverage`: CloudTrail coverage COMPLETE.
   - `ev-u_bob-review-thresholds`: Threshold 0.25 applied.
   - `ev-u_bob-review-utilization`: 2 of 13 exercised, 11 never exercised.
5. **AI Investigation (`investigator.py`):**
   - Verified Facts: 4 events observed with COMPLETE coverage; role is `AdministratorAccess`.
   - Inferences: Observed routine work utilized a small read-only subset of capabilities.
   - Adversarial Question: *"Are unexercised high-risk permissions required for emergency, quarterly, or disaster-recovery tasks?"*
6. **Human Decision (`ReviewerDecisionCard.tsx`):** Manager clicks `APPROVED` (approving downscoping to ReadOnly), enters rationale: *"Consulted with Platform lead; Bob only needs ReadOnly for monitoring"*, and exports the dossier.

### Concrete Walkthrough 2: Alice Nguyen (`fnd-u_alice-rule-a-protected`)
1. **Raw Facts:** Alice holds `break-glass-emergency-admin`. In CloudTrail over 90 days, we observe 0 events.
2. **Deterministic Rule (`utilization.py`):** Coverage is `COMPLETE`, so usage is a determinate `NONE_OBSERVED`. The ratio is 0.000. However, the role is matched against `protected_role_patterns` (`break-glass`).
3. **Finding Emitted:** `PROTECTED_BREAK_GLASS` (Severity: `INFO`, Status: `PROTECTED`, Recommendation: `NO_ACTION_DOCUMENT_JUSTIFICATION`).
4. **Evidence Attached (6 Exhibits):** Entitlement grant, protection policy basis (`always_protected_roles`), COMPLETE coverage statement, and zero-utilization arithmetic.
5. **AI Investigation:** Verified Fact: Role is tagged emergency break-glass. Inference: Absence of routine activity proves emergency role is not being abused for daily work. Adversarial Question: *"When was this emergency role last exercised in a scheduled disaster recovery drill?"*
6. **Human Decision:** Reviewer clicks `APPROVED` (affirming no action needed) and documents drill schedule.

### Concrete Walkthrough 3: Carol Diaz (`fnd-u_carol-rule-d`)
1. **Raw Facts:** Carol was terminated in HR on 2026-08-14 17:00 UTC. Her Okta account was disabled on 2026-08-15 09:12 UTC. On 2026-08-19 and 2026-09-11, GitHub recorded successful `repo.clone` calls using `ghp_carol_legacy`. On 2026-08-16, an AWS call using `AKIACAROLKEY` was denied.
2. **Deterministic Rule (`ghost_access.py`):** Calculates deprovisioning cutoff at 2026-08-15 09:12 UTC. Finds 3 successful GitHub events after cutoff. Finds 1 denied AWS event. Threshold is $\ge 1$.
3. **Finding Emitted:** `GHOST_ACCESS` (Severity: `CRITICAL`, Status: `INVESTIGATION_REQUIRED`, Recommendation: `INVESTIGATE_GHOST_ACCESS`).
4. **Evidence Attached (8 Exhibits):** Timeline points for termination and Okta disable, activity events for post-disable GitHub clones, denied AWS call, and coverage tallies.
5. **AI Investigation:** Verified Fact: Downstream token activity continued after central account was disabled. Inference: Downstream PAT persisted after IdP deactivation. Adversarial Question: *"Was this downstream token generated through a self-service personal access mechanism?"*
6. **Human Decision:** Incident Commander clicks `APPROVED`, enters incident ticket number `#SEC-8821`, and exports dossier for legal/forensics.

---

## 14. The AI Layer & Safety Boundaries

### Exact Implementation Details
The AI layer is located in `backend/app/ai/`. It consists of:
- `schemas.py`: Pydantic contracts for `StructuredInvestigationResult`, `FactVsInference`, and `EvidenceCitation`.
- `packet.py`: `InvestigationPacket` builder.
- `provider.py`: `LLMProvider` abstract base class and `MockLLMProvider`.
- `safety.py`: Post-generation safety validation and denylist enforcement.
- `investigator.py`: Coordinator executing provider and safety validation.

### Real LLM Call Reality
> **CRITICAL DEMO FACT:** The current implementation uses a **deterministic mock provider** (`MockLLMProvider` returning `provider_info="deterministic-mock-v1"`) and **does NOT yet make a real external model call** (no OpenAI, Gemini, or Claude API calls).  
> What would change when a real provider is connected: A concrete implementation of `LLMProvider` would make an HTTPS call with structured JSON output enforcement. The rest of the system—the `InvestigationPacket`, the safety validator, the API, and the Next.js UI—is already fully wired and would remain identical.

### Safety Enforcements (`backend/app/ai/safety.py`)
Every AI-generated output is scanned against strict programmatic guardrails before being returned. If a violation is found, `validate_investigation_safety` raises `SafetyViolationError`:
1. **No Revocation Directives:** Blocks phrases matching `revoke`, `remove access`, `disable account`, `deprovision immediately`. (Permits factual retrospective phrases like *"token was not revoked"* in ghost access).
2. **No Necessity Claims:** Blocks words like `unnecessary`, `no longer needed`, `not needed`, `safe to remove`, `is necessary`.
3. **No Severity Re-grading:** Blocks attempts to re-score or downgrade finding severities (`severity should be`, `regrade to`, `upgrade to`).
4. **No Assertions on Incomplete Coverage:** If telemetry coverage is `PARTIAL` or `MISSING`, blocks definitive statements like `has not used any`, `did not use`, `zero events recorded`, `no activity`.
5. **No Hallucinated Evidence:** Validates every cited `evidence_id` against `packet.valid_evidence_ids`. If the AI cites an ID not attached by the deterministic engine, it is rejected.

---

## 15. The Human Reviewer & Exportable Dossier

### Reviewer Workflow (`frontend/components/ReviewerDecisionCard.tsx`)
1. Reviewer navigates to a finding dossier (`/findings/[id]`).
2. Evaluates the finding, exhibits, and AI cross-examination questions.
3. Selects an attested decision:
   - **`PENDING`**: Awaiting review.
   - **`APPROVED`**: Concurs with the finding's recommendation.
   - **`REJECTED`**: Disagrees with recommendation; keeps access as-is.
   - **`DEFERRED`**: Postpones review pending further evidence/inquiry.
4. Enters audit notes in the rationale textarea.
5. Decision and rationale are saved instantly to the browser's `sessionStorage` (`accesslens_decision_{id}`, `accesslens_rationale_{id}`).

### Exportable Auditor Dossier
Clicking **"Export Auditor Dossier (.json)"** triggers a client-side download of `accesslens-dossier-{finding_id}.json`.
- **What it Contains:**
  - `dossier_version`: `"1.0"`
  - `finding`: Full deterministic finding with all exhibits.
  - `subject`: Complete persona profile and entitlement history.
  - `investigation`: The structured AI forensic result.
  - `reviewer_decision`: Attested choice (`APPROVED`, etc.).
  - `reviewer_rationale`: Human audit notes.
  - `decided_at`: ISO timestamp of decision.
  - `exported_at`: ISO timestamp of export generation.
- **Cryptographic Status:** The dossier is **NOT cryptographically signed**. It contains dataset content hashes and timestamps, but does not use digital signatures.

---

## 16. Backend API Reference

The backend exposes **5 read-only HTTP endpoints** under `/api`:

| Method | Path | Purpose | Input / Parameters | Output Schema | Used By |
|---|---|---|---|---|---|
| `GET` | `/api/health` | Readiness & ingest health check. | None | `HealthResponse` (status, database, users_loaded, ingest_status, content_hash, rejections) | `DatasetStrip`, `/data` page, k8s probes |
| `GET` | `/api/personas` | Complete review population with entitlements & coverage. | None | `PersonaListResponse` (count, content_hash, personas list) | `/data` page, `DatasetStrip` |
| `GET` | `/api/analysis` | Complete review queue of security findings. | None | `AnalysisResponse` (dataset fingerprint, window dates, rejections, findings summaries) | Home page (`/`), Forensics page (`/forensics`) |
| `GET` | `/api/analysis/findings/{finding_id}` | Full auditor dossier for a specific finding. | `finding_id` (path string) | `FindingDossierResponse` (full finding, exhibits, subject details, related findings) | Dossier page (`/findings/[id]`) |
| `GET` | `/api/analysis/findings/{finding_id}/investigation` | AI forensic investigation analysis for a finding. | `finding_id` (path string) | `StructuredInvestigationResult` (factual summary, facts vs inferences, questions, next steps) | Dossier page (`InvestigationPanel.tsx`) |

*Security Invariant:* There are **zero mutating endpoints** (`POST`, `PUT`, `DELETE`, `PATCH`). This is enforced by test `test_no_endpoint_can_change_anyones_access`.

---

## 17. Storage & Persistence Reality

- **Database Engine:** SQLite via SQLAlchemy (`sqlite+pysqlite:///./accesslens.db`). Portable schema allows pointing to PostgreSQL via `ACCESSLENS_DATABASE_URL` with zero code changes.
- **What is Persisted in SQLite:** Ingested domain data only: `users`, `identities`, `entitlements`, `activity_events`, `coverage`, `rejections`, and `ingest_runs`.
- **What is NOT Persisted in SQLite:**
  - `findings` and `evidence` tables stay at **0 rows**. Findings are computed on-the-fly in memory.
  - AI investigation results are generated dynamically in memory.
  - Human reviewer decisions are stored in client-side `sessionStorage`.

---

## 18. Real vs. Demo Capabilities Matrix

| Capability | Current State | Explanation |
|---|---|---|
| **Deterministic Security Analysis** | **REAL** | Fully functional Python engine (`utilization.py`, `privileged_usage.py`, `duplicate_identity.py`, `ghost_access.py`) tested with 374 passing unit tests. |
| **Identity & Access Data** | **DEMO / FIXTURE** | Hand-crafted JSON fixture files in `data/` anchored to `2026-09-29T06:00:00Z`. |
| **Deterministic Rules** | **REAL** | Strict mathematical set logic and temporal predicates. |
| **AI Investigation Layer** | **SIMULATED / MOCK** | Uses `MockLLMProvider` delivering structured mock dossiers. Framework and safety layers are real; external LLM calls are not yet connected. |
| **Real LLM Integration** | **NOT CONNECTED** | Abstract interface exists; no real API tokens or network calls are active. |
| **AI Safety Boundaries** | **REAL** | Real regex and phrase scanners in `safety.py` enforcing denylists. |
| **Human Adjudication** | **REAL (SESSION)** | Interactive UI allowing review decisions and rationale entry. |
| **Reviewer Persistence** | **SESSION ONLY** | Stored in browser `sessionStorage`; no database write-back. |
| **Real Connectors (Okta, AWS)** | **NOT IMPLEMENTED** | Feeds are read from local JSON files, not live API connectors. |
| **Automated Revocation** | **DELIBERATELY ABSENT** | Intentionally excluded from architecture; a human must approve every change. |
| **Auditor Dossier Export** | **REAL** | Downloads structured JSON dossiers client-side (unsigned). |

---

## 19. 10–15 Minute Executive Demo Story

### Step 1: Opening (30 Seconds)
- **URL:** Open browser to `http://localhost:3000/`.
- **Say:** *"Every enterprise spends hundreds of thousands of dollars on quarterly access reviews, yet security teams still suffer from rubber-stamping and ghost access. Managers approve access simply because they don't know what permissions their people actually use. AccessLens solves this by bringing runtime activity telemetry into the review."*

### Step 2: The Review Queue & Core Architecture (2 Minutes)
- **URL:** `http://localhost:3000/`
- **Point at:** The 8 finding rows, severity badges, and sticky footer.
- **Say:** *"Here is our review queue. Over a 90-day lookback window anchored to our dataset fingerprint in the footer, our deterministic Python engine evaluated HR state, Okta identity, and CloudTrail/GitHub logs. It surfaced exactly 8 high-fidelity findings across 6 employees. Notice our first architectural guarantee: findings are ordered per person, worst-severity first. Notice also that AccessLens suggests actions, but never revokes access automatically."*

### Step 3: Data Quality & Coverage Integrity (2 Minutes)
- **URL:** Click **Data** in the top navigation (`/data`).
- **Point at:** Rejection count (`3 rejected records`), Gina Patel's row, and Ivan Petrov's row.
- **Say:** *"Before trusting a security finding, an auditor must trust the data. In the real world, log feeds break. Look at Gina Patel: she has 0 events, but her coverage is marked MISSING because our Zscaler proxy export failed. A naive tool would report her as clean; AccessLens reports her as UNKNOWN and withholds judgment. Look at Ivan Petrov: one CloudTrail event had a malformed timestamp. We quarantined it, downgraded his coverage to PARTIAL, and flagged an audit gap instead of making a false accusation."*

### Step 4: The Break-Glass Protection Case (2 Minutes)
- **URL:** Click **Review** (`/`), then click Alice Nguyen (`fnd-u_alice-rule-a-protected`).
- **Point at:** Status `PROTECTED`, Usage `NONE_OBSERVED`, and Summary.
- **Say:** *"Here is our first core scenario: Alice Nguyen. Alice holds an emergency Disaster Recovery admin role. In our 90-day window, our telemetry proves she had zero events. In a standard tool, she would be flagged for revocation. But our engine enforces our cardinal rule: 'Unused is not unnecessary.' Her role is tagged as break-glass, so AccessLens flags it as PROTECTED with INFO severity, ensuring emergency access is never accidentally pruned."*

### Step 5: Over-Privileged Low-Usage (2 Minutes)
- **URL:** Click **Review** (`/`), then click Bob Chen (`fnd-u_bob-rule-a`).
- **Point at:** Summary, Risk `CRITICAL`, Severity `HIGH`, Exhibits list.
- **Say:** *"Next, Bob Chen. Bob holds full AWS AdministratorAccess—13 distinct capabilities. But our telemetry shows he only ever ran S3 read and EC2 describe actions. His observed utilization is 15.4%, well below our 25% threshold. We generate a HIGH severity finding recommending manual downscoping to a read-only role."*

### Step 6: The AI Trial Lawyer Layer (2 Minutes)
- **URL:** Scroll down on Bob Chen's dossier page to the **AI Trial Lawyer** panel.
- **Point at:** Split view: *Verified Telemetry Facts* vs *Analytical Inferences*, and the *Adversarial Cross-Examination Questions*.
- **Say:** *"Now observe our AI layer. The AI does not make the security decision—Python made the finding. The AI acts as an investigative assistant. Look at this split: it separates verified telemetry facts from inferences. Down here, it drafts adversarial questions: 'Are unexercised permissions required for quarterly DR drills?' This equips the manager to conduct a meaningful review rather than rubber-stamping."*

### Step 7: Deprovisioning Forensics & Ghost Access (2 Minutes)
- **URL:** Click **Forensics** in the navigation (`/forensics`), then click Carol Diaz (`fnd-u_carol-rule-d`).
- **Point at:** Timeline exhibits in the dossier.
- **Say:** *"Now, our most critical security finding: Carol Diaz. Carol resigned on August 14. Her Okta account was disabled on August 15. But look at our exhibits: on August 19, four days after her Okta account was shut down, she successfully executed Git clones using a personal access token that was never revoked. This is Ghost Access—the deprovisioning gap that leads to major breaches. AccessLens caught it by correlating HR, IdP, and GitHub audit logs."*

### Step 8: Human Decision & Dossier Export (1 Minute)
- **URL:** Scroll to the **Human Reviewer Adjudication** card on Carol Diaz's page.
- **Action:** Click **Approve Recommendation**, type into rationale: *"Opening incident ticket SEC-8821 to revoke GitHub PAT"*, and click **Export Auditor Dossier (.json)**.
- **Say:** *"Finally, the human decision. AccessLens never revokes automatically. The reviewer reviews the evidence, selects an attested decision, enters their rationale, and exports this complete, audit-ready JSON dossier for compliance and legal records."*

---

## 20. "Do NOT Say This" (Misleading Claims to Avoid)

| What NOT to Say | Why It Is Misleading | What to Say Instead |
|---|---|---|
| *"The AI automatically revokes unnecessary permissions."* | AccessLens has zero write or revocation capabilities by architectural design. | *"AccessLens generates evidence-backed recommendations for a human reviewer to approve; it never modifies permissions."* |
| *"We are pulling live data from our production Okta and AWS tenants."* | Current deployment runs off static, dated JSON fixture feeds in `data/`. | *"We are demonstrating against a realistic, dated multi-source enterprise fixture set anchored to a fixed analysis window."* |
| *"Our AI model independently detected these security risks."* | Detection is 100% deterministic Python logic. The AI only explains findings. | *"Detection is entirely deterministic and reproducible in Python; the AI acts strictly as an investigative assistant and counsel."* |
| *"The AI re-evaluates the severity of findings based on context."* | The AI safety layer strictly forbids altering or re-grading deterministic severities. | *"The deterministic engine sets severity and risk; the AI is prohibited from altering those ratings."* |
| *"Reviewer decisions are stored permanently in our database."* | Reviewer decisions are currently stored client-side in browser `sessionStorage`. | *"Decisions are recorded in the reviewer's session and exported as audit-ready JSON dossiers; they do not alter backend state."* |
| *"The exported dossier is cryptographically signed with our PKI."* | The exported JSON contains hashes and timestamps, but no cryptographic signature. | *"The exported dossier contains cryptographic fingerprints of the source dataset and timestamps, providing an audit trail."* |

---

## 21. Executive Questions & Answers (VP / CISO Level)

#### 1. What problem are you actually solving?
- **Short Answer:** Preventing rubber-stamping in access reviews and catching lingering ghost credentials after employees leave.
- **Detailed Answer:** Traditional IAM tools show what permissions people have, leading managers to blindly approve them. AccessLens correlates granted access with 90 days of runtime telemetry to show what was actually used, protecting break-glass roles while exposing unused privileges and post-termination token activity.
- **Where to Demo:** Bob Chen (`/findings/fnd-u_bob-rule-a`) and Carol Diaz (`/forensics`).

#### 2. How is this different from SailPoint, Saviynt, or Okta Access Requests?
- **Short Answer:** SailPoint manages entitlements; AccessLens analyzes runtime usage and audit logs.
- **Detailed Answer:** Legacy IGA tools look at static group memberships and directory attributes. They have no visibility into CloudTrail or GitHub activity logs, so they cannot distinguish an active admin from an idle admin or catch an unrevoked API key. AccessLens is telemetry-informed.
- **Where to Demo:** Compare Bob Chen (low usage) vs Dave Okonkwo (full usage) on `/data`.

#### 3. Where does your evidence come from?
- **Short Answer:** Workday (HR), Okta (IdP), AWS IAM / GitHub (Entitlements), and CloudTrail / GitHub Audit (Activity).
- **Detailed Answer:** The platform ingests feeds across workforce identity, directory state, entitlement grants, and audit logs. Every finding includes an exhibit list citing specific timestamps, event IDs, and raw log payloads.
- **Where to Demo:** The "Exhibits" panel on `/findings/fnd-u_bob-rule-a`.

#### 4. What happens when log data is incomplete or corrupted?
- **Short Answer:** AccessLens reports `INSUFFICIENT_EVIDENCE` and withholds judgment; it never assumes silence means safety.
- **Detailed Answer:** We enforce strict coverage manifests. If a feed is missing (Gina Patel) or has corrupted timestamps (Ivan Petrov), coverage drops to `MISSING` or `PARTIAL`. The engine suppresses utilization ratios and tells the reviewer to gather missing logs.
- **Where to Demo:** Gina Patel and Ivan Petrov on `/data`.

#### 5. Why use AI here if detection is deterministic?
- **Short Answer:** To translate complex cloud logs into plain English and challenge the human reviewer with adversarial questions.
- **Detailed Answer:** Telemetry logs are noisy and hard for non-technical managers to interpret. The AI layer synthesizes the facts, clearly separates verified telemetry from inferences, and drafts cross-examination questions to prevent rubber-stamping.
- **Where to Demo:** The "AI Trial Lawyer" panel on `/findings/fnd-u_bob-rule-a`.

#### 6. Why not let the AI make the security decision?
- **Short Answer:** Security decisions must be reproducible, defensible, and legally accountable.
- **Detailed Answer:** LLMs can hallucinate and are non-deterministic. An access review finding must be defensible to SOC2 or ISO auditors months later. Python provides mathematical determinism; humans provide legal and operational accountability.
- **Where to Demo:** Architecture banner in `InvestigationPanel.tsx`.

#### 7. How do you prevent AI hallucinations?
- **Short Answer:** Through strict programmatic safety guardrails and evidence citation validation.
- **Detailed Answer:** The AI receives an immutable `InvestigationPacket` containing only verified facts. Our post-generation safety layer scans all text against denylists, blocking unauthorized revocation directives, necessity claims, and any cited evidence ID not in the packet.
- **Where to Demo:** `backend/app/ai/safety.py` code inspection.

#### 8. How do you detect ghost access?
- **Short Answer:** By comparing IdP deactivation timestamps against subsequent downstream activity.
- **Detailed Answer:** Rule D establishes the deprovisioning cutoff from Okta or HR. It scans downstream logs for successful actions occurring after that instant. If a token or key continues to execute actions, it triggers a Critical `GHOST_ACCESS` finding.
- **Where to Demo:** Carol Diaz on `/forensics`.

#### 9. How do you handle break-glass / emergency accounts?
- **Short Answer:** By explicitly recognizing that "unused does not mean unnecessary."
- **Detailed Answer:** Break-glass roles are meant to sit idle until a disaster occurs. AccessLens checks role names and tags against configured break-glass policies. When an emergency role shows zero usage, it generates a `PROTECTED_BREAK_GLASS` finding with `INFO` severity, explicitly recommending no pruning.
- **Where to Demo:** Alice Nguyen on `/findings/fnd-u_alice-rule-a-protected`.

#### 10. How do you handle duplicate directory identities?
- **Short Answer:** Rule C groups directory accounts by human user and flags multiple accounts within the same provider.
- **Detailed Answer:** If a person has multiple active accounts in Okta (e.g. Henry Okafor holding an active account and an unmigrated legacy account), Rule C flags it as `INVESTIGATION_REQUIRED` because audit logs cannot be uniquely attributed.
- **Where to Demo:** Henry Okafor on `/findings/fnd-u_henry-rule-c-okta`.

#### 11. How would this integrate with enterprise systems in production?
- **Short Answer:** By replacing the local JSON loaders with API connectors to Workday, Okta, AWS EventBridge/S3, and GitHub.
- **Detailed Answer:** The pipeline uses an abstract `BaseLoader` interface. Production connectors would pull batches from Okta System Log, AWS S3/CloudWatch, and Workday APIs, feeding the same normalization and resolution pipeline.
- **Where to Demo:** `backend/app/ingestion/loaders/` folder structure.

#### 12. What is deterministic vs. what is AI?
- **Short Answer:** Ingestion, coverage arithmetic, and security rules are deterministic; narrative synthesis and cross-examination questions are AI.
- **Detailed Answer:** Everything that generates a finding, assigns a severity, evaluates a ratio, or gates coverage is 100% deterministic Python. The AI is strictly an explanatory and questioning overlay.
- **Where to Demo:** Root layout and `backend/app/engine/`.

#### 13. What happens if the AI provider fails or times out?
- **Short Answer:** The finding and exhibits remain completely intact; the AI panel falls back to an error state gracefully.
- **Detailed Answer:** In `app/ai/investigator.py`, model exceptions are caught and return an `ERROR` status result. The finding, evidence exhibits, and human decision card continue to function with zero disruption.
- **Where to Demo:** `backend/app/ai/investigator.py:41-65`.

#### 14. How do you audit reviewer decisions?
- **Short Answer:** By generating exportable JSON dossiers recording the reviewer's decision, rationale, and timestamps.
- **Detailed Answer:** When a reviewer completes an evaluation, clicking "Export Auditor Dossier" generates a JSON record containing the complete finding, exhibits, AI analysis, reviewer choice, and audit notes.
- **Where to Demo:** `ReviewerDecisionCard.tsx` export button.

#### 15. What is currently mocked in this deployment?
- **Short Answer:** The upstream SaaS connectors and the external LLM API call.
- **Detailed Answer:** Data feeds are local JSON fixtures representing real formats, and the AI layer uses a deterministic mock provider. The data models, security engine, REST API, safety filters, and Next.js frontend are real and fully functional.
- **Where to Demo:** Table in Section 18 of this guide.

#### 16. What would you build next for an enterprise production release?
- **Short Answer:** Live SaaS connectors, PostgreSQL storage, webhook alerts, and live LLM integration with ephemeral tokens.
- **Detailed Answer:** 
  1. Live ingestion workers for Okta, AWS EventBridge, and GitHub Webhooks.
  2. Persistent reviewer decision tables in PostgreSQL.
  3. Live LLM provider connecting to Google Gemini 1.5 Pro via structured JSON outputs.
  4. Cryptographic signing of exported auditor dossiers via AWS KMS or HashiCorp Vault.
- **Where to Demo:** Architecture roadmap discussion.

#### 17. Can this tool be used to achieve SOC2 / ISO 27001 compliance?
- **Short Answer:** Yes, it directly satisfies CC6.2, CC6.3 (user access reviews), and CC6.5 (deprovisioning).
- **Detailed Answer:** SOC2 requires periodic user access reviews and timely revocation of terminated access. AccessLens produces mathematical proof of reviews and catches deprovisioning gaps before external auditors find them.
- **Where to Demo:** Dossier export on Carol Diaz.

#### 18. Why is the analysis window anchored to September 2026?
- **Short Answer:** To guarantee deterministic test reproducibility across all machines and time.
- **Detailed Answer:** The fixture set is anchored to `2026-09-29T06:00:00Z`. If we used the live wall clock, the 90-day lookback window would slide forward daily, causing fixture events to fall out and findings to disappear. Pinning `ACCESSLENS_ANALYSIS_AS_OF` ensures repeatable audits.
- **Where to Demo:** `.env.example` and `backend/app/core/config.py`.

#### 19. How do you handle service accounts and non-human identities?
- **Short Answer:** Unmapped service principals are quarantined and recorded, but do not degrade human coverage.
- **Detailed Answer:** Ingestion isolates unmapped service accounts (like `00u_svcbackup`) and shared role ARNs. They are reported in the dataset rejection counts without skewing individual human employee metrics.
- **Where to Demo:** Rejections list on `/data`.

#### 20. What is the business ROI of deploying AccessLens?
- **Short Answer:** 80% reduction in access review fatigue, zero rubber-stamped admin roles, and immediate detection of offboarding breaches.
- **Detailed Answer:** Access reviews typically cost enterprises thousands of hours of manual manager toil. AccessLens automates the evidence gathering, eliminates false positives on break-glass roles, and prevents former employees from retaining backdoor cloud access.
- **Where to Demo:** Executive summary overview.

---

## 22. The Final Mental Model & One-Page Cheat Sheet

### If You Remember Only 10 Things About AccessLens, Remember These:
1. **AccessLens never modifies or revokes access.** It is strictly a review and investigation platform; humans make every decision.
2. **"Unused" does not mean "unnecessary".** Break-glass and disaster recovery accounts are protected from accidental removal.
3. **Missing evidence is not safe.** If telemetry is missing or corrupted, AccessLens reports `INSUFFICIENT_EVIDENCE` rather than calling an account clean.
4. **Python is the security truth; AI is the explanation layer.** Detection is 100% deterministic; AI never makes the security call.
5. **AI output is guarded by strict safety denylists.** The model cannot prescribe revocation, claim access is unnecessary, or alter severity.
6. **Carol Diaz is our Ghost Access proof.** Proves that disabling an Okta account does not automatically revoke downstream GitHub tokens.
7. **Bob Chen is our Over-Privileged proof.** Holds full AWS AdministratorAccess but only ever ran read/describe commands.
8. **Alice Nguyen is our Break-Glass proof.** Zero activity in 90 days, but correctly preserved because inactivity is the intended state of emergency roles.
9. **Data quality gates findings.** 3 rejected records and 1 missing proxy source prove the system handles dirty enterprise data safely.
10. **Every finding produces an auditable dossier.** Reviewers record attested decisions and export complete, verifiable JSON records.

---

### One-Page Flow Cheat Sheet

```text
========================================================================================
                                     ACCESSLENS FLOW
========================================================================================

INPUTS:
  [Workday HR]          [Okta IdP]          [AWS / GitHub Roles]   [CloudTrail / GitHub Logs]
  (users_hr.json)       (idp_state.json)    (entitlements.json)    (activity_logs.json)
         │                     │                     │                      │
         └─────────────────────┼─────────────────────┴──────────────────────┘
                               ▼
INGESTION & COVERAGE GATING (app/ingestion/):
  • Quarantines bad records (3 rejected)
  • Resolves identity mappings to real humans
  • Gates coverage: COMPLETE, PARTIAL, or MISSING
                               ▼
IN-MEMORY DATASET (InMemoryDataset):
  • Cryptographic SHA-256 fingerprint & content hash
  • Persists raw domain data into SQLite (accesslens.db)
                               ▼
DETERMINISTIC SECURITY ENGINE (app/engine/):
  ┌──────────────────────────────────────────────────────────────────────────────────┐
  │ Rule A (utilization.py)         ──> Bob Chen (High Privilege, Low Usage)        │
  │                                 ──> Alice Nguyen (Protected Break-Glass)        │
  │                                 ──> Gina Patel & Ivan Petrov (Insufficient)     │
  │ Rule B (privileged_usage.py)    ──> Erin Walsh & Carol Diaz (Destructive Subset)│
  │ Rule C (duplicate_identity.py)  ──> Henry Okafor (Duplicate Okta Accounts)      │
  │ Rule D (ghost_access.py)        ──> Carol Diaz (Ghost Access Post-Disable)      │
  └──────────────────────────────────────────────────────────────────────────────────┘
                               ▼
OUTPUT FINDINGS (8 Findings + 60 Verifiable Exhibits)
                               ▼
REST API (GET /api/analysis & GET /api/analysis/findings/{id})
                               ▼
AI TRIAL LAWYER (app/ai/investigator.py):
  • Ingests immutable InvestigationPacket
  • Deterministic Mock Provider drafts forensic analysis
  • Separates Verified Facts from Inferences
  • Drafts Adversarial Cross-Examination Questions
  • Validates output against strict Safety Denylist (safety.py)
                               ▼
FRONTEND (Next.js 16 App Router):
  • Review Queue (/)                ──> Triage 8 ordered findings
  • Deprovisioning Forensics (/forensics) ──> Isolate Carol Diaz ghost access
  • Data & Coverage (/data)         ──> Audit feed health & coverage gaps
  • Auditor Dossier (/findings/[id])──> Exhibits + AI Analysis + Decision Card
                               ▼
HUMAN REVIEWER ADJUDICATION:
  • Reviewer selects: [APPROVED] [REJECTED] [DEFERRED]
  • Inputs rationale notes into sessionStorage (zero backend mutation)
  • Clicks: [Export Auditor Dossier (.json)]
========================================================================================
```
