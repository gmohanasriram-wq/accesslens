/**
 * TypeScript mirrors of the backend's API contracts.
 *
 * These are hand-written against `backend/app/schemas/api.py` rather than
 * generated. Phase 1 has two response shapes and a generator would be more
 * moving parts than the problem has; the point of this file is that the enums
 * below are spelled out in full, so a backend change that adds a coverage state
 * surfaces here as a type error instead of silently rendering as `undefined`.
 */

/** Whether we actually have logs for a source and window. */
export type Coverage = "COMPLETE" | "PARTIAL" | "MISSING" | "NOT_QUERIED";

/**
 * How much a user was observed to use, within a window we can vouch for.
 *
 * All six members of the backend enum, in the backend's own order. The three
 * graded members (`HIGH`/`MODERATE`/`LOW`) and the three categorical ones
 * (`OBSERVED`/`NONE_OBSERVED`/`UNKNOWN`) are not interchangeable, and the
 * distinction the UI must protect is the last pair: `NONE_OBSERVED` means "we
 * had full coverage and saw nothing", `UNKNOWN` means "we cannot say".
 * Collapsing them is how an access review reports "safe" when the truth is
 * "unmeasured" -- which is the one thing this product exists to stop.
 *
 * A narrowed union here would not fail loudly: the backend would send a grade
 * the UI had no name for and it would render as the string `undefined`.
 */
export type UsageObservation =
  | "HIGH"
  | "MODERATE"
  | "LOW"
  | "OBSERVED"
  | "NONE_OBSERVED"
  | "UNKNOWN";

export type RiskLevel = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "UNKNOWN";

export type EmploymentStatus = "ACTIVE" | "TERMINATED";

export type IdentityStatus = "ACTIVE" | "DISABLED" | "UNKNOWN";

export interface HealthResponse {
  status: string;
  app: string;
  version: string;
  environment: string;
  database: string;
  users_loaded: number;
  ingest_status: string | null;
  content_hash: string | null;
  rejections: number;
  detail: string | null;
}

export interface EntitlementSummary {
  source: string;
  role: string;
  risk_level: RiskLevel;
  protected_role: boolean;
  protection_reason: string | null;
  protection_tags: string[];
  granted_at: string | null;
}

export interface IdentitySummary {
  provider: string;
  account_id: string;
  login: string;
  status: IdentityStatus;
  deactivated_at: string | null;
  deactivation_trigger: string | null;
  is_duplicate_of: string | null;
}

export interface ActivitySummary {
  coverage: Coverage;
  usage_observation: UsageObservation;
  observed_event_count: number;
  last_activity_at: string | null;
  sources_queried: string[];
  sources_missing: string[];
  gaps: string[];
}

export interface PersonaSummary {
  id: string;
  username: string;
  name: string;
  department: string;
  employment_status: EmploymentStatus;
  termination_date: string | null;
  identities: IdentitySummary[];
  entitlements: EntitlementSummary[];
  activity: ActivitySummary;
}

export interface PersonaListResponse {
  count: number;
  content_hash: string;
  analysis_as_of: string;
  generated_at: string | null;
  personas: PersonaSummary[];
}

/* ------------------------------------------------------------------------- *
 * Findings — the engine's output, as the API returns it.
 *
 * These mirror `app/core/enums.py` member for member. That is the point: the
 * backend declares them as real `StrEnum`s, so a rule that starts emitting a
 * new `FindingType` or a new `EvidenceKind` becomes a TypeScript error here
 * rather than a value that renders as `undefined` on a reviewer's screen.
 *
 * Nothing below is renamed. The engine's word for a thing is the word the API
 * sends and the word the UI renders -- `severity`, `status`, `type`,
 * `evidence_completeness`. A friendlier alias at this layer would mean two
 * names for one fact, and no way to notice when they drift apart.
 * ------------------------------------------------------------------------- */

export type Severity = "INFO" | "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";

export type FindingStatus =
  | "REVIEW_REQUIRED"
  | "PROTECTED"
  | "INVESTIGATION_REQUIRED"
  | "INSUFFICIENT_EVIDENCE"
  | "INFORMATIONAL"
  | "CLOSED";

export type FindingType =
  | "HIGH_PRIVILEGE_LOW_USAGE"
  | "PROTECTED_BREAK_GLASS"
  | "GHOST_ACCESS"
  | "RARELY_USED_PRIVILEGED_PERMISSION"
  | "INSUFFICIENT_EVIDENCE"
  | "DUPLICATE_IDENTITY"
  | "NO_FINDING";

/**
 * What AccessLens suggests. There is deliberately no member that revokes,
 * disables, or otherwise changes access — the type system is where the
 * "human approval required" rule is enforced.
 */
export type Recommendation =
  | "MANUAL_REVIEW"
  | "SUGGEST_DOWNSCOPE_MANUAL_APPROVAL"
  | "NO_ACTION_DOCUMENT_JUSTIFICATION"
  | "INVESTIGATE_GHOST_ACCESS"
  | "GATHER_MORE_EVIDENCE";

export type EvidenceKind =
  | "ACTIVITY_EVENT"
  | "TIMELINE_POINT"
  | "ENTITLEMENT_GRANT"
  | "COVERAGE_STATEMENT"
  | "CONFIG_VALUE"
  | "REJECTED_RECORD"
  | "IDENTITY_LINK";

export type EvidenceCompleteness = "COMPLETE" | "PARTIAL" | "MISSING";

export interface Evidence {
  evidence_id: string;
  finding_id: string | null;
  kind: EvidenceKind;
  source: string;
  /** `null` for kinds not anchored to a moment (`COVERAGE_STATEMENT`, `CONFIG_VALUE`). */
  timestamp: string | null;
  event_id: string | null;
  description: string;
  /** Rule-specific payload. Opaque on purpose: the UI renders it generically
   *  rather than encoding what each rule happens to put in it. */
  detail: Record<string, unknown>;
}

export interface Finding {
  id: string;
  user_id: string;
  type: FindingType;
  severity: Severity;
  status: FindingStatus;
  risk_level: RiskLevel;
  summary: string;
  recommendation: Recommendation;
  evidence: Evidence[];
  /** How much of the evidence this conclusion *should* rest on actually exists. */
  evidence_completeness: EvidenceCompleteness;
  rules_triggered: string[];
  usage: UsageObservation | null;
  created_at: string;
}

/** The person a finding is about, in the queue's compact form. */
export interface FindingSubject {
  id: string;
  username: string;
  name: string;
  department: string;
  employment_status: EmploymentStatus;
  termination_date: string | null;
}

/** A queue row: the finding without its payload, plus its subject. */
export interface FindingSummary
  extends Omit<Finding, "evidence"> {
  evidence_count: number;
  subject: FindingSubject;
}

export interface AnalysisResponse {
  content_hash: string;
  dataset_fingerprint: string;
  analysis_as_of: string;
  window_start: string;
  window_end: string;
  rejections: number;
  findings: FindingSummary[];
}

export interface FindingDossierResponse {
  finding: Finding;
  subject: PersonaSummary;
  related_findings: FindingSummary[];
}
