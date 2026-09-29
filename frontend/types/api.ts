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
 * `UNKNOWN` is not a synonym for `NONE_OBSERVED`. The first means "we cannot
 * say"; the second means "we had full coverage and saw nothing". The UI must
 * never render them the same way — collapsing them is how an access review
 * reports "safe" when the truth is "unmeasured".
 */
export type UsageObservation = "UNKNOWN" | "NONE_OBSERVED" | "OBSERVED";

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
