import { ApiError, fetchHealth, fetchPersonas } from "@/lib/api";
import type {
  ActivitySummary,
  Coverage,
  PersonaSummary,
  UsageObservation,
} from "@/types/api";

/**
 * Phase 1 status page.
 *
 * Deliberately not the review dashboard — that is Phase 3. This page exists to
 * prove the stack end-to-end: FastAPI serves, ingestion persists, the schema
 * validates, and Next renders real ingested data rather than a mock.
 *
 * It shows the coverage model on purpose. A page that displayed only names and
 * roles would look correct while hiding the one thing this system is built
 * around, so every row states whether the window could be vouched for and
 * `UNKNOWN` is rendered as its own state rather than as "no activity".
 */

export const dynamic = "force-dynamic";

export default async function Home() {
  let personas: Awaited<ReturnType<typeof fetchPersonas>> | null = null;
  let health: Awaited<ReturnType<typeof fetchHealth>> | null = null;
  let error: string | null = null;
  let errorStatus: number | null = null;

  try {
    [health, personas] = await Promise.all([fetchHealth(), fetchPersonas()]);
  } catch (err) {
    error = err instanceof Error ? err.message : String(err);
    errorStatus = err instanceof ApiError ? err.status : null;
  }

  return (
    <main className="mx-auto max-w-5xl px-4 py-12 font-sans">
      <header className="mb-8">
        <h1 className="text-2xl font-semibold tracking-tight text-slate-900 dark:text-slate-50">
          AccessLens
        </h1>
        <p className="mt-1 text-sm text-slate-600 dark:text-slate-400">
          Telemetry-informed access review. Findings are produced by
          deterministic rules; nothing here changes anyone&apos;s access.
        </p>
      </header>

      {error ? (
        <ErrorPanel message={error} status={errorStatus} />
      ) : (
        <>
          {health && <HealthBar health={health} />}
          {personas && <PersonaTable personas={personas.personas} />}
          {personas && (
            <footer className="mt-6 text-xs text-slate-500 dark:text-slate-500">
              {personas.count} personas · analysis window ends{" "}
              <time dateTime={personas.analysis_as_of}>
                {formatTimestamp(personas.analysis_as_of)}
              </time>{" "}
              · dataset <code className="font-mono">{personas.content_hash.slice(0, 12)}</code>
            </footer>
          )}
        </>
      )}
    </main>
  );
}

function ErrorPanel({ message, status }: { message: string; status: number | null }) {
  return (
    <div className="rounded-lg border border-amber-300 bg-amber-50 p-4 dark:border-amber-800 dark:bg-amber-950/40">
      <h2 className="text-sm font-semibold text-amber-900 dark:text-amber-200">
        The backend did not return a dataset
        {status ? ` (HTTP ${status})` : ""}
      </h2>
      <p className="mt-2 text-sm text-amber-800 dark:text-amber-300">{message}</p>
      <p className="mt-3 text-xs text-amber-700 dark:text-amber-400">
        The page reports the failure rather than rendering an empty review,
        because &quot;no rows&quot; and &quot;could not look&quot; are different
        answers.
      </p>
    </div>
  );
}

function HealthBar({
  health,
}: {
  health: Awaited<ReturnType<typeof fetchHealth>>;
}) {
  const degraded = health.status !== "ok";
  return (
    <div
      className={`mb-6 flex flex-wrap items-center gap-x-6 gap-y-1 rounded-lg border p-3 text-xs ${
        degraded
          ? "border-amber-300 bg-amber-50 dark:border-amber-800 dark:bg-amber-950/40"
          : "border-slate-200 bg-slate-50 dark:border-slate-800 dark:bg-slate-900"
      }`}
    >
      <Field label="status" value={health.status} />
      <Field label="database" value={health.database} />
      <Field label="ingest" value={health.ingest_status ?? "—"} />
      <Field label="users" value={String(health.users_loaded)} />
      <Field label="rejected records" value={String(health.rejections)} />
      <Field label="env" value={health.environment} />
    </div>
  );
}

function Field({ label, value }: { label: string; value: string }) {
  return (
    <span className="text-slate-600 dark:text-slate-400">
      {label}{" "}
      <span className="font-mono font-medium text-slate-900 dark:text-slate-100">
        {value}
      </span>
    </span>
  );
}

function PersonaTable({ personas }: { personas: PersonaSummary[] }) {
  return (
    <div className="overflow-x-auto rounded-lg border border-slate-200 dark:border-slate-800">
      <table className="w-full border-collapse text-sm">
        <thead>
          <tr className="bg-slate-50 text-left text-xs uppercase tracking-wide text-slate-500 dark:bg-slate-900 dark:text-slate-400">
            <th className="px-4 py-2 font-medium">Person</th>
            <th className="px-4 py-2 font-medium">Status</th>
            <th className="px-4 py-2 font-medium">Access</th>
            <th className="px-4 py-2 font-medium">Activity evidence</th>
          </tr>
        </thead>
        <tbody>
          {personas.map((persona) => (
            <PersonaRow key={persona.id} persona={persona} />
          ))}
        </tbody>
      </table>
    </div>
  );
}

function PersonaRow({ persona }: { persona: PersonaSummary }) {
  const privileged = persona.entitlements.some(
    (e) => e.risk_level === "CRITICAL" || e.risk_level === "HIGH",
  );

  return (
    <tr className="border-t border-slate-200 align-top dark:border-slate-800">
      <td className="px-4 py-3">
        <div className="font-medium text-slate-900 dark:text-slate-100">
          {persona.name}
        </div>
        <div className="font-mono text-xs text-slate-500 dark:text-slate-400">
          {persona.username}
        </div>
        <div className="text-xs text-slate-500 dark:text-slate-400">
          {persona.department}
        </div>
        {persona.identities.some((i) => i.is_duplicate_of) && (
          <div className="mt-1 text-xs text-amber-700 dark:text-amber-400">
            duplicate directory account
          </div>
        )}
      </td>

      <td className="px-4 py-3">
        <Badge
          tone={persona.employment_status === "ACTIVE" ? "neutral" : "warn"}
          label={persona.employment_status.toLowerCase()}
        />
        {persona.identities.map((identity) => (
          <div
            key={identity.account_id}
            className="mt-1 text-xs text-slate-500 dark:text-slate-400"
          >
            {identity.provider} {identity.status.toLowerCase()}
          </div>
        ))}
      </td>

      <td className="px-4 py-3">
        {persona.entitlements.length === 0 ? (
          <span className="text-xs text-slate-400">none</span>
        ) : (
          <ul className="space-y-1">
            {persona.entitlements.map((entitlement) => (
              <li key={`${entitlement.source}-${entitlement.role}`}>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs text-slate-700 dark:text-slate-300">
                    {entitlement.role}
                  </span>
                  <Badge
                    tone={riskTone(entitlement.risk_level)}
                    label={entitlement.risk_level.toLowerCase()}
                  />
                </div>
                {entitlement.protected_role && (
                  <div className="text-xs text-sky-700 dark:text-sky-400">
                    protected{entitlement.protection_tags.length > 0
                      ? ` · ${entitlement.protection_tags.join(", ")}`
                      : ""}
                  </div>
                )}
              </li>
            ))}
          </ul>
        )}
        {privileged && (
          <div className="mt-2 text-xs text-slate-500 dark:text-slate-400">
            holds privileged access
          </div>
        )}
      </td>

      <td className="px-4 py-3">
        <ActivityCell activity={persona.activity} />
      </td>
    </tr>
  );
}

function ActivityCell({ activity }: { activity: ActivitySummary }) {
  return (
    <div>
      <div className="flex items-center gap-2">
        <Badge tone={usageTone(activity.usage_observation)} label={usageLabel(activity.usage_observation)} />
        <Badge tone={coverageTone(activity.coverage)} label={`coverage: ${activity.coverage.toLowerCase().replace("_", " ")}`} />
      </div>

      <div className="mt-1 text-xs text-slate-500 dark:text-slate-400">
        {activity.observed_event_count} successful event
        {activity.observed_event_count === 1 ? "" : "s"}
        {activity.last_activity_at
          ? ` · last ${formatTimestamp(activity.last_activity_at)}`
          : ""}
      </div>

      {activity.gaps.length > 0 && (
        <ul className="mt-2 space-y-1">
          {activity.gaps.map((gap) => (
            <li
              key={gap}
              className="rounded border border-amber-200 bg-amber-50 px-2 py-1 text-xs text-amber-800 dark:border-amber-900 dark:bg-amber-950/40 dark:text-amber-300"
            >
              {gap}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}

type Tone = "neutral" | "warn" | "danger" | "info" | "muted";

const TONE_CLASSES: Record<Tone, string> = {
  neutral:
    "border-slate-300 bg-white text-slate-700 dark:border-slate-700 dark:bg-slate-900 dark:text-slate-300",
  muted:
    "border-slate-200 bg-slate-50 text-slate-500 dark:border-slate-800 dark:bg-slate-900 dark:text-slate-500",
  warn: "border-amber-300 bg-amber-50 text-amber-800 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-300",
  danger:
    "border-red-300 bg-red-50 text-red-800 dark:border-red-900 dark:bg-red-950/40 dark:text-red-300",
  info: "border-sky-300 bg-sky-50 text-sky-800 dark:border-sky-800 dark:bg-sky-950/40 dark:text-sky-300",
};

function Badge({ tone, label }: { tone: Tone; label: string }) {
  return (
    <span
      className={`inline-block whitespace-nowrap rounded-full border px-2 py-0.5 text-xs ${TONE_CLASSES[tone]}`}
    >
      {label}
    </span>
  );
}

function riskTone(risk: string): Tone {
  if (risk === "CRITICAL" || risk === "HIGH") return "danger";
  if (risk === "MEDIUM") return "warn";
  return "muted";
}

/**
 * `UNKNOWN` gets its own tone, distinct from both "we saw activity" and "we saw
 * none". Rendering it as a muted/neutral state is the honest choice: it is not a
 * warning about the user, it is a statement about our evidence.
 */
function usageTone(usage: UsageObservation): Tone {
  if (usage === "OBSERVED") return "info";
  if (usage === "NONE_OBSERVED") return "neutral";
  return "muted";
}

function usageLabel(usage: UsageObservation): string {
  if (usage === "OBSERVED") return "usage observed";
  if (usage === "NONE_OBSERVED") return "no usage observed";
  return "usage unknown";
}

function coverageTone(coverage: Coverage): Tone {
  if (coverage === "COMPLETE") return "neutral";
  if (coverage === "NOT_QUERIED") return "muted";
  return "warn";
}

function formatTimestamp(value: string): string {
  // Fixed locale and UTC: the analysis window is pinned, and a server/browser
  // locale difference would render the same instant two different ways.
  return new Date(value).toLocaleString("en-GB", {
    timeZone: "UTC",
    year: "numeric",
    month: "short",
    day: "2-digit",
    hour: "2-digit",
    minute: "2-digit",
  });
}
