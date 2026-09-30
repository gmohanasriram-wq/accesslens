import { connection } from "next/server";

import { ErrorPanel, Field, Panel, Stamp, describeError } from "@/components/ui";
import { fetchHealth, fetchPersonas } from "@/lib/api";
import { coverageStamp, usageStamp } from "@/lib/display";
import { formatStamp } from "@/lib/format";
import type {
  ActivitySummary,
  HealthResponse,
  PersonaSummary,
} from "@/types/api";

/**
 * `/data` — what was ingested, and how much of it arrived.
 *
 * This is the Phase 1 coverage page, moved rather than replaced. It is not
 * scaffolding for the review surface: it is the only view of the *raw record* —
 * who was ingested, how much of each source actually arrived, which records
 * were discarded and why. Every finding cites this dataset, and this is where a
 * reviewer goes to check the citation.
 *
 * It is also the page that keeps the product honest about silence. `UNKNOWN`
 * and `NONE_OBSERVED` are shown as the distinct states they are, gaps are
 * explained rather than counted, and a source that was never delivered is
 * named. A page that showed only names and roles would look correct while
 * hiding the one thing this system is built around.
 *
 * The persona table is the only `<table>` on the page, and the ingest summary
 * is a definition list rather than a second one — a reviewer's screen reader
 * should meet one table here, and it should be the people.
 */
export default async function DataPage() {
  await connection();

  let health: HealthResponse;
  let personas: PersonaSummary[];
  let contentHash: string;

  try {
    const [healthResult, personaResult] = await Promise.all([
      fetchHealth(),
      fetchPersonas(),
    ]);
    health = healthResult;
    personas = personaResult.personas;
    contentHash = personaResult.content_hash;
  } catch (error) {
    return (
      <>
        <PageHeading />
        <div className="mt-6">
          <ErrorPanel {...describeError(error)} />
        </div>
      </>
    );
  }

  return (
    <>
      <PageHeading
        lede={`The record every finding on this deployment was computed from. ${personas.length} people were ingested; a source that was not delivered is named rather than counted as silence.`}
      />

      <div className="mt-6 space-y-6">
        <Panel
          title="Ingest"
          aside={
            <span className="wrap-anywhere font-mono text-[10px] tracking-[0.14em] text-muted uppercase">
              {health.ingest_status ?? "not recorded"}
            </span>
          }
        >
          <dl className="grid gap-x-6 gap-y-4 sm:grid-cols-3">
            <Field label="Service status">{health.status}</Field>
            <Field label="Database">{health.database}</Field>
            <Field label="Environment">{health.environment}</Field>
            <Field label="Users loaded">{String(health.users_loaded)}</Field>
            <Field label="Rejected records">{String(health.rejections)}</Field>
            <Field label="Dataset">{contentHash.slice(0, 12)}</Field>
          </dl>

          <p className="mt-4 border-t border-rule pt-3 text-xs leading-relaxed text-muted">
            {health.rejections === 0
              ? "Every record in the export passed validation."
              : `${health.rejections} ${
                  health.rejections === 1 ? "record" : "records"
                } failed validation and were set aside rather than guessed at. A discarded record is why a finding may be absent, so the count is part of the review rather than a detail of the plumbing.`}
          </p>

          {health.detail ? (
            <p className="wrap-anywhere mt-2 font-mono text-[11px] text-muted">
              {health.detail}
            </p>
          ) : null}
        </Panel>

        <Panel
          title="People, access and activity evidence"
          flush
          aside={
            <span className="font-mono text-[10px] tracking-[0.14em] text-faint uppercase">
              ordered by username
            </span>
          }
        >
          {/* Roles are stated rather than left implicit. Below `sm` the cells
              become blocks (`stack-table` in globals.css), which drops the
              implicit table roles, and a screen reader on a phone would get a
              run of unlabelled text. Each `data-label` repeats its column's
              heading verbatim, so the phone's label and the desktop's header
              are the same string. */}
          <div className="overflow-x-auto">
            <table role="table" className="stack-table w-full border-collapse text-sm">
              <caption className="sr-only">
                Ingested people, with their directory accounts, entitlements and
                the activity evidence available for each
              </caption>
              <thead role="rowgroup">
                <tr role="row" className="border-b border-rule-strong text-left">
                  {["Person", "Status", "Access", "Activity evidence"].map(
                    (heading) => (
                      <th
                        key={heading}
                        role="columnheader"
                        scope="col"
                        className="px-4 py-2.5 font-mono text-[10px] font-medium tracking-[0.14em] text-faint uppercase sm:px-5"
                      >
                        {heading}
                      </th>
                    ),
                  )}
                </tr>
              </thead>
              <tbody role="rowgroup">
                {personas.map((persona) => (
                  <PersonaRow key={persona.id} persona={persona} />
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      </div>
    </>
  );
}

function PageHeading({ lede }: { lede?: string }) {
  return (
    <header>
      <h1 className="font-display text-3xl tracking-tight text-ink sm:text-4xl">
        Data &amp; coverage
      </h1>
      {lede ? (
        <p className="mt-3 max-w-[75ch] text-sm leading-relaxed text-muted">
          {lede}
        </p>
      ) : null}
    </header>
  );
}

function PersonaRow({ persona }: { persona: PersonaSummary }) {
  return (
    <tr role="row" className="border-b border-rule align-top last:border-b-0">
      <td role="cell" className="px-4 py-3.5 sm:px-5">
        <div className="text-[15px] text-ink">{persona.name}</div>
        <div className="wrap-anywhere font-mono text-[11px] text-muted">
          {persona.username}
        </div>
        <div className="text-xs text-muted">{persona.department}</div>
        {persona.identities.some((identity) => identity.is_duplicate_of) ? (
          <div className="mt-1.5">
            <Stamp className="border-signal bg-signal-ground text-signal">
              duplicate account
            </Stamp>
          </div>
        ) : null}
      </td>

      <td role="cell" data-label="Status" className="px-4 py-3.5 sm:px-5">
        <Stamp className="border-rule bg-card-sunk text-muted">
          {persona.employment_status}
        </Stamp>
        {persona.termination_date ? (
          <div className="mt-1.5 font-mono text-[10px] text-faint">
            ended {formatStamp(persona.termination_date)}
          </div>
        ) : null}
        <ul className="mt-2 space-y-1">
          {persona.identities.map((identity) => (
            <li
              key={identity.account_id}
              className="font-mono text-[10px] text-muted"
            >
              {identity.provider} · {identity.status}
              {identity.deactivated_at
                ? ` · off ${formatStamp(identity.deactivated_at)}`
                : ""}
            </li>
          ))}
        </ul>
      </td>

      <td role="cell" data-label="Access" className="px-4 py-3.5 sm:px-5">
        {persona.entitlements.length === 0 ? (
          <span className="font-mono text-[11px] text-faint">
            no entitlements ingested
          </span>
        ) : (
          <ul className="space-y-2">
            {persona.entitlements.map((entitlement) => (
              <li key={`${entitlement.source}-${entitlement.role}`}>
                <div className="wrap-anywhere font-mono text-[11px] text-ink">
                  {entitlement.role}
                </div>
                <div className="mt-1 flex flex-wrap items-center gap-1.5">
                  <Stamp className="border-rule bg-card-sunk text-muted">
                    {entitlement.risk_level}
                  </Stamp>
                  {entitlement.protected_role ? (
                    <Stamp className="border-verified bg-verified-ground text-verified">
                      protected
                    </Stamp>
                  ) : null}
                </div>
                <p className="wrap-anywhere mt-1 font-mono text-[10px] text-faint">
                  {entitlement.source}
                  {entitlement.protection_tags.length > 0
                    ? ` · ${entitlement.protection_tags.join(", ")}`
                    : ""}
                </p>
              </li>
            ))}
          </ul>
        )}
      </td>

      <td
        role="cell"
        data-label="Activity evidence"
        className="px-4 py-3.5 sm:px-5"
      >
        <ActivityCell activity={persona.activity} />
      </td>
    </tr>
  );
}

function ActivityCell({ activity }: { activity: ActivitySummary }) {
  // The floor that made the desktop column legible is what pushed the phone into
  // a horizontal scroll, so it applies only once the table is actually a table.
  return (
    <div className="sm:min-w-[16rem]">
      <div className="flex flex-wrap items-center gap-1.5">
        <Stamp className={usageStamp(activity.usage_observation)}>
          {activity.usage_observation}
        </Stamp>
        <Stamp className={coverageStamp(activity.coverage)}>
          coverage {activity.coverage}
        </Stamp>
      </div>

      <p className="mt-2 font-mono text-[10px] text-muted">
        {activity.observed_event_count} successful event
        {activity.observed_event_count === 1 ? "" : "s"}
        {activity.last_activity_at
          ? ` · last ${formatStamp(activity.last_activity_at)}`
          : ""}
      </p>

      {activity.sources_queried.length > 0 ? (
        <p className="wrap-anywhere mt-1 font-mono text-[10px] text-faint">
          queried: {activity.sources_queried.join(", ")}
        </p>
      ) : null}

      {activity.gaps.length > 0 ? (
        <ul className="mt-2 space-y-1.5">
          {activity.gaps.map((gap) => (
            <li
              key={gap}
              className="wrap-anywhere border-l-2 border-l-seal bg-seal-ground px-2 py-1.5 font-mono text-[10px] text-ink"
            >
              {gap}
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
