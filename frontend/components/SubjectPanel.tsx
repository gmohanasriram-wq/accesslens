import { Field, Stamp } from "@/components/ui";
import { cx } from "@/lib/cx";
import { coverageStamp, usageStamp } from "@/lib/display";
import { formatDate, formatStamp } from "@/lib/format";
import type { PersonaSummary } from "@/types/api";

/**
 * Who the finding is about, at the moment of analysis.
 *
 * This is the same projection `/api/personas` returns -- literally the same
 * object, built by the same code on the server -- so a reviewer moving between
 * the coverage page and a dossier cannot be shown two different answers about
 * one person's coverage.
 *
 * ## What is deliberately missing
 *
 * `EntitlementSummary.protection_reason` is not rendered here. It is free text
 * written by whoever maintains the protected-role configuration, and it is the
 * one field in this payload that argues a conclusion rather than stating a
 * fact -- Alice's reads that the role is "deliberately held *unused*...,
 * inactivity is the intended state". That is an operator's reasoning, and it
 * belongs with the configuration it came from (`/data` shows the ingested
 * record). A dossier states what the engine concluded and which records it
 * rested on; printing unguarded prose next to a security conclusion is how a
 * reviewer ends up treating someone else's sentence as the finding.
 *
 * The engine's own guarded statement of the same protection is in the finding's
 * summary, a few inches above this panel.
 */
export function SubjectPanel({ persona }: { persona: PersonaSummary }) {
  const { activity } = persona;
  const unvouched = activity.coverage !== "COMPLETE";

  return (
    <div className="space-y-5">
      <dl className="grid gap-x-6 gap-y-4 sm:grid-cols-3">
        <Field label="Name">{persona.name}</Field>
        <Field label="Username">{persona.username}</Field>
        <Field label="Department">{persona.department}</Field>
        <Field label="Employment">{persona.employment_status}</Field>
        <Field label="Terminated">{formatDate(persona.termination_date)}</Field>
        <Field label="Person id">{persona.id}</Field>
      </dl>

      <section>
        <h3 className="font-mono text-[10px] tracking-[0.14em] text-faint uppercase">
          Directory accounts
        </h3>
        <ul className="mt-2">
          {persona.identities.map((identity) => (
            <li
              key={identity.account_id}
              className="flex flex-wrap items-baseline gap-x-3 gap-y-1 border-t border-rule py-2.5"
            >
              <span className="wrap-anywhere font-mono text-[13px] text-ink">
                {identity.login}
              </span>
              <Stamp className="border-rule bg-card-sunk text-muted">
                {identity.status}
              </Stamp>
              {identity.is_duplicate_of ? (
                <Stamp className="border-signal bg-signal-ground text-signal">
                  duplicate
                </Stamp>
              ) : null}
              <span className="wrap-anywhere w-full font-mono text-[10px] text-faint">
                {identity.provider} · {identity.account_id}
                {identity.deactivated_at
                  ? ` · deactivated ${formatStamp(identity.deactivated_at)}`
                  : ""}
                {identity.deactivation_trigger
                  ? ` · ${identity.deactivation_trigger}`
                  : ""}
                {identity.is_duplicate_of
                  ? ` · duplicate of ${identity.is_duplicate_of}`
                  : ""}
              </span>
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h3 className="font-mono text-[10px] tracking-[0.14em] text-faint uppercase">
          Entitlements
        </h3>
        <ul className="mt-2">
          {persona.entitlements.map((entitlement) => (
            <li
              key={`${entitlement.source}-${entitlement.role}`}
              className="border-t border-rule py-2.5"
            >
              <div className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                <span className="wrap-anywhere font-mono text-[13px] text-ink">
                  {entitlement.role}
                </span>
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
                {entitlement.source} · granted {formatDate(entitlement.granted_at)}
                {entitlement.protection_tags.length > 0
                  ? ` · ${entitlement.protection_tags.join(", ")}`
                  : ""}
              </p>
            </li>
          ))}
        </ul>
      </section>

      <section>
        <h3 className="font-mono text-[10px] tracking-[0.14em] text-faint uppercase">
          Activity evidence
        </h3>
        <div className="mt-2 flex flex-wrap items-center gap-2">
          <Stamp className={usageStamp(activity.usage_observation)}>
            {activity.usage_observation}
          </Stamp>
          <Stamp className={coverageStamp(activity.coverage)}>
            coverage {activity.coverage}
          </Stamp>
        </div>
        <p className="mt-2 font-mono text-[11px] text-muted">
          {activity.observed_event_count} successful event
          {activity.observed_event_count === 1 ? "" : "s"}
          {activity.last_activity_at
            ? ` · last ${formatStamp(activity.last_activity_at)}`
            : ""}
        </p>

        {/*
          A window we cannot vouch for is stated as its own condition, with the
          coverage value on the element. Rendering it as a quiet fact would let
          "we did not look" read as "we looked and saw nothing" -- which is the
          one mistake this whole product is arranged to prevent.
        */}
        {unvouched ? (
          <div
            data-coverage-state={activity.coverage}
            className={cx(
              "mt-3 border px-3 py-2.5",
              activity.coverage === "NOT_QUERIED"
                ? "border-rule bg-card-sunk"
                : "border-seal bg-seal-ground",
            )}
          >
            <p className="font-mono text-[10px] tracking-[0.14em] text-seal uppercase">
              Coverage {activity.coverage}
            </p>
            <p className="mt-1.5 text-[13px] leading-relaxed text-ink">
              This window cannot be vouched for in full, so silence in it is not
              evidence of anything. Treat the usage observation above as
              undetermined rather than as an absence.
            </p>
            {activity.sources_missing.length > 0 ? (
              <p className="wrap-anywhere mt-1.5 font-mono text-[10px] text-muted">
                not delivered: {activity.sources_missing.join(", ")}
              </p>
            ) : null}
            {activity.gaps.length > 0 ? (
              <ul className="mt-2 space-y-1">
                {activity.gaps.map((gap) => (
                  <li
                    key={gap}
                    className="wrap-anywhere font-mono text-[10px] text-muted"
                  >
                    {gap}
                  </li>
                ))}
              </ul>
            ) : null}
          </div>
        ) : (
          <p className="wrap-anywhere mt-2 font-mono text-[10px] text-faint">
            sources queried: {activity.sources_queried.join(", ") || "none"}
          </p>
        )}
      </section>
    </div>
  );
}
