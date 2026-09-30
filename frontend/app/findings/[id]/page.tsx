import Link from "next/link";
import { notFound } from "next/navigation";
import { connection } from "next/server";

import { Exhibit } from "@/components/Exhibit";
import { InvestigationPanel } from "@/components/InvestigationPanel";
import { ReviewerDecisionCard } from "@/components/ReviewerDecisionCard";
import { SubjectPanel } from "@/components/SubjectPanel";
import { ErrorPanel, Field, Panel, Stamp, describeError } from "@/components/ui";
import { ApiError, fetchDossier, fetchInvestigation } from "@/lib/api";
import { severityInk, statusStamp } from "@/lib/display";
import { formatStamp } from "@/lib/format";
import type { FindingDossierResponse, StructuredInvestigationResult } from "@/types/api";

/**
 * `/findings/[id]` — the auditor dossier.
 *
 * This is the page the rest of the product exists to produce: one finding, the
 * person it is about, every exhibit the rule attached, and the person's other
 * findings. A queue tells a reviewer *that* something was flagged; this is
 * where they can check whether it is true.
 *
 * Nothing is summarised away. Every piece of evidence the engine emitted is
 * rendered, in the engine's order, including the ones that weaken the finding —
 * a coverage statement saying a source was never delivered, a configuration
 * value showing the role was protected on purpose. A dossier that quietly
 * dropped those would look tidier and would be lying, and the reviewer would
 * have no way to tell.
 *
 * An unknown id is a 404, not an empty dossier. "There is no such record" and
 * "this person has nothing to report" are different claims, and a page that
 * rendered the same thing for both would let a typo read as an all-clear.
 */
export default async function DossierPage(
  props: PageProps<"/findings/[id]">,
) {
  await connection();
  const { id } = await props.params;

  let dossier: FindingDossierResponse;
  let investigation: StructuredInvestigationResult | null = null;
  try {
    dossier = await fetchDossier(id);
    investigation = await fetchInvestigation(id);
  } catch (error) {
    if (error instanceof ApiError && error.status === 404) notFound();
    return (
      <>
        <header>
          <h1 className="font-display text-3xl tracking-tight text-ink">
            Finding unavailable
          </h1>
        </header>
        <div className="mt-6">
          <ErrorPanel {...describeError(error)} />
        </div>
      </>
    );
  }

  const { finding, subject, related_findings: related } = dossier;

  return (
    <article data-finding-id={finding.id}>
      <header>
        <p className="wrap-anywhere font-mono text-[10px] tracking-[0.18em] text-faint uppercase">
          {finding.id}
        </p>
        <h1 className="mt-2 font-display text-3xl tracking-tight text-ink sm:text-4xl">
          {subject.name}
        </h1>

        <div className="mt-4 flex flex-wrap items-center gap-2">
          <Stamp className={statusStamp(finding.status)}>{finding.status}</Stamp>
          <Stamp className="border-rule bg-card-sunk text-muted">
            {finding.type}
          </Stamp>
          <Stamp className="border-rule bg-card-sunk text-muted">
            {finding.risk_level} risk
          </Stamp>
        </div>

        <p className="mt-5 max-w-[70ch] font-display text-lg leading-relaxed text-ink">
          {finding.summary}
        </p>

        <p className="mt-4 max-w-[70ch] text-sm leading-relaxed text-muted">
          Suggested next step:{" "}
          <span className="wrap-anywhere font-mono text-[13px] text-ink">
            {finding.recommendation}
          </span>
          . AccessLens reports it and stops there — a person decides what, if
          anything, happens to this account.
        </p>
      </header>

      <div className="mt-8 space-y-6">
        <Panel
          title="The finding"
          aside={
            <span className={severityInk(finding.severity) + " font-mono text-[10px] tracking-[0.14em] uppercase"}>
              {finding.severity} severity
            </span>
          }
        >
          <dl className="grid gap-x-6 gap-y-4 sm:grid-cols-3">
            <Field label="Type">{finding.type}</Field>
            <Field label="Severity">{finding.severity}</Field>
            <Field label="Status">{finding.status}</Field>
            <Field label="Risk level">{finding.risk_level}</Field>
            <Field label="Usage observation">
              {finding.usage ?? "not recorded"}
            </Field>
            <Field label="Evidence completeness">
              {finding.evidence_completeness}
            </Field>
            <Field label="Controls that fired">
              {finding.rules_triggered.join(", ") || "none recorded"}
            </Field>
            <Field label="Raised at">{formatStamp(finding.created_at)}</Field>
            <Field label="Recommendation">{finding.recommendation}</Field>
          </dl>
        </Panel>

        <Panel
          title="The person"
          aside={
            <span className="font-mono text-[10px] tracking-[0.14em] text-faint uppercase">
              {subject.username}
            </span>
          }
        >
          <SubjectPanel persona={subject} />
        </Panel>

        {investigation ? (
          <InvestigationPanel investigation={investigation} />
        ) : null}

        <ReviewerDecisionCard
          finding={finding}
          subject={subject}
          investigation={investigation}
        />

        <Panel
          title="Exhibits"
          flush
          aside={
            <span className="font-mono text-[10px] tracking-[0.14em] text-faint uppercase">
              {finding.evidence.length} recorded
            </span>
          }
        >
          {finding.evidence.length === 0 ? (
            <p className="px-4 py-4 text-sm text-muted sm:px-5">
              The rule attached no exhibits to this finding, which is itself a
              fact about how much the conclusion rests on.
            </p>
          ) : (
            <ol>
              {finding.evidence.map((evidence, index) => (
                <Exhibit
                  key={evidence.evidence_id}
                  evidence={evidence}
                  index={index}
                  severity={finding.severity}
                />
              ))}
            </ol>
          )}
        </Panel>

        {related.length > 0 ? (
          <Panel
            title="Also raised about this person"
            aside={
              <span className="font-mono text-[10px] tracking-[0.14em] text-faint uppercase">
                {related.length}
              </span>
            }
          >
            <ul>
              {related.map((other) => (
                <li
                  key={other.id}
                  className="border-b border-rule py-3 first:pt-0 last:border-b-0 last:pb-0"
                >
                  <Link
                    href={`/findings/${other.id}`}
                    className="focus-ring block"
                  >
                    <span className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                      <span className="wrap-anywhere font-mono text-[11px] tracking-[0.12em] text-muted">
                        {other.type}
                      </span>
                      <span className="font-mono text-[10px] tracking-[0.12em] text-faint uppercase">
                        {other.severity} · {other.status}
                      </span>
                    </span>
                    <span className="mt-1.5 block max-w-[70ch] text-sm leading-relaxed text-ink">
                      {other.summary}
                    </span>
                  </Link>
                </li>
              ))}
            </ul>
          </Panel>
        ) : null}
      </div>
    </article>
  );
}
