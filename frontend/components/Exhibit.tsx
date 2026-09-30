import { cx } from "@/lib/cx";
import { timelineDot } from "@/lib/display";
import { exhibitNumber, formatStamp } from "@/lib/format";
import type { Evidence, Severity } from "@/types/api";

/**
 * One exhibit, as it appears in a dossier.
 *
 * ## Why `detail` is not on this page
 *
 * `Evidence.detail` is the rule's own payload and the domain type documents it
 * as opaque on purpose. It is not rendered, for two reasons that agree.
 *
 * The first is that it is not evidence. It is the working that produced the
 * description, and a reviewer citing a finding cites the description. Printing
 * raw rule payloads beside a security conclusion invites the reader to treat
 * the payload as the conclusion.
 *
 * The second is that it is unguarded prose. The engine bans language its
 * evidence cannot support from `summary` -- and `detail` is where a
 * `protection_reason` written by an operator, in their own words, ends up. On
 * Alice's dossier that string reads "deliberately held *unused* so it is
 * available when the identity provider is unavailable", which is the first step
 * on the road to "so remove it". The register renders what the rule concluded
 * and which record it rests on; the operator's justification for a control
 * lives on `/data`, where the subject is what was ingested, not what was
 * decided.
 *
 * ## Order and the rail
 *
 * Exhibits render in the engine's order, which is not incidental: for a ghost
 * access case the sequence *is* the argument. The margin rule runs the length
 * of the list, and a `TIMELINE_POINT` -- a moment the rule recorded, rather
 * than an artefact it read -- gets a marker on it. That is the only structural
 * difference between the two, and it is the real one.
 */
export function Exhibit({
  evidence,
  index,
  severity,
}: {
  evidence: Evidence;
  index: number;
  severity: Severity;
}) {
  const isTimeline = evidence.kind === "TIMELINE_POINT";

  return (
    <li
      data-evidence-id={evidence.evidence_id}
      data-timeline-point={isTimeline ? evidence.evidence_id : undefined}
      className="grid grid-cols-[1.5rem_1fr] border-b border-rule last:border-b-0 sm:grid-cols-[2rem_1fr]"
    >
      <div className="relative" aria-hidden="true">
        <span className="absolute inset-y-0 left-1/2 w-px -translate-x-1/2 bg-rule" />
        {isTimeline ? (
          <span
            className={cx(
              "absolute top-6 left-1/2 h-2.5 w-2.5 -translate-x-1/2 rounded-full ring-4 ring-card",
              timelineDot(severity),
            )}
          />
        ) : null}
      </div>

      <div className="min-w-0 px-4 py-4 sm:px-5">
        <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1">
          <span className="wrap-anywhere font-mono text-[10px] tracking-[0.14em] text-muted uppercase">
            Exhibit {exhibitNumber(index)}
            <span className="mx-1.5 text-rule-strong">·</span>
            {evidence.kind}
          </span>
          <time
            dateTime={evidence.timestamp ?? undefined}
            className="font-mono text-[11px] tabular-nums text-faint"
          >
            {formatStamp(evidence.timestamp)}
          </time>
        </div>

        <p className="mt-2 max-w-[70ch] font-display text-[15px] leading-relaxed text-ink">
          {evidence.description}
        </p>

        <p className="wrap-anywhere mt-2 font-mono text-[10px] text-faint">
          {evidence.evidence_id}
          <span className="mx-1.5 text-rule-strong">·</span>
          {evidence.source}
          {evidence.event_id ? (
            <>
              <span className="mx-1.5 text-rule-strong">·</span>
              {evidence.event_id}
            </>
          ) : null}
        </p>
      </div>
    </li>
  );
}
