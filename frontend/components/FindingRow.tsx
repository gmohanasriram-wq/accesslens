import Link from "next/link";

import { Stamp } from "@/components/ui";
import { cx } from "@/lib/cx";
import { severityBand, severityInk, statusStamp } from "@/lib/display";
import type { FindingSummary } from "@/types/api";

/**
 * One entry in the register.
 *
 * Both the review queue and the forensics view are this component, because they
 * are the same list read two ways: the forensics view is the queue filtered to
 * the findings the engine classified as `GHOST_ACCESS`, and it renders them
 * identically on purpose. A separate "investigation card" would be a second
 * rendering of one engine fact, and the two would drift.
 *
 * The entry is a single link rather than a card with a link in it. A reviewer
 * reads down the queue and opens one; making the whole entry the target means
 * that is one keystroke, not a hunt for the small piece of text that happens to
 * be clickable.
 */
export function FindingRow({ finding }: { finding: FindingSummary }) {
  return (
    <li
      data-finding-id={finding.id}
      data-severity={finding.severity}
      data-status={finding.status}
      data-finding-type={finding.type}
      className={cx(
        "border-b border-b-rule border-l-[6px] last:border-b-0",
        severityBand(finding.severity),
      )}
    >
      <Link
        href={`/findings/${finding.id}`}
        className="focus-ring block bg-card px-4 py-4 transition-colors hover:bg-card-sunk sm:px-5"
      >
        <div className="flex flex-wrap items-baseline gap-x-3 gap-y-2">
          <span className="wrap-anywhere font-mono text-[11px] tracking-[0.12em] text-muted">
            {finding.type}
          </span>
          <Stamp className={cx("ml-auto", statusStamp(finding.status))}>
            {finding.status}
          </Stamp>
        </div>

        <h2 className="mt-3 font-display text-lg leading-snug tracking-tight text-ink">
          {finding.subject.name}
        </h2>

        <p className="wrap-anywhere mt-0.5 font-mono text-[11px] text-muted">
          {finding.subject.username} · {finding.subject.department} ·{" "}
          {finding.subject.employment_status}
        </p>

        {/* Clamped to three lines. The summary is a full paragraph of the
            rule's prose, and eight of them unbroken is a wall a reviewer has to
            read rather than scan -- six screens of it on a phone. The queue's
            job is triage: the band, the type, the person and the status are the
            scanning anchors, and the paragraph previews the claim. Nothing is
            withheld by this: the dossier renders the same string unclamped, one
            keystroke away, and the engine's full text is still what a screen
            reader reads here. */}
        <p className="mt-3 line-clamp-3 max-w-[70ch] font-display text-[15px] leading-relaxed text-ink">
          {finding.summary}
        </p>

        {/* The severity word is here rather than only in the margin's colour,
            so the entry still ranks correctly on a printout. */}
        <div className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1.5 font-mono text-[10px] tracking-[0.12em] uppercase">
          <span className={severityInk(finding.severity)}>
            {finding.severity}
          </span>
          <span className="text-faint">{finding.evidence_count} exhibits</span>
          {finding.usage ? (
            <span className="text-faint">usage {finding.usage}</span>
          ) : null}
          {finding.rules_triggered.map((rule) => (
            <span key={rule} className="wrap-anywhere text-faint">
              {rule}
            </span>
          ))}
        </div>
      </Link>
    </li>
  );
}
