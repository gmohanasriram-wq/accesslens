import type { ReactNode } from "react";

import { cx } from "@/lib/cx";
import { ApiError } from "@/lib/api";

/**
 * The small set of primitives the register is built from.
 *
 * There are four of them, and they exist so that the pages read as a document
 * rather than as a pile of divs: a stamp for a state, a field for a labelled
 * fact, a panel for a section with a heading, and one honest failure notice.
 */

/** A state, set as a stamp. Always carries its value as text. */
export function Stamp({
  className,
  children,
}: {
  className: string;
  children: ReactNode;
}) {
  return (
    <span
      className={cx(
        "inline-block border px-1.5 py-0.5 font-mono text-[10px] leading-4 tracking-[0.12em] whitespace-nowrap",
        className,
      )}
    >
      {children}
    </span>
  );
}

/** A labelled fact. The label is chrome; the value is the record. */
export function Field({
  label,
  children,
  mono = true,
}: {
  label: string;
  children: ReactNode;
  mono?: boolean;
}) {
  return (
    <div className="min-w-0">
      <dt className="font-mono text-[10px] tracking-[0.14em] text-faint uppercase">
        {label}
      </dt>
      <dd
        className={cx(
          "wrap-anywhere mt-0.5 text-sm text-ink",
          mono && "font-mono text-[13px]",
        )}
      >
        {children}
      </dd>
    </div>
  );
}

/**
 * A ruled section with a serif heading.
 *
 * The heading is an `h2` and the page owns the only `h1`; the document has to
 * be navigable by heading level, which is why this is a component rather than a
 * class name applied ad hoc.
 */
export function Panel({
  title,
  aside,
  children,
  className,
  flush = false,
}: {
  title: string;
  aside?: ReactNode;
  children: ReactNode;
  className?: string;
  /** For contents that carry their own inset, such as the exhibit register. */
  flush?: boolean;
}) {
  return (
    <section className={cx("border border-rule bg-card", className)}>
      <div className="flex flex-wrap items-baseline justify-between gap-x-4 gap-y-1 border-b border-rule px-4 py-3 sm:px-5">
        <h2 className="font-display text-base tracking-tight text-ink">{title}</h2>
        {aside}
      </div>
      <div className={flush ? undefined : "px-4 py-4 sm:px-5"}>{children}</div>
    </section>
  );
}

/**
 * The backend did not answer.
 *
 * It reports the failure rather than rendering an empty register, because "no
 * findings" and "could not look" are different answers -- and the second one is
 * the one that gets mistaken for the first. The status and the backend's own
 * message are both shown: a reviewer who sees "503" knows to wait, and a
 * reviewer who sees a coverage error knows to go and fix the export.
 */
export function ErrorPanel({
  message,
  status,
}: {
  message: string;
  status: number | null;
}) {
  return (
    <div
      role="alert"
      className="border border-signal bg-signal-ground px-4 py-4 sm:px-5"
    >
      <h2 className="font-display text-base text-signal">
        The register could not be compiled
      </h2>
      <p className="mt-2 text-sm text-ink">
        The analysis service did not return a dataset
        {status ? ` (HTTP ${status})` : ""}.
      </p>
      <p className="mt-2 font-mono text-xs break-words text-muted">{message}</p>
      <p className="mt-3 text-xs text-muted">
        Nothing is claimed about anyone below this line, because nothing was
        read.
      </p>
    </div>
  );
}

/** Turns a thrown value into what `ErrorPanel` needs. */
export function describeError(error: unknown): {
  message: string;
  status: number | null;
} {
  return {
    message: error instanceof Error ? error.message : String(error),
    status: error instanceof ApiError ? error.status : null,
  };
}
