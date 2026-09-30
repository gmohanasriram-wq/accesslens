import Link from "next/link";

/**
 * Nothing is filed under that address.
 *
 * This is a 404 and not an empty dossier, and the difference is the point: "we
 * have no such record" and "we have a record and it says nothing" are different
 * answers, and a page that rendered the second for the first would let a typo
 * in a finding id read as an all-clear.
 */
export default function NotFound() {
  return (
    <>
      <header>
        <p className="font-mono text-[10px] tracking-[0.18em] text-faint uppercase">
          404
        </p>
        <h1 className="mt-2 font-display text-3xl tracking-tight text-ink">
          No record filed here
        </h1>
      </header>

      <p className="mt-4 max-w-[65ch] text-sm leading-relaxed text-muted">
        This address does not correspond to a finding in the dataset. That is a
        different statement from a person having nothing raised about them — it
        means there is nothing here to read at all, so nothing here should be
        taken as reassurance.
      </p>

      <p className="mt-6">
        <Link
          href="/"
          className="focus-ring font-mono text-[11px] tracking-[0.14em] text-ink uppercase underline decoration-rule-strong underline-offset-4 hover:decoration-ink"
        >
          Back to the review queue
        </Link>
      </p>
    </>
  );
}
