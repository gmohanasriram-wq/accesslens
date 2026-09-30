import { fetchHealth, fetchPersonas } from "@/lib/api";
import { hashPrefix, formatStamp } from "@/lib/format";

/**
 * The provenance line, on every view.
 *
 * A finding with no window and no dataset behind it is a claim; with them it is
 * a citation. So the window, the dataset's short name and how much input the
 * ingest could not use are stated once, in the shell, rather than being
 * repeated -- or forgotten -- by each page.
 *
 * It reads through the same cached fetchers the pages use, so on `/data`, where
 * the health and persona payloads are the page's whole subject, this costs
 * nothing: React's `cache` collapses the shell's request and the page's into
 * one.
 *
 * If the API is down the strip says so and stops. It does not render zeros: a
 * strip reading "0 rejected" because nothing answered would be a false
 * statement of exactly the kind this product exists to catch.
 */
export async function DatasetStrip() {
  try {
    const [health, personas] = await Promise.all([
      fetchHealth(),
      fetchPersonas(),
    ]);

    return (
      <footer className="mt-12 border-t border-rule">
        <div className="mx-auto max-w-5xl px-4 py-5 sm:px-6">
          <dl className="flex flex-wrap gap-x-6 gap-y-3 font-mono text-[10px] tracking-[0.1em] uppercase">
            <Provenance label="dataset">
              {hashPrefix(personas.content_hash)}
            </Provenance>
            <Provenance label="window ends">
              {formatStamp(personas.analysis_as_of)}
            </Provenance>
            <Provenance label="people">{String(health.users_loaded)}</Provenance>
            <Provenance label="rejected records">
              {String(health.rejections)}
            </Provenance>
            <Provenance label="ingest">
              {health.ingest_status ?? "not recorded"}
            </Provenance>
          </dl>

          <p className="mt-4 max-w-[75ch] text-xs leading-relaxed text-muted">
            Findings are computed from this dataset by deterministic rules.
            Every access change is approved by a person; this service cannot
            change anyone&apos;s access.
          </p>
        </div>
      </footer>
    );
  } catch {
    return (
      <footer className="mt-12 border-t border-rule">
        <div className="mx-auto max-w-5xl px-4 py-5 sm:px-6">
          <p className="font-mono text-[10px] tracking-[0.1em] text-muted uppercase">
            Dataset provenance unavailable — the analysis service did not answer
          </p>
        </div>
      </footer>
    );
  }
}

function Provenance({
  label,
  children,
}: {
  label: string;
  children: React.ReactNode;
}) {
  return (
    <div>
      <dt className="text-faint">{label}</dt>
      <dd className="wrap-anywhere mt-0.5 text-[11px] text-ink">{children}</dd>
    </div>
  );
}
