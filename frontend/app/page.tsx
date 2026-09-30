import { connection } from "next/server";

import { FindingRow } from "@/components/FindingRow";
import { ErrorPanel, describeError } from "@/components/ui";
import { fetchAnalysis } from "@/lib/api";
import { formatDate } from "@/lib/format";
import type { AnalysisResponse } from "@/types/api";

/**
 * `/` — the review queue.
 *
 * The page is a faithful view of `analyze()`: the same findings, in the same
 * order, with nothing filtered, ranked or grouped in the browser. The engine
 * ordered the sweep person-major and severity-descending so that one person's
 * two findings stay adjacent and are not read as two people's problems; a view
 * that re-sorted by severity across everybody would silently destroy that, and
 * nothing would fail, because the same rows would still be on the page.
 *
 * `connection()` puts the route into request-time rendering. The alternative,
 * `force-dynamic`, throws away the data cache along with the prerender; this
 * keeps `next: { revalidate: 10 }` on the fetches and only declines to
 * *pre*-render. Without it, `next build` would render every view with the API
 * down, catch the failure state, and bake it into the static output — an
 * access-review console that ships an outage notice as its first impression.
 */
export default async function ReviewPage() {
  await connection();

  let analysis: AnalysisResponse;
  try {
    analysis = await fetchAnalysis();
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

  const { findings } = analysis;
  const people = new Set(findings.map((finding) => finding.user_id)).size;

  return (
    <>
      <PageHeading
        lede={
          findings.length === 0
            ? "The rules produced nothing to review for this window. That is a result, not a guarantee — check the coverage page for sources that were never delivered."
            : `${findings.length} findings across ${people} ${
                people === 1 ? "person" : "people"
              }, over ${formatDate(analysis.window_start)} to ${formatDate(
                analysis.window_end,
              )}. A finding is a reason to look at something, not an instruction to change it.`
        }
      />

      {findings.length === 0 ? null : (
        <ol className="mt-6 border border-rule">
          {findings.map((finding) => (
            <FindingRow key={finding.id} finding={finding} />
          ))}
        </ol>
      )}
    </>
  );
}

function PageHeading({ lede }: { lede?: string }) {
  return (
    <header>
      <h1 className="font-display text-3xl tracking-tight text-ink sm:text-4xl">
        Access review
      </h1>
      {lede ? (
        <p className="mt-3 max-w-[75ch] text-sm leading-relaxed text-muted">
          {lede}
        </p>
      ) : null}
    </header>
  );
}
