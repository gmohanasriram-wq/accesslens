import { connection } from "next/server";

import { FindingRow } from "@/components/FindingRow";
import { ErrorPanel, describeError } from "@/components/ui";
import { fetchAnalysis } from "@/lib/api";
import type { AnalysisResponse } from "@/types/api";

/**
 * `/forensics` — deprovisioning.
 *
 * The view filters the engine's output by the engine's own `type`. It does not
 * compare termination dates to activity timestamps, and it does not decide
 * whether an account stayed usable after someone left: that is a security
 * decision Rule D already made, deterministically and with its evidence
 * attached. Re-deciding it in TypeScript would be a second implementation of a
 * rule, in a language the engine's tests do not cover, unlogged — and the two
 * would eventually disagree, with the browser's answer being the one a reviewer
 * happened to see.
 *
 * So the filter here is one line, and it is the whole of this page's logic.
 */

const GHOST_ACCESS = "GHOST_ACCESS";

export default async function ForensicsPage() {
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

  const findings = analysis.findings.filter(
    (finding) => finding.type === GHOST_ACCESS,
  );

  return (
    <>
      <PageHeading
        lede={
          findings.length === 0
            ? "The engine classified nothing in this window as access outliving the account it belonged to."
            : `${findings.length} ${
                findings.length === 1 ? "case" : "cases"
              } where a credential was still usable after the account it belonged to was closed. Each one opens onto the sequence the rule recorded, in the order it happened.`
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
        Deprovisioning forensics
      </h1>
      {lede ? (
        <p className="mt-3 max-w-[75ch] text-sm leading-relaxed text-muted">
          {lede}
        </p>
      ) : null}
    </header>
  );
}
