import type { StructuredInvestigationResult } from "@/types/api";
import { Panel, Stamp } from "@/components/ui";
import { formatStamp } from "@/lib/format";

interface InvestigationPanelProps {
  investigation: StructuredInvestigationResult;
}

export function InvestigationPanel({ investigation }: InvestigationPanelProps) {
  const isComplete = investigation.status === "COMPLETED";
  const isInsufficient = investigation.status === "INSUFFICIENT_EVIDENCE";

  return (
    <div data-testid="investigation-panel">
      <Panel
        title="AI Trial Lawyer — Forensic Analysis"
        aside={
          <div className="flex flex-wrap items-center gap-2">
            <Stamp
              className={
                isComplete
                  ? "border-verified bg-verified-ground text-verified"
                  : isInsufficient
                    ? "border-signal bg-signal-ground text-signal"
                    : "border-seal bg-seal-ground text-seal"
              }
            >
              {investigation.status}
            </Stamp>
            <span className="font-mono text-[10px] tracking-[0.14em] text-faint uppercase">
              {investigation.provider_info}
            </span>
          </div>
        }
      >
        <div className="space-y-6">
          {/* Trial Lawyer Mode Banner */}
          <div className="border border-rule bg-card-sunk px-3.5 py-2.5 sm:px-4 sm:py-3">
            <p className="font-mono text-[11px] tracking-[0.12em] text-muted uppercase">
              Investigative Support Only · Not an Autonomous Security Decision
            </p>
            <p className="mt-1 text-xs leading-relaxed text-muted">
              The AI receives structured findings and exhibits to challenge assumptions, identify evidence gaps,
              and draft reviewer questions. AccessLens never alters access automatically; a human decides.
            </p>
          </div>

          {/* Factual Summary */}
          <div>
            <h3 className="font-mono text-[10px] tracking-[0.14em] text-faint uppercase">
              Factual Summary
            </h3>
            <p className="mt-1.5 font-display text-base leading-relaxed text-ink">
              {investigation.factual_summary}
            </p>
          </div>

          {/* Verified Facts vs. Inferences */}
          <div className="grid gap-4 sm:grid-cols-2">
            <div className="border border-rule bg-card px-3.5 py-3 sm:px-4">
              <div className="flex items-center gap-2">
                <span className="inline-block h-2 w-2 rounded-full bg-verified" />
                <h4 className="font-mono text-[10px] tracking-[0.14em] text-verified uppercase">
                  Verified Telemetry Facts
                </h4>
              </div>
              <ul className="mt-2.5 space-y-1.5 text-xs leading-relaxed text-ink">
                {investigation.evidence_vs_inference.verified_facts.length === 0 ? (
                  <li className="text-muted italic">No verified facts recorded.</li>
                ) : (
                  investigation.evidence_vs_inference.verified_facts.map((fact, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <span className="font-mono text-faint select-none">·</span>
                      <span>{fact}</span>
                    </li>
                  ))
                )}
              </ul>
            </div>

            <div className="border border-rule bg-card px-3.5 py-3 sm:px-4">
              <div className="flex items-center gap-2">
                <span className="inline-block h-2 w-2 rounded-full bg-signal" />
                <h4 className="font-mono text-[10px] tracking-[0.14em] text-signal uppercase">
                  Analytical Inferences
                </h4>
              </div>
              <ul className="mt-2.5 space-y-1.5 text-xs leading-relaxed text-ink">
                {investigation.evidence_vs_inference.inferences.length === 0 ? (
                  <li className="text-muted italic">No analytical inferences drawn.</li>
                ) : (
                  investigation.evidence_vs_inference.inferences.map((inf, idx) => (
                    <li key={idx} className="flex items-start gap-2">
                      <span className="font-mono text-faint select-none">·</span>
                      <span>{inf}</span>
                    </li>
                  ))
                )}
              </ul>
            </div>
          </div>

          {/* Supporting Exhibits Cited */}
          {investigation.supporting_evidence.length > 0 && (
            <div>
              <h3 className="font-mono text-[10px] tracking-[0.14em] text-faint uppercase mb-2">
                Supporting Exhibits Cited
              </h3>
              <div className="space-y-2">
                {investigation.supporting_evidence.map((cit) => (
                  <div
                    key={cit.evidence_id}
                    className="flex flex-col gap-1 border-l-2 border-accent/40 bg-card-sunk/50 px-3 py-2 text-xs sm:flex-row sm:items-baseline sm:gap-3"
                  >
                    <span className="font-mono font-medium text-accent">
                      {cit.evidence_id}
                    </span>
                    <span className="text-ink">{cit.relevance}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Uncertainty & Coverage Gaps */}
          {(investigation.uncertainty_and_contradictions.length > 0 ||
            investigation.missing_or_unverified_evidence.length > 0) && (
              <div>
                <h3 className="font-mono text-[10px] tracking-[0.14em] text-faint uppercase mb-2">
                  Uncertainty & Coverage Gaps
                </h3>
                <div className="space-y-2 border border-signal/30 bg-signal-ground/20 p-3 sm:p-4">
                  {investigation.uncertainty_and_contradictions.map((item, idx) => (
                    <div key={`unc-${idx}`} className="flex items-start gap-2 text-xs text-ink">
                      <span className="font-mono text-signal font-bold select-none">⚠</span>
                      <span>{item}</span>
                    </div>
                  ))}
                  {investigation.missing_or_unverified_evidence.map((item, idx) => (
                    <div key={`mis-${idx}`} className="flex items-start gap-2 text-xs text-muted">
                      <span className="font-mono text-faint font-bold select-none">✕</span>
                      <span>{item}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

          {/* Adversarial Cross-Examination Questions */}
          {investigation.adversarial_questions.length > 0 && (
            <div>
              <h3 className="font-mono text-[10px] tracking-[0.14em] text-faint uppercase mb-2">
                Adversarial Cross-Examination Questions
              </h3>
              <div className="border border-seal/30 bg-seal-ground/20 p-3 sm:p-4">
                <p className="font-mono text-[11px] text-seal mb-2">
                  Challenge these questions before making a determination:
                </p>
                <ol className="list-decimal list-inside space-y-1.5 text-xs text-ink">
                  {investigation.adversarial_questions.map((q, idx) => (
                    <li key={idx} className="leading-relaxed">
                      {q}
                    </li>
                  ))}
                </ol>
              </div>
            </div>
          )}

          {/* Investigative Next Steps */}
          {investigation.investigation_next_steps.length > 0 && (
            <div>
              <h3 className="font-mono text-[10px] tracking-[0.14em] text-faint uppercase mb-2">
                Investigative Next Steps
              </h3>
              <ul className="space-y-1.5 border border-rule bg-card p-3 sm:p-4 text-xs text-ink">
                {investigation.investigation_next_steps.map((step, idx) => (
                  <li key={idx} className="flex items-start gap-2">
                    <span className="font-mono text-accent select-none">→</span>
                    <span>{step}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* Provenance Footer */}
          <div className="border-t border-rule/60 pt-3">
            <p className="font-mono text-[10px] tracking-[0.12em] text-faint uppercase">
              Investigation generated at {formatStamp(investigation.generated_at)}
            </p>
          </div>
        </div>
      </Panel>
    </div>
  );
}
