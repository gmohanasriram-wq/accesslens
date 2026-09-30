"use client";

import { useEffect, useState } from "react";
import type {
  ExportableAuditorDossier,
  Finding,
  PersonaSummary,
  RecommendationDecision,
  StructuredInvestigationResult,
} from "@/types/api";
import { Panel, Stamp } from "@/components/ui";

interface ReviewerDecisionCardProps {
  finding: Finding;
  subject: PersonaSummary;
  investigation: StructuredInvestigationResult | null;
}

interface DecisionOption {
  value: RecommendationDecision;
  label: string;
  badgeClass: string;
}

const DECISIONS: DecisionOption[] = [
  {
    value: "PENDING",
    label: "Pending Review",
    badgeClass: "border-faint bg-card-sunk text-muted",
  },
  {
    value: "APPROVED",
    label: "Approve Recommendation",
    badgeClass: "border-verified bg-verified-ground text-verified font-bold",
  },
  {
    value: "REJECTED",
    label: "Reject / Keep Access",
    badgeClass: "border-seal bg-seal-ground text-seal font-bold",
  },
  {
    value: "DEFERRED",
    label: "Defer for Information",
    badgeClass: "border-signal bg-signal-ground text-signal font-bold",
  },
];

export function ReviewerDecisionCard({
  finding,
  subject,
  investigation,
}: ReviewerDecisionCardProps) {
  const [decision, setDecision] = useState<RecommendationDecision>("PENDING");
  const [rationale, setRationale] = useState("");
  const [exported, setExported] = useState(false);

  // Restore decision and rationale from session storage on mount
  useEffect(() => {
    try {
      const savedDecision = sessionStorage.getItem(
        `accesslens_decision_${finding.id}`,
      ) as RecommendationDecision | null;
      if (savedDecision && DECISIONS.some((d) => d.value === savedDecision)) {
        setDecision(savedDecision);
      }
      const savedRationale = sessionStorage.getItem(
        `accesslens_rationale_${finding.id}`,
      );
      if (savedRationale !== null) {
        setRationale(savedRationale);
      }
    } catch {
      // Storage access may be restricted in sandboxed iframes
    }
  }, [finding.id]);

  const handleDecisionChange = (newDecision: RecommendationDecision) => {
    setDecision(newDecision);
    try {
      sessionStorage.setItem(`accesslens_decision_${finding.id}`, newDecision);
    } catch {
      // Ignore storage errors
    }
  };

  const handleRationaleChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    const text = e.target.value;
    setRationale(text);
    try {
      sessionStorage.setItem(`accesslens_rationale_${finding.id}`, text);
    } catch {
      // Ignore storage errors
    }
  };

  const handleExportDossier = () => {
    const exportData: ExportableAuditorDossier = {
      dossier_version: "1.0",
      finding,
      subject,
      investigation,
      reviewer_decision: decision,
      reviewer_rationale: rationale,
      decided_at: decision === "PENDING" ? null : new Date().toISOString(),
      exported_at: new Date().toISOString(),
    };

    const jsonBlob = new Blob([JSON.stringify(exportData, null, 2)], {
      type: "application/json",
    });
    const url = URL.createObjectURL(jsonBlob);
    const link = document.createElement("a");
    link.href = url;
    link.download = `accesslens-dossier-${finding.id}.json`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);

    setExported(true);
    setTimeout(() => setExported(false), 3000);
  };

  const activeMeta = DECISIONS.find((d) => d.value === decision) ?? DECISIONS[0];

  return (
    <Panel
      title="Human Reviewer Adjudication"
      aside={
        <div className="flex items-center gap-2" data-testid="decision-status">
          <Stamp className={activeMeta.badgeClass}>{decision}</Stamp>
        </div>
      }
    >
      <div className="space-y-5" data-testid="reviewer-decision-card">
        <div>
          <p className="text-xs leading-relaxed text-muted">
            AccessLens never modifies permissions automatically. A human reviewer evaluates
            the deterministic findings, telemetry evidence, and AI investigation questions before
            recording an attested decision.
          </p>
        </div>

        {/* Decision Buttons */}
        <div>
          <label className="block font-mono text-[10px] tracking-[0.14em] text-faint uppercase mb-2">
            Attested Reviewer Decision
          </label>
          <div
            role="radiogroup"
            aria-label="Reviewer decision"
            className="grid grid-cols-2 gap-2 sm:grid-cols-4"
          >
            {DECISIONS.map((opt) => {
              const isSelected = decision === opt.value;
              return (
                <button
                  key={opt.value}
                  type="button"
                  data-testid={`decision-btn-${opt.value.toLowerCase()}`}
                  onClick={() => handleDecisionChange(opt.value)}
                  className={`border px-3 py-2 text-left transition-colors sm:px-3 sm:py-2.5 ${isSelected
                    ? "border-accent bg-accent/10 shadow-sm"
                    : "border-rule bg-card hover:bg-card-sunk/60"
                    }`}
                >
                  <div className="font-mono text-[11px] font-semibold text-ink">
                    {opt.label}
                  </div>
                  <div className="mt-0.5 font-mono text-[10px] text-faint uppercase">
                    {opt.value}
                  </div>
                </button>
              );
            })}
          </div>
        </div>

        {/* Reviewer Rationale & Audit Notes */}
        <div>
          <label
            htmlFor="reviewer-rationale"
            className="block font-mono text-[10px] tracking-[0.14em] text-faint uppercase mb-1.5"
          >
            Reviewer Rationale & Audit Notes
          </label>
          <textarea
            id="reviewer-rationale"
            data-testid="reviewer-rationale-input"
            value={rationale}
            onChange={handleRationaleChange}
            rows={3}
            placeholder="Record justification, mitigating circumstances, or specific supervisor consultation details..."
            className="w-full border border-rule bg-card px-3 py-2 font-mono text-xs text-ink placeholder:text-faint focus:border-accent focus:outline-none"
          />
        </div>

        {/* Export Auditor Dossier */}
        <div className="flex flex-wrap items-center justify-between gap-3 border-t border-rule/50 pt-4">
          <button
            type="button"
            data-testid="export-dossier-btn"
            onClick={handleExportDossier}
            className="border border-rule bg-card px-3.5 py-1.5 font-mono text-xs font-medium text-ink transition-colors hover:border-accent hover:bg-accent/10 sm:px-4 sm:py-2"
          >
            {exported ? "✓ Dossier Downloaded" : "Export Auditor Dossier (.json)"}
          </button>
          {exported && (
            <span
              data-testid="export-success-indicator"
              className="font-mono text-[11px] text-verified"
            >
              Dossier JSON saved to local downloads
            </span>
          )}
          <span className="font-mono text-[10px] tracking-[0.12em] text-faint uppercase">
            Session-scoped · Zero backend mutation · Audit-ready export
          </span>
        </div>
      </div>
    </Panel>
  );
}
