/**
 * How each engine value is drawn.
 *
 * Two rules hold everywhere in this file.
 *
 * **Values are rendered verbatim.** `HIGH_PRIVILEGE_LOW_USAGE` is printed with
 * its underscores, not spaced into "High privilege low usage". That is not
 * fastidiousness: a spaced-out reading of the enum is a sentence, and a
 * sentence is something an auditor can be asked to defend, whereas the enum is
 * a name for a rule. It also means the screen and the API and the rule module
 * all use one word for one thing, and the wire format stays greppable.
 *
 * **Colour is an intensifier, never the message.** Severity is a single ramp --
 * sealed oxblood for `CRITICAL` down to a bare hairline for `INFO` -- rather
 * than a traffic-light rainbow, and the severity word is always set in text
 * beside it. A reviewer reading a printout, or with a colour deficiency, loses
 * nothing. Every class string below is a literal so Tailwind can see it.
 */

import type {
  Coverage,
  FindingStatus,
  RiskLevel,
  Severity,
  UsageObservation,
} from "@/types/api";

/** The severity tab in the register's margin: one hue at five intensities. */
const SEVERITY_BAND: Record<Severity, string> = {
  CRITICAL: "border-l-seal",
  HIGH: "border-l-signal",
  MEDIUM: "border-l-faint",
  LOW: "border-l-rule-strong",
  INFO: "border-l-rule",
};

const SEVERITY_INK: Record<Severity, string> = {
  CRITICAL: "text-seal",
  HIGH: "text-signal",
  MEDIUM: "text-ink",
  LOW: "text-muted",
  INFO: "text-faint",
};

/**
 * What state the finding is in, as a stamp.
 *
 * `PROTECTED` is deliberately in the calm pine rather than in a warning
 * colour. It is the one status that means "a control is working as configured";
 * painting it amber would tell a reviewer to go and change something.
 */
const STATUS_STAMP: Record<FindingStatus, string> = {
  REVIEW_REQUIRED: "border-signal bg-signal-ground text-signal",
  INVESTIGATION_REQUIRED: "border-seal bg-seal-ground text-seal",
  PROTECTED: "border-verified bg-verified-ground text-verified",
  INSUFFICIENT_EVIDENCE: "border-rule bg-card-sunk text-muted",
  INFORMATIONAL: "border-rule bg-card-sunk text-muted",
  CLOSED: "border-rule bg-card-sunk text-faint",
};

const RISK_INK: Record<RiskLevel, string> = {
  CRITICAL: "text-seal",
  HIGH: "text-signal",
  MEDIUM: "text-ink",
  LOW: "text-muted",
  UNKNOWN: "text-faint",
};

const COVERAGE_STAMP: Record<Coverage, string> = {
  COMPLETE: "border-verified bg-verified-ground text-verified",
  PARTIAL: "border-signal bg-signal-ground text-signal",
  MISSING: "border-seal bg-seal-ground text-seal",
  NOT_QUERIED: "border-rule bg-card-sunk text-muted",
};

/**
 * `NONE_OBSERVED` and `UNKNOWN` are drawn differently on purpose.
 *
 * The first is a measurement -- full coverage, nothing seen -- and is set in
 * plain ink, a fact. The second is the absence of a measurement, and is the one
 * value drawn with a dashed border: unfilled, because that is what it is.
 * Anything that made them look alike would be the bug this product exists to
 * prevent.
 */
const USAGE_STAMP: Record<UsageObservation, string> = {
  HIGH: "border-seal bg-seal-ground text-seal",
  MODERATE: "border-signal bg-signal-ground text-signal",
  LOW: "border-rule bg-card-sunk text-ink",
  OBSERVED: "border-verified bg-verified-ground text-verified",
  NONE_OBSERVED: "border-rule-strong bg-card text-ink",
  UNKNOWN: "border-dashed border-rule-strong bg-card text-muted",
};

export const severityBand = (severity: Severity) => SEVERITY_BAND[severity];
export const severityInk = (severity: Severity) => SEVERITY_INK[severity];
export const statusStamp = (status: FindingStatus) => STATUS_STAMP[status];
export const riskInk = (risk: RiskLevel) => RISK_INK[risk];
export const coverageStamp = (coverage: Coverage) => COVERAGE_STAMP[coverage];
export const usageStamp = (usage: UsageObservation) => USAGE_STAMP[usage];

/** The colour of a timeline dot, borrowed from the severity it belongs to. */
export const timelineDot = (severity: Severity) => {
  if (severity === "CRITICAL") return "bg-seal";
  if (severity === "HIGH") return "bg-signal";
  if (severity === "MEDIUM") return "bg-faint";
  return "bg-rule-strong";
};
