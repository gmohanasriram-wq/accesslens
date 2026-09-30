import { readFileSync } from "node:fs";
import { join } from "node:path";

import type { APIRequestContext } from "@playwright/test";

/**
 * Shared plumbing for the end-to-end specs.
 *
 * ## The API is the oracle
 *
 * Several specs compare what the page renders against what `/api/analysis`
 * returns, rather than against a hardcoded list. That is deliberate: the
 * question a reviewer cares about is not "does the page show eight rows" but
 * "does the page show *the engine's* eight rows". Reading the expected values
 * from the API means a rule that starts or stops firing changes both sides at
 * once, and the spec still fails if the UI drops one.
 *
 * The counts that *are* hardcoded (eight findings, sixty exhibits, nine
 * personas) are written down on purpose. They are the fixture population, and a
 * silently shrunken population should fail loudly rather than adjust itself.
 *
 * ## The markup contract
 *
 * The specs key off `data-*` attributes rather than visible wording, so that a
 * copy change is a copy change and not a test failure. These attributes are
 * therefore part of what the views must provide:
 *
 * | Attribute                  | On                        | Value                     |
 * |----------------------------|---------------------------|---------------------------|
 * | `data-finding-id`          | each review row, and the  | the engine's `Finding.id` |
 * |                            | dossier root              |                           |
 * | `data-severity`            | each review row           | `Severity` member         |
 * | `data-status`              | each review row           | `FindingStatus` member    |
 * | `data-finding-type`        | each review row           | `FindingType` member      |
 * | `data-evidence-id`         | each exhibit              | `Evidence.evidence_id`    |
 * | `data-timeline-point`      | each timeline entry       | `Evidence.evidence_id`    |
 * | `data-coverage-state`      | a missing-coverage notice | `Coverage` member         |
 *
 * None of them carry information a sighted reader does not also get as text --
 * checked by a spec, because an attribute-only interface would pass these tests
 * while being unusable.
 */

export const API_BASE = process.env.API_BASE_URL ?? "http://127.0.0.1:8000";

/** The fixture population. Written down so a shrunken set fails rather than adapts. */
export const EXPECTED_FINDING_COUNT = 8;
export const EXPECTED_EXHIBIT_COUNT = 60;
export const EXPECTED_PERSONA_COUNT = 9;

export const sel = {
  queueRow: "[data-finding-id]",
  exhibit: "[data-evidence-id]",
  timelinePoint: "[data-timeline-point]",
} as const;

export type Json = Record<string, any>;

async function get(request: APIRequestContext, path: string): Promise<Json> {
  const response = await request.get(`${API_BASE}${path}`);
  if (!response.ok()) {
    throw new Error(
      `GET ${path} -> ${response.status()}. The frontend cannot be verified ` +
        `against an oracle that is not answering.`,
    );
  }
  return response.json();
}

export const getAnalysis = (r: APIRequestContext) => get(r, "/api/analysis");
export const getPersonas = (r: APIRequestContext) => get(r, "/api/personas");
export const getDossier = (r: APIRequestContext, id: string) =>
  get(r, `/api/analysis/findings/${id}`);

/** Every finding's id, in the order the engine returned them. */
export function orderedIds(analysis: Json): string[] {
  return analysis.findings.map((finding: Json) => finding.id);
}

export function findingFor(analysis: Json, username: string): Json {
  const found = analysis.findings.find(
    (finding: Json) => finding.subject.username === username,
  );
  if (!found) throw new Error(`no finding for ${username}`);
  return found;
}

export function findingsFor(analysis: Json, username: string): Json[] {
  return analysis.findings.filter(
    (finding: Json) => finding.subject.username === username,
  );
}

/**
 * The engine's own forbidden vocabulary, copied from
 * `app/schemas/domain/finding.py`.
 *
 * Copied rather than imported because the question is whether a *reviewer's
 * screen* avoids language the evidence cannot support, and that has to be
 * asserted from outside the system that produces the text.
 * `tests/test_analysis.py` asserts the same list at the HTTP boundary.
 */
export const FORBIDDEN_CONCLUSION_PHRASES = [
  "unnecessary",
  "no longer needed",
  "not needed",
  "safe to remove",
  "safe to delete",
  "should be revoked",
  "must be revoked",
  "automatically revoke",
];

/**
 * Each persona's own forbidden words, read from the oracle.
 *
 * Read rather than copied because the oracle *is* the specification, and a
 * persona's `must_not_say` is a claim about that persona specifically: Alice's
 * break-glass role is provably unused, the word "unused" is demonstrably
 * accurate about her, and it is still forbidden -- it is the first step on the
 * road to "so remove it".
 *
 * Applying one global ban would be wrong in the other direction. Carol's
 * ghost-access record correctly states that a credential was *not revoked*;
 * "revoke" appears there in a true sentence and must not be banned globally.
 */
export function mustNotSayFor(username: string): string[] {
  const oracle = loadOracle();
  const persona = oracle.personas.find((p: Json) => p.username === username);
  return persona?.must_not_say ?? [];
}

let cachedOracle: Json | null = null;

function loadOracle(): Json {
  if (cachedOracle) return cachedOracle;
  const path = join(
    process.cwd(),
    "..",
    "backend",
    "tests",
    "fixtures",
    "oracles",
    "expected_findings.json",
  );
  cachedOracle = JSON.parse(readFileSync(path, "utf-8")) as Json;
  return cachedOracle;
}
