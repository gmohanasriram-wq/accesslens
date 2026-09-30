import { expect, test } from "@playwright/test";

import {
  EXPECTED_EXHIBIT_COUNT,
  FORBIDDEN_CONCLUSION_PHRASES,
  findingFor,
  findingsFor,
  getAnalysis,
  getDossier,
  getPersonas,
  mustNotSayFor,
  sel,
} from "./support";

/**
 * `/findings/[id]` — the auditor dossier.
 *
 * Two things are being verified, and only one of them is layout.
 *
 * The first is **completeness**: every exhibit the engine attached is on the
 * page, and the dossier is reachable from the queue. A dossier that quietly
 * dropped a coverage statement would look tidier and would be lying.
 *
 * The second is **restraint**: the page must not say more than the evidence
 * supports. Alice's break-glass role is the case that matters -- her evidence
 * genuinely proves she never used it, and the correct rendering is still that
 * nothing should be removed. That is the single most valuable assertion in this
 * suite, because it is the one a well-meaning copy edit would break.
 */

test("the dossier renders the finding the queue linked to", async ({
  page,
  request,
}) => {
  const analysis = await getAnalysis(request);
  const bob = findingFor(analysis, "bob.chen");
  const dossier = await getDossier(request, bob.id);

  await page.goto(`/findings/${bob.id}`);

  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  await expect(page.locator(sel.queueRow).first()).toHaveAttribute(
    "data-finding-id",
    bob.id,
  );
  await expect(page.locator("body")).toContainText(dossier.finding.summary);
  await expect(page.locator("body")).toContainText(dossier.finding.recommendation);
});

test("every exhibit the engine produced is on the page", async ({
  page,
  request,
}) => {
  const analysis = await getAnalysis(request);

  for (const finding of analysis.findings) {
    const dossier = await getDossier(request, finding.id);
    await page.goto(`/findings/${finding.id}`);

    await expect(page.locator(sel.exhibit)).toHaveCount(
      dossier.finding.evidence.length,
    );
  }
});

test("every exhibit in the fixture population is reachable exactly once", async ({
  page,
  request,
}) => {
  const analysis = await getAnalysis(request);

  const seen: string[] = [];
  for (const finding of analysis.findings) {
    await page.goto(`/findings/${finding.id}`);
    await expect(page.locator(sel.exhibit).first()).toBeVisible();

    seen.push(
      ...(await page
        .locator(sel.exhibit)
        .evaluateAll((items) =>
          items.map((item) => item.getAttribute("data-evidence-id") ?? ""),
        )),
    );
  }

  expect(seen).toHaveLength(EXPECTED_EXHIBIT_COUNT);
  expect(new Set(seen).size).toBe(EXPECTED_EXHIBIT_COUNT);
});

test("the dossier names the control that fired and the person it is about", async ({
  page,
  request,
}) => {
  const analysis = await getAnalysis(request);
  const carol = findingsFor(analysis, "carol.diaz")[0];
  const dossier = await getDossier(request, carol.id);

  await page.goto(`/findings/${carol.id}`);

  for (const rule of dossier.finding.rules_triggered) {
    await expect(page.locator("body")).toContainText(rule);
  }

  // The grant is what the finding is about, so it travels with the dossier.
  const persona = dossier.subject;
  await expect(page.locator("body")).toContainText(persona.username);
  await expect(page.locator("body")).toContainText(persona.entitlements[0].role);
});

test("the dossier shows the person's other findings rather than hiding them", async ({
  page,
  request,
}) => {
  const analysis = await getAnalysis(request);
  const carol = findingsFor(analysis, "carol.diaz");
  const [first, second] = carol;

  await page.goto(`/findings/${first.id}`);

  await expect(page.locator("body")).toContainText(second.type);
});

test("alice's dossier never concludes more than the evidence supports", async ({
  page,
  request,
}) => {
  const analysis = await getAnalysis(request);
  const alice = findingFor(analysis, "alice.nguyen");

  await page.goto(`/findings/${alice.id}`);
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();

  const text = (await page.locator("body").innerText()).toLowerCase();
  const forbidden = [...FORBIDDEN_CONCLUSION_PHRASES, ...mustNotSayFor("alice.nguyen")];

  for (const phrase of forbidden) {
    expect(text, `alice's dossier says ${JSON.stringify(phrase)}`).not.toContain(
      phrase.toLowerCase(),
    );
  }
});

test("a person we could not observe is rendered as unmeasured, not as clean", async ({
  page,
  request,
}) => {
  const analysis = await getAnalysis(request);
  const gina = findingFor(analysis, "gina.patel");

  await page.goto(`/findings/${gina.id}`);
  await expect(page.locator(`[data-finding-id="${gina.id}"]`)).toBeVisible();

  // "0 events" and "we could not look" are different answers, and only one of
  // them is safe. The page has to say which one it is.
  await expect(page.locator('[data-coverage-state="MISSING"]')).toBeVisible();

  const text = (await page.locator("body").innerText()).toLowerCase();
  const forbidden = [...FORBIDDEN_CONCLUSION_PHRASES, ...mustNotSayFor("gina.patel")];
  for (const phrase of forbidden) {
    expect(text, `gina's dossier says ${JSON.stringify(phrase)}`).not.toContain(
      phrase.toLowerCase(),
    );
  }
});

test("an unknown finding id is a not-found page, not an empty dossier", async ({
  page,
}) => {
  const response = await page.goto("/findings/f_no_such_finding");

  // An empty dossier would read as "this person has nothing to report", which
  // is a different claim from "there is no such record".
  expect(response?.status()).toBe(404);
});

test("the dossier's subject matches what /api/personas reports for the same person", async ({
  page,
  request,
}) => {
  const analysis = await getAnalysis(request);
  const personas = await getPersonas(request);
  const bob = findingFor(analysis, "bob.chen");
  const dossier = await getDossier(request, bob.id);

  const expected = personas.personas.find((p: any) => p.id === bob.user_id);
  expect(dossier.subject.username).toBe(expected.username);
  expect(dossier.subject.activity.coverage).toBe(expected.activity.coverage);

  await page.goto(`/findings/${bob.id}`);
  await expect(page.locator("body")).toContainText(expected.activity.coverage);
});
