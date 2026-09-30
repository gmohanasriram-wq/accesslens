import { expect, test } from "@playwright/test";

import { getAnalysis, getDossier, sel, type Json } from "./support";

/**
 * `/forensics` — the deprovisioning view.
 *
 * The important property is that this view **derives nothing**. Whether an
 * account stayed usable after someone left is a security decision Rule D
 * already made; the browser's job is to filter the engine's output by the
 * engine's own `type` field and draw the timeline the engine already recorded
 * as evidence.
 *
 * A view that re-decided "is this ghost access?" from termination dates and
 * activity would be a second implementation of a security rule, in TypeScript,
 * unlogged and untested -- and the two would eventually disagree.
 */

const GHOST_ACCESS = "GHOST_ACCESS";

function ghostFindings(analysis: Json): Json[] {
  return analysis.findings.filter((f: Json) => f.type === GHOST_ACCESS);
}

test("forensics lists exactly the findings the engine classified as ghost access", async ({
  page,
  request,
}) => {
  const analysis = await getAnalysis(request);
  const expected = ghostFindings(analysis);

  expect(expected.length).toBeGreaterThan(0);

  await page.goto("/forensics");
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();

  await expect(page.locator(sel.queueRow)).toHaveCount(expected.length);

  const rendered = await page
    .locator(sel.queueRow)
    .evaluateAll((rows) => rows.map((row) => row.getAttribute("data-finding-id")));
  expect(rendered.sort()).toEqual(expected.map((f: Json) => f.id).sort());
});

test("forensics re-derives nothing: every row is a finding the engine called ghost access", async ({
  page,
}) => {
  await page.goto("/forensics");
  await expect(page.locator(sel.queueRow).first()).toBeVisible();

  const types = await page
    .locator(sel.queueRow)
    .evaluateAll((rows) => rows.map((row) => row.getAttribute("data-finding-type")));

  expect(types.length).toBeGreaterThan(0);
  for (const type of types) {
    expect(type).toBe(GHOST_ACCESS);
  }
});

test("a ghost-access case draws the timeline in the order the engine recorded it", async ({
  page,
  request,
}) => {
  const analysis = await getAnalysis(request);
  const ghost = ghostFindings(analysis)[0];
  const dossier = await getDossier(request, ghost.id);

  // The timeline is evidence the rule emitted, not a story the page assembles.
  const ordered = dossier.finding.evidence.filter(
    (e: Json) => e.kind === "TIMELINE_POINT",
  );
  expect(ordered.length).toBeGreaterThan(1);

  await page.goto(`/findings/${ghost.id}`);

  const rendered = await page
    .locator(sel.timelinePoint)
    .evaluateAll((points) =>
      points.map((point) => point.getAttribute("data-timeline-point")),
    );

  expect(rendered).toEqual(ordered.map((e: Json) => e.evidence_id));
});

test("the timeline states the moment access ended and the activity that outlived it", async ({
  page,
  request,
}) => {
  const analysis = await getAnalysis(request);
  const ghost = ghostFindings(analysis)[0];

  await page.goto(`/findings/${ghost.id}`);
  await expect(page.locator(sel.timelinePoint).first()).toBeVisible();

  // Every point on the line carries a visible timestamp. A sequence of events
  // with no times is an anecdote.
  const points = page.locator(sel.timelinePoint);
  for (const point of await points.all()) {
    await expect(point).toContainText(/\d{4}/);
  }
});

test("a ghost-access row leads to the dossier that explains it", async ({
  page,
  request,
}) => {
  const analysis = await getAnalysis(request);
  const ghost = ghostFindings(analysis)[0];

  await page.goto("/forensics");
  await page.locator(`[data-finding-id="${ghost.id}"]`).getByRole("link").first().click();

  await expect(page).toHaveURL(new RegExp(`/findings/${ghost.id}$`));
  await expect(page.locator(sel.exhibit).first()).toBeVisible();
});
