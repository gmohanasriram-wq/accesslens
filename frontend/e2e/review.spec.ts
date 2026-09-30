import { expect, test } from "@playwright/test";

import {
  EXPECTED_FINDING_COUNT,
  getAnalysis,
  orderedIds,
  sel,
  findingsFor,
  type Json,
} from "./support";

/**
 * `/` — the review queue.
 *
 * The queue's whole job is to be a faithful view of `analyze()`'s output, so
 * every assertion here is a comparison against `/api/analysis` rather than
 * against a written-down list of rows. A rule that starts firing changes both
 * sides; a UI that drops a finding changes only one.
 */

test("the review lists every finding the engine produced", async ({
  page,
  request,
}) => {
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();

  const analysis = await getAnalysis(request);
  expect(analysis.findings).toHaveLength(EXPECTED_FINDING_COUNT);

  await expect(page.locator(sel.queueRow)).toHaveCount(analysis.findings.length);
});

test("the review preserves the engine's order rather than re-sorting it", async ({
  page,
  request,
}) => {
  await page.goto("/");
  await expect(page.locator(sel.queueRow).first()).toBeVisible();

  const analysis = await getAnalysis(request);
  const rendered = await page
    .locator(sel.queueRow)
    .evaluateAll((rows) => rows.map((row) => row.getAttribute("data-finding-id")));

  // The engine's order is user-major and severity-descending, so one person's
  // two findings stay adjacent. A view that sorted by severity across everyone
  // would scatter Carol's two facts and invite counting them as two people.
  expect(rendered).toEqual(orderedIds(analysis));
});

test("every row names its person and links to that finding's dossier", async ({
  page,
  request,
}) => {
  await page.goto("/");
  const analysis = await getAnalysis(request);
  const first: Json = analysis.findings[0];

  const row = page.locator(`[data-finding-id="${first.id}"]`);
  await expect(row).toBeVisible();
  await expect(row).toContainText(first.subject.username);

  const link = row.getByRole("link").first();
  await expect(link).toHaveAttribute("href", `/findings/${first.id}`);
});

test("a person carrying two findings is shown carrying two", async ({
  page,
  request,
}) => {
  await page.goto("/");
  const analysis = await getAnalysis(request);
  const carol = findingsFor(analysis, "carol.diaz");

  expect(carol).toHaveLength(2);
  for (const finding of carol) {
    await expect(page.locator(`[data-finding-id="${finding.id}"]`)).toBeVisible();
  }
});

test("severity is stated in text, not carried by colour alone", async ({
  page,
}) => {
  await page.goto("/");
  await expect(page.locator(sel.queueRow).first()).toBeVisible();

  const rows = page.locator(sel.queueRow);
  for (const row of await rows.all()) {
    const severity = await row.getAttribute("data-severity");
    expect(severity).toBeTruthy();
    // A reviewer with a colour deficiency, or reading a printout, must still be
    // able to tell a critical finding from an informational one.
    await expect(row).toContainText(severity!);
  }
});

test("the queue states the window and the dataset it was computed from", async ({
  page,
  request,
}) => {
  await page.goto("/");
  const analysis = await getAnalysis(request);

  // A finding with no window and no hash is a claim; with them it is a citation.
  await expect(page.locator("body")).toContainText(analysis.content_hash.slice(0, 12));
  await expect(page.locator("body")).toContainText("2026");
});

test("the queue reports how much input the ingest could not use", async ({
  page,
  request,
}) => {
  await page.goto("/");
  const analysis = await getAnalysis(request);

  // Three rejected records is why a finding may be absent, so it is a fact
  // about the review rather than about the plumbing.
  expect(analysis.rejections).toBe(3);
  await expect(page.locator("body")).toContainText(String(analysis.rejections));
});
