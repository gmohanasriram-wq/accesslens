import { expect, test } from "@playwright/test";

import {
  EXPECTED_PERSONA_COUNT,
  getAnalysis,
  getPersonas,
} from "./support";

/**
 * `/data` — the Phase 1 coverage and ingest page, moved rather than replaced.
 *
 * Phase 3 adds a review surface on top of Phase 1's stack proof. The temptation
 * is to delete the old page as scaffolding. It is not scaffolding: it is the
 * only view of the *raw record* -- who was ingested, how much of each source
 * actually arrived, which records were discarded and why. The findings view
 * cites the dataset; this is where a reviewer goes to check it.
 *
 * These specs exist so the move is a move. If the page is dropped, or its
 * coverage verdicts stop being rendered, the suite says so.
 */

test("the coverage page still reports ingest health and rejected records", async ({
  page,
  request,
}) => {
  const health = await (await request.get("http://127.0.0.1:8000/api/health")).json();

  await page.goto("/data");

  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
  await expect(page.locator("body")).toContainText(health.ingest_status);
  await expect(page.locator("body")).toContainText(String(health.rejections));
  await expect(page.locator("body")).toContainText(String(health.users_loaded));
});

test("the coverage page still renders every persona's coverage verdict", async ({
  page,
  request,
}) => {
  const personas = await getPersonas(request);
  expect(personas.personas).toHaveLength(EXPECTED_PERSONA_COUNT);

  await page.goto("/data");

  await expect(page.getByRole("table").getByRole("row")).toHaveCount(
    EXPECTED_PERSONA_COUNT + 1, // header row
  );

  // The page's reason for existing: `UNKNOWN` is its own state, not "no activity".
  for (const persona of personas.personas) {
    await expect(page.locator("body")).toContainText(persona.username);
    await expect(page.locator("body")).toContainText(persona.activity.coverage);
  }
});

test("the coverage page still explains the gaps rather than just counting them", async ({
  page,
  request,
}) => {
  const personas = await getPersonas(request);
  const gina = personas.personas.find((p: any) => p.username === "gina.patel");
  expect(gina.activity.gaps.length).toBeGreaterThan(0);

  await page.goto("/data");

  for (const gap of gina.activity.gaps) {
    await expect(page.locator("body")).toContainText(gap);
  }
});

test("the coverage page and the review surface name the same dataset", async ({
  page,
  request,
}) => {
  const analysis = await getAnalysis(request);
  const prefix = analysis.content_hash.slice(0, 12);

  await page.goto("/data");
  await expect(page.locator("body")).toContainText(prefix);

  await page.goto("/");
  await expect(page.locator("body")).toContainText(prefix);
});

test("both views are reachable from the navigation", async ({ page }) => {
  await page.goto("/");

  const nav = page.getByRole("navigation");
  await expect(nav).toBeVisible();

  await nav.getByRole("link", { name: /data|coverage|ingest/i }).click();
  await expect(page).toHaveURL(/\/data$/);
});
