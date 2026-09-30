import { expect, test } from "@playwright/test";
import {
  FORBIDDEN_CONCLUSION_PHRASES,
  findingFor,
  getAnalysis,
  mustNotSayFor,
} from "./support";

/**
 * End-to-end tests for the Phase 4 AI Investigation Panel & Reviewer Adjudication.
 *
 * Verifies:
 * 1. AI Trial Lawyer investigation panel rendering (factual summary, facts vs inferences,
 *    adversarial cross-examination questions, and investigative next steps).
 * 2. Coverage gap notices on unmeasured personas (Gina Patel).
 * 3. Human reviewer adjudication flow (PENDING -> APPROVED/REJECTED/DEFERRED).
 * 4. Session persistence of reviewer decision and audit notes.
 * 5. Exportable Auditor Dossier JSON generation and download.
 * 6. Responsive mobile viewport layout (375x667).
 * 7. Preservation of the forbidden conclusion phrase denylist.
 */

test("the investigation panel renders factual analysis, adversarial questions, and next steps", async ({
  page,
  request,
}) => {
  const analysis = await getAnalysis(request);
  const bob = findingFor(analysis, "bob.chen");

  await page.goto(`/findings/${bob.id}`);

  // Investigation panel is visible
  const panel = page.locator('[data-testid="investigation-panel"]');
  await expect(panel).toBeVisible();

  // Core sections rendered
  await expect(panel).toContainText("AI Trial Lawyer — Forensic Analysis");
  await expect(panel).toContainText("Investigative Support Only");
  await expect(panel).toContainText("Factual Summary");
  await expect(panel).toContainText("Verified Telemetry Facts");
  await expect(panel).toContainText("Analytical Inferences");
  await expect(panel).toContainText("Adversarial Cross-Examination Questions");
  await expect(panel).toContainText("Investigative Next Steps");
});

test("gina's investigation reflects insufficient evidence and coverage gaps without clean claims", async ({
  page,
  request,
}) => {
  const analysis = await getAnalysis(request);
  const gina = findingFor(analysis, "gina.patel");

  await page.goto(`/findings/${gina.id}`);

  const panel = page.locator('[data-testid="investigation-panel"]');
  await expect(panel).toBeVisible();

  // Displays insufficient evidence status and coverage gaps
  await expect(panel).toContainText("INSUFFICIENT_EVIDENCE");
  await expect(panel).toContainText("Uncertainty & Coverage Gaps");

  // Denylist verification: page must not claim Gina is clean or safe
  const text = (await page.locator("body").innerText()).toLowerCase();
  const forbidden = [...FORBIDDEN_CONCLUSION_PHRASES, ...mustNotSayFor("gina.patel")];
  for (const phrase of forbidden) {
    expect(text, `gina's page contains forbidden phrase ${JSON.stringify(phrase)}`).not.toContain(
      phrase.toLowerCase(),
    );
  }
});

test("reviewer can record an attested decision and notes with session persistence", async ({
  page,
  request,
}) => {
  const analysis = await getAnalysis(request);
  const bob = findingFor(analysis, "bob.chen");

  await page.goto(`/findings/${bob.id}`);

  const statusBadge = page.locator('[data-testid="decision-status"]');
  const rationaleInput = page.locator('[data-testid="reviewer-rationale-input"]');

  // Initial state is PENDING
  await expect(statusBadge).toContainText("PENDING");

  // Select APPROVED
  await page.locator('[data-testid="decision-btn-approved"]').click();
  await expect(statusBadge).toContainText("APPROVED");

  // Type rationale
  const note = "Approved downscoping to read-only roles after discussion with manager.";
  await rationaleInput.fill(note);

  // Reload page to verify session persistence
  await page.reload();

  await expect(page.locator('[data-testid="decision-status"]')).toContainText("APPROVED");
  await expect(page.locator('[data-testid="reviewer-rationale-input"]')).toHaveValue(note);
});

test("reviewer can export an Exportable Auditor Dossier JSON bundle", async ({
  page,
  request,
}) => {
  const analysis = await getAnalysis(request);
  const bob = findingFor(analysis, "bob.chen");

  await page.goto(`/findings/${bob.id}`);

  // Set a decision and note
  await page.locator('[data-testid="decision-btn-deferred"]').click();
  const note = "Deferred pending verification of proxy logs from Q2.";
  await page.locator('[data-testid="reviewer-rationale-input"]').fill(note);

  // Listen for the download event
  const downloadPromise = page.waitForEvent("download");
  await page.locator('[data-testid="export-dossier-btn"]').click();
  const download = await downloadPromise;

  // Confirm download filename matches pattern
  expect(download.suggestedFilename()).toBe(`accesslens-dossier-${bob.id}.json`);

  // Verify downloaded JSON content structure
  const readable = await download.createReadStream();
  if (!readable) {
    throw new Error("Unable to read downloaded dossier stream");
  }
  const chunks: Buffer[] = [];
  for await (const chunk of readable) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  const jsonContent = JSON.parse(Buffer.concat(chunks).toString("utf-8"));

  expect(jsonContent.dossier_version).toBe("1.0");
  expect(jsonContent.finding.id).toBe(bob.id);
  expect(jsonContent.subject.username).toBe("bob.chen");
  expect(jsonContent.reviewer_decision).toBe("DEFERRED");
  expect(jsonContent.reviewer_rationale).toBe(note);
  expect(jsonContent.investigation).not.toBeNull();
  expect(jsonContent.investigation.finding_id).toBe(bob.id);
  expect(jsonContent.exported_at).toBeDefined();

  // Success indicator visible in UI
  await expect(page.locator('[data-testid="export-success-indicator"]')).toBeVisible();
});

test("investigation panel and decision card render properly on mobile viewport (375x667)", async ({
  page,
  request,
}) => {
  await page.setViewportSize({ width: 375, height: 667 });

  const analysis = await getAnalysis(request);
  const bob = findingFor(analysis, "bob.chen");

  await page.goto(`/findings/${bob.id}`);

  const panel = page.locator('[data-testid="investigation-panel"]');
  await expect(panel).toBeVisible();

  const decisionCard = page.locator('[data-testid="reviewer-decision-card"]');
  await expect(decisionCard).toBeVisible();

  // All 4 decision buttons remain clickable and visible on mobile
  await expect(page.locator('[data-testid="decision-btn-pending"]')).toBeVisible();
  await expect(page.locator('[data-testid="decision-btn-approved"]')).toBeVisible();
  await expect(page.locator('[data-testid="decision-btn-rejected"]')).toBeVisible();
  await expect(page.locator('[data-testid="decision-btn-deferred"]')).toBeVisible();

  // Export button visible on mobile
  await expect(page.locator('[data-testid="export-dossier-btn"]')).toBeVisible();
});

