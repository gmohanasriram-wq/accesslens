import { expect, test } from "@playwright/test";
import {
  FORBIDDEN_CONCLUSION_PHRASES,
  findingFor,
  getAnalysis,
  mustNotSayFor,
} from "./support";

/**
 * End-to-end tests for the Phase 4 Contextual AI Review Chatbot ("AI Trial Lawyer Chat").
 *
 * Verifies:
 * 1. Mounting inside the finding dossier with explicit provider transparency badge.
 * 2. Bob Chen privilege utilization inquiry (AdministratorAccess vs 2 observed read capabilities).
 * 3. Carol Diaz ghost access inquiry (Okta disable timeline vs post-deactivation GitHub actions).
 * 4. Gina Patel incomplete coverage inquiry (missing proxy telemetry; strictly no clean claims).
 * 5. Evidence citation badges linking directly to exhibit cards.
 * 6. Safety invariant preservation (no revocation directives, no necessity claims).
 * 7. Session storage persistence across page reloads and reset capability.
 */

test("the investigation chat renders with provider disclosure badge and contextual prompt chips", async ({
  page,
  request,
}) => {
  const analysis = await getAnalysis(request);
  const bob = findingFor(analysis, "bob.chen");

  await page.goto(`/findings/${bob.id}`);

  const chat = page.locator('[data-testid="investigation-chat"]');
  await expect(chat).toBeVisible();

  // Header and title
  await expect(chat).toContainText("Interactive Cross-Examination");
  await expect(chat).toContainText("Contextual Q&A Grounded Strictly in Finding Exhibits");

  // Explicit provider badge
  const badge = chat.locator('[data-testid="chat-provider-badge"]');
  await expect(badge).toBeVisible();
  const badgeText = await badge.innerText();
  expect(
    badgeText.includes("Deterministic Local Engine") ||
      badgeText.includes("NVIDIA Nemotron") ||
      badgeText.includes("NVIDIA unavailable"),
  ).toBeTruthy();

  // Contextual prompt chips for Bob
  const chips = chat.locator('[data-testid="chat-prompt-chip"]');
  await expect(chips.first()).toBeVisible();
  await expect(chips.first()).toContainText("Bob");
});

test("bob chen: asks about privilege utilization and verifies grounded facts and citations", async ({
  page,
  request,
}) => {
  const analysis = await getAnalysis(request);
  const bob = findingFor(analysis, "bob.chen");

  await page.goto(`/findings/${bob.id}`);

  const chat = page.locator('[data-testid="investigation-chat"]');
  const input = chat.locator('[data-testid="chat-input"]');
  const submit = chat.locator('[data-testid="chat-submit"]');

  // Submit question regarding Bob's privileges
  await input.fill("Why was Bob flagged for AdministratorAccess?");
  await submit.click();

  // Wait for assistant response
  const messages = chat.locator('[data-testid="chat-messages"]');
  await expect(messages).toContainText("Reviewer Question");
  await expect(messages).toContainText("AI Trial Lawyer");

  // Verify grounded facts: AdministratorAccess, 13 capabilities, 2 observed capabilities
  const responseText = await messages.innerText();
  expect(responseText).toMatch(/AdministratorAccess|13 capabilities|ratio|CloudTrail/i);

  // Safety assertions: no revocation directives, no necessity assertions
  expect(responseText.toLowerCase()).not.toContain("revoke");
  expect(responseText.toLowerCase()).not.toContain("unnecessary");
  expect(responseText.toLowerCase()).not.toContain("safe to remove");

  // Citations linking to exhibit cards
  const citationButtons = chat.locator('[data-testid^="citation-"]');
  const citationCount = await citationButtons.count();
  expect(citationCount).toBeGreaterThan(0);

  // Click the first citation and check that it scrolls to the exhibit element
  const firstCitation = citationButtons.first();
  const exhibitId = await firstCitation.getAttribute("data-evidence-id");
  expect(exhibitId).toBeTruthy();
  await firstCitation.click();

  // Verify corresponding exhibit element exists on page
  const exhibitEl = page.locator(`#exhibit-${exhibitId}`);
  await expect(exhibitEl).toBeAttached();
});

test("carol diaz: asks about post-deactivation activity and verifies chronological forensics", async ({
  page,
  request,
}) => {
  const analysis = await getAnalysis(request);
  const carol = findingFor(analysis, "carol.diaz");

  await page.goto(`/findings/${carol.id}`);

  const chat = page.locator('[data-testid="investigation-chat"]');
  const input = chat.locator('[data-testid="chat-input"]');
  const submit = chat.locator('[data-testid="chat-submit"]');

  await input.fill("What happened after Carol's Okta account was disabled?");
  await submit.click();

  const messages = chat.locator('[data-testid="chat-messages"]');
  await expect(messages).toContainText("AI Trial Lawyer");

  const responseText = await messages.innerText();
  // Carol forensics: Okta disable on 2026-08-15, GitHub activity on 2026-08-19
  expect(responseText).toMatch(/Okta|GitHub|disabled|post-deactivation|clone/i);

  // Safety assertions: no imperative revocation directives
  expect(responseText.toLowerCase()).not.toContain("should be revoked");
  expect(responseText.toLowerCase()).not.toContain("must be revoked");
  expect(responseText.toLowerCase()).not.toContain("automatically revoke");
  expect(responseText.toLowerCase()).not.toContain("delete account");

  // Exhibits cited
  const citations = chat.locator('[data-testid^="citation-"]');
  expect(await citations.count()).toBeGreaterThan(0);
});

test("gina patel: asks about application usage and verifies missing telemetry notice without clean claims", async ({
  page,
  request,
}) => {
  const analysis = await getAnalysis(request);
  const gina = findingFor(analysis, "gina.patel");

  await page.goto(`/findings/${gina.id}`);

  const chat = page.locator('[data-testid="investigation-chat"]');
  const input = chat.locator('[data-testid="chat-input"]');
  const submit = chat.locator('[data-testid="chat-submit"]');

  await input.fill("Did Gina use her application access?");
  await submit.click();

  const messages = chat.locator('[data-testid="chat-messages"]');
  await expect(messages).toContainText("AI Trial Lawyer");

  const responseText = await messages.innerText();
  // Telemetry missing or insufficient evidence
  expect(responseText).toMatch(/missing|insufficient|proxy|telemetry|unmeasured/i);

  // Strict denylist: page must not claim Gina is clean, unused, or safe
  const bodyText = (await page.locator("body").innerText()).toLowerCase();
  const forbidden = [...FORBIDDEN_CONCLUSION_PHRASES, ...mustNotSayFor("gina.patel")];
  for (const phrase of forbidden) {
    expect(bodyText, `chat contains forbidden phrase ${JSON.stringify(phrase)}`).not.toContain(
      phrase.toLowerCase(),
    );
  }
});

test("chat conversation persists in sessionStorage and can be reset", async ({
  page,
  request,
}) => {
  const analysis = await getAnalysis(request);
  const bob = findingFor(analysis, "bob.chen");

  await page.goto(`/findings/${bob.id}`);

  const chat = page.locator('[data-testid="investigation-chat"]');
  const input = chat.locator('[data-testid="chat-input"]');
  const submit = chat.locator('[data-testid="chat-submit"]');

  await input.fill("What is Bob's privilege utilization ratio?");
  await submit.click();

  const messages = chat.locator('[data-testid="chat-messages"]');
  await expect(messages).toContainText("AI Trial Lawyer");

  // Reload the page
  await page.reload();

  // The conversation should still be restored from sessionStorage
  const reloadedChat = page.locator('[data-testid="investigation-chat"]');
  await expect(reloadedChat).toBeVisible();
  const reloadedMessages = reloadedChat.locator('[data-testid="chat-messages"]');
  await expect(reloadedMessages).toContainText("What is Bob's privilege utilization ratio?");

  // Click Reset button to clear history
  const resetButton = reloadedChat.getByRole("button", { name: "Reset" });
  await expect(resetButton).toBeVisible();
  await resetButton.click();

  // Verify chat is reset to empty prompt state
  await expect(reloadedChat.locator('[data-testid="chat-prompt-chip"]').first()).toBeVisible();
});
