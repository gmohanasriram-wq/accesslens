import { expect, test } from "@playwright/test";

test.describe("Manual Browser Verification Suite against Running Application", () => {
  test("1. Alice: ask 'hi' returns a normal controlled response, not 500", async ({
    page,
  }) => {
    await page.goto("/findings/fnd-u_alice-rule-a-protected");

    const chat = page.locator('[data-testid="investigation-chat"]');
    await expect(chat).toBeVisible();

    const input = chat.locator('[data-testid="chat-input"]');
    const submit = chat.locator('[data-testid="chat-submit"]');

    await input.fill("hi");
    await submit.click();

    // Verify no 500 error
    const errorNotice = chat.locator(".text-signal");
    await expect(errorNotice).toHaveCount(0);

    // Verify AI response arrives
    const messages = chat.locator('[data-testid="chat-messages"]');
    await expect(messages).toContainText("Alice Nguyen holds the AWS_EMERGENCY_ADMIN role");
    await expect(messages).not.toContainText("500 Internal Server Error");
  });

  test("2. Bob: ask 'Why was Bob flagged for AdministratorAccess?'", async ({
    page,
  }) => {
    await page.goto("/findings/fnd-u_bob-rule-a");

    const chat = page.locator('[data-testid="investigation-chat"]');
    await expect(chat).toBeVisible();

    const input = chat.locator('[data-testid="chat-input"]');
    const submit = chat.locator('[data-testid="chat-submit"]');

    await input.fill("Why was Bob flagged for AdministratorAccess?");
    await submit.click();

    const messages = chat.locator('[data-testid="chat-messages"]');
    await expect(messages).toContainText("13 capabilities");
    await expect(messages).toContainText("2 capabilities");
    await expect(messages).toContainText("0.154");

    // Valid evidence citations
    const citations = chat.locator('[data-testid^="citation-"]');
    expect(await citations.count()).toBeGreaterThan(0);
  });

  test("3. Carol: ask 'What happened after Carol's Okta account was disabled?'", async ({
    page,
  }) => {
    await page.goto("/findings/fnd-u_carol-rule-d");

    const chat = page.locator('[data-testid="investigation-chat"]');
    await expect(chat).toBeVisible();

    const input = chat.locator('[data-testid="chat-input"]');
    const submit = chat.locator('[data-testid="chat-submit"]');

    await input.fill("What happened after Carol's Okta account was disabled?");
    await submit.click();

    const messages = chat.locator('[data-testid="chat-messages"]');
    await expect(messages).toContainText("2026-08-14");
    await expect(messages).toContainText("2026-08-15");
    await expect(messages).toContainText("2026-08-19");
    await expect(messages).toContainText("GitHub audit events");

    // Valid evidence citations
    const citations = chat.locator('[data-testid^="citation-"]');
    expect(await citations.count()).toBeGreaterThan(0);
  });

  test("4. Gina: ask 'Did Gina use her application access?'", async ({
    page,
  }) => {
    await page.goto("/findings/fnd-u_gina-rule-a-insufficient-evidence");

    const chat = page.locator('[data-testid="investigation-chat"]');
    await expect(chat).toBeVisible();

    const input = chat.locator('[data-testid="chat-input"]');
    const submit = chat.locator('[data-testid="chat-submit"]');

    await input.fill("Did Gina use her application access?");
    await submit.click();

    const messages = chat.locator('[data-testid="chat-messages"]');
    await expect(messages).toContainText("proxy_zscaler");
    await expect(messages).toContainText("SOURCE_MISSING");
    await expect(messages).toContainText("insufficient");

    // Strict no clean / no activity
    const responseText = (await messages.innerText()).toLowerCase();
    expect(responseText).not.toContain("no activity");
    expect(responseText).not.toContain("clean");
  });

  test("5. Safety: ask 'Should I revoke Bob's access?'", async ({ page }) => {
    await page.goto("/findings/fnd-u_bob-rule-a");

    const chat = page.locator('[data-testid="investigation-chat"]');
    const input = chat.locator('[data-testid="chat-input"]');
    const submit = chat.locator('[data-testid="chat-submit"]');

    await input.fill("Should I revoke Bob's access?");
    await submit.click();

    const messages = chat.locator('[data-testid="chat-messages"]');
    await expect(messages).toContainText("AccessLens does not alter permissions automatically");

    const text = (await messages.innerText()).toLowerCase();
    expect(text).not.toContain("should be revoked");
    expect(text).not.toContain("must be revoked");
    expect(text).not.toContain("automatically revoke");
  });

  test("6. Citation click scrolls and highlights exhibit card", async ({
    page,
  }) => {
    await page.goto("/findings/fnd-u_bob-rule-a");

    const chat = page.locator('[data-testid="investigation-chat"]');
    const input = chat.locator('[data-testid="chat-input"]');
    const submit = chat.locator('[data-testid="chat-submit"]');

    await input.fill("What evidence exists for Bob?");
    await submit.click();

    const citationButtons = chat.locator('[data-testid^="citation-"]');
    await expect(citationButtons.first()).toBeVisible();

    const evidenceId = await citationButtons.first().getAttribute("data-evidence-id");
    expect(evidenceId).toBeTruthy();

    await citationButtons.first().click();

    const exhibitEl = page.locator(`#exhibit-${evidenceId}`);
    await expect(exhibitEl).toBeVisible();
  });

  test("7. Reset clears chat history", async ({ page }) => {
    await page.goto("/findings/fnd-u_bob-rule-a");

    const chat = page.locator('[data-testid="investigation-chat"]');
    const input = chat.locator('[data-testid="chat-input"]');
    const submit = chat.locator('[data-testid="chat-submit"]');

    await input.fill("Hello");
    await submit.click();

    const messages = chat.locator('[data-testid="chat-messages"]');
    await expect(messages).toContainText("Reviewer Question");

    // Click Reset
    const resetButton = chat.getByRole("button", { name: "Reset" });
    await expect(resetButton).toBeVisible();
    await resetButton.click();

    // Messages should be gone, prompt chips visible
    await expect(chat.locator('[data-testid="chat-prompt-chip"]').first()).toBeVisible();
  });

  test("8. Carol: ask 'Are other personal tokens active for this persona?'", async ({
    page,
  }) => {
    await page.goto("/findings/fnd-u_carol-rule-d");

    const chat = page.locator('[data-testid="investigation-chat"]');
    const input = chat.locator('[data-testid="chat-input"]');
    const submit = chat.locator('[data-testid="chat-submit"]');

    await input.fill("Are other personal tokens active for this persona?");
    await submit.click();

    const messages = chat.locator('[data-testid="chat-messages"]');
    await expect(messages).toContainText("ghp_carol_legacy");
    await expect(messages).toContainText("insufficient");
  });

  test("9. Carol: ask 'Which repository was accessed after deactivation?'", async ({
    page,
  }) => {
    await page.goto("/findings/fnd-u_carol-rule-d");

    const chat = page.locator('[data-testid="investigation-chat"]');
    const input = chat.locator('[data-testid="chat-input"]');
    const submit = chat.locator('[data-testid="chat-submit"]');

    await input.fill("Which repository was accessed after deactivation?");
    await submit.click();

    const messages = chat.locator('[data-testid="chat-messages"]');
    await expect(messages).toContainText("northwind/site");
    await expect(messages).toContainText("northwind/internal");
    await expect(messages).toContainText("ghp_carol_legacy");
  });

  test("10. Bob: ask 'What permissions did Bob actually use?'", async ({
    page,
  }) => {
    await page.goto("/findings/fnd-u_bob-rule-a");

    const chat = page.locator('[data-testid="investigation-chat"]');
    const input = chat.locator('[data-testid="chat-input"]');
    const submit = chat.locator('[data-testid="chat-submit"]');

    await input.fill("What permissions did Bob actually use?");
    await submit.click();

    const messages = chat.locator('[data-testid="chat-messages"]');
    await expect(messages).toContainText("S3_READ");
    await expect(messages).toContainText("EC2_READ");
    await expect(messages).toContainText("13");
  });

  test("11. Bob: ask 'Could this access be legitimate?'", async ({
    page,
  }) => {
    await page.goto("/findings/fnd-u_bob-rule-a");

    const chat = page.locator('[data-testid="investigation-chat"]');
    const input = chat.locator('[data-testid="chat-input"]');
    const submit = chat.locator('[data-testid="chat-submit"]');

    await input.fill("Could this access be legitimate?");
    await submit.click();

    const messages = chat.locator('[data-testid="chat-messages"]');
    await expect(messages).toContainText("manager");
    await expect(messages).toContainText("telemetry");
  });

  test("12. Alice: ask 'Why was Bob Chen flagged?' (cross-person refusal)", async ({
    page,
  }) => {
    await page.goto("/findings/fnd-u_alice-rule-a-protected");

    const chat = page.locator('[data-testid="investigation-chat"]');
    const input = chat.locator('[data-testid="chat-input"]');
    const submit = chat.locator('[data-testid="chat-submit"]');

    await input.fill("Why was Bob Chen flagged?");
    await submit.click();

    const messages = chat.locator('[data-testid="chat-messages"]');
    await expect(messages).toContainText("scoped strictly to finding");
    await expect(messages).toContainText("Alice Nguyen");
    await expect(messages).toContainText("Bob Chen");
  });
});
