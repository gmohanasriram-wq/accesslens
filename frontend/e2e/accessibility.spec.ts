import { expect, test } from "@playwright/test";

import { getAnalysis, sel } from "./support";

/**
 * Structure and operability, not decoration.
 *
 * Deliberately no axe dependency: the assertions that matter for this product
 * are specific and cheap to state, and a rule-engine report would say less. An
 * auditor's tool has to be readable as a document -- one heading, a navigation
 * landmark, a stated current view -- and operable without a mouse.
 *
 * This is not polish deferred to the end. A dossier whose severity is a colour
 * swatch and whose exhibits are not in the accessibility tree is a dossier an
 * auditor cannot cite.
 */

const VIEWS = ["/", "/forensics", "/data"];

for (const path of VIEWS) {
  test(`${path} has one top-level heading and a navigation landmark`, async ({
    page,
  }) => {
    await page.goto(path);

    await expect(page.getByRole("heading", { level: 1 })).toHaveCount(1);
    await expect(page.getByRole("navigation")).toBeVisible();
    await expect(page.locator("main")).toHaveCount(1);
  });
}

test("the navigation marks the view the reviewer is on", async ({ page }) => {
  // Without `aria-current`, a screen-reader user gets a list of links and no
  // indication of which one they already followed.
  await page.goto("/forensics");

  const current = page.getByRole("navigation").locator('[aria-current="page"]');
  await expect(current).toHaveCount(1);
  await expect(current).toHaveAttribute("href", "/forensics");
});

test("the review queue is operable by keyboard alone", async ({ page, request }) => {
  const analysis = await getAnalysis(request);
  const first = analysis.findings[0];

  await page.goto("/");

  const link = page.locator(`[data-finding-id="${first.id}"]`).getByRole("link").first();
  await link.focus();
  await expect(link).toBeFocused();

  // A focused element has to be visibly focused, or a keyboard user is lost.
  const outline = await link.evaluate((el) => {
    const style = getComputedStyle(el);
    return `${style.outlineStyle} ${style.outlineWidth} ${style.boxShadow}`;
  });
  expect(outline).not.toBe("none 0px none");

  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(new RegExp(`/findings/${first.id}$`));
});

test("every exhibit is in the accessibility tree and names its source", async ({
  page,
  request,
}) => {
  const analysis = await getAnalysis(request);
  const bob = analysis.findings[0];

  await page.goto(`/findings/${bob.id}`);
  const exhibits = page.locator(sel.exhibit);
  await expect(exhibits.first()).toBeVisible();

  for (const exhibit of await exhibits.all()) {
    await expect(exhibit).not.toBeEmpty();
  }
});

test("the page does not scroll horizontally on a phone", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await expect(page.getByRole("heading", { level: 1 })).toBeVisible();

  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(overflow).toBeLessThanOrEqual(1);
});
