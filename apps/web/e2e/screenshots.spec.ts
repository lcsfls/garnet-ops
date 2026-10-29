/**
 * The screenshots of the README, on demo data (e2e/demo.ts), at the 1080p baseline. Run on purpose only:
 *
 *   GARNETOPS_SCREENSHOTS=1 npx playwright test --project screenshots
 *
 * The pictures go to docs/screenshots/. Every run of the end-to-end suite resets the database, so the demo
 * data never meets the other tests.
 */
import { expect, type Page, test } from "@playwright/test";
import { seedDemo } from "./demo.ts";
import { STATE_FILE } from "./helpers.ts";

test.skip(
  process.env.GARNETOPS_SCREENSHOTS !== "1",
  "set GARNETOPS_SCREENSHOTS=1 to take the README screenshots",
);
test.use({ storageState: STATE_FILE });

const OUT = "../../docs/screenshots";

test.beforeAll(async () => {
  await seedDemo();
});

/** Waits until the page has its data and no animation is running, then takes the picture. */
async function shoot(page: Page, name: string) {
  await page.waitForLoadState("networkidle");
  await expect(page.locator('[aria-busy="true"]')).toHaveCount(0);
  await page.mouse.move(0, 0);
  await page.screenshot({ path: `${OUT}/${name}.png`, animations: "disabled" });
}

for (const theme of ["light", "dark"] as const) {
  test(`overview (${theme})`, async ({ page }) => {
    await page.addInitScript((t) => localStorage.setItem("garnetops.theme", t), theme);
    await page.goto("/");
    await expect(page.getByRole("heading", { name: "Overview", level: 1 })).toBeVisible();
    await shoot(page, `overview-${theme}`);
  });
}

test("findings with the detail of one", async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem("garnetops.theme", "light"));
  await page.goto("/findings");
  await page.getByRole("row").filter({ hasText: "GHSA-xvch-5gv4-984h" }).first().click();
  await expect(page).toHaveURL(/id=/);
  await shoot(page, "findings");
});

test("repositories with their grades", async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem("garnetops.theme", "light"));
  await page.goto("/repositories");
  await expect(page.getByRole("link", { name: "billing-portal", exact: true })).toBeVisible();
  await shoot(page, "repositories");
});

test("early warnings", async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem("garnetops.theme", "light"));
  await page.goto("/early-warnings");
  await expect(page.getByTestId("early-warning").first()).toBeVisible();
  await shoot(page, "early-warnings");
});

test("statistics", async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem("garnetops.theme", "light"));
  await page.goto("/statistics");
  await expect(page.getByRole("heading", { name: "Statistics", level: 1 })).toBeVisible();
  await shoot(page, "statistics");
});

test("system status", async ({ page }) => {
  await page.addInitScript(() => localStorage.setItem("garnetops.theme", "light"));
  await page.goto("/system");
  await expect(page.getByTestId("scanner-isolation")).toContainText("Isolated");
  await shoot(page, "system-status");
});
