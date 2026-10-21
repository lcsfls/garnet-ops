import { expect, test } from "@playwright/test";
import { hasNoHorizontalScroll, overflowingCards, STATE_FILE, watchForProblems } from "./helpers.ts";

/** Layout baseline (AGENTS.md rule 5): every screen fits at 1080p with 100, 125 and 150 % scaling. */
test.describe("signed out", () => {
  test("sign-in fits without horizontal scrolling", async ({ page }, info) => {
    const problems = watchForProblems(page);
    await page.goto("/sign-in");
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    expect(await hasNoHorizontalScroll(page)).toBe(true);
    await expect(page.getByRole("button", { name: "Sign in" })).toBeInViewport();
    await page.screenshot({ path: info.outputPath("sign-in.png") });
    expect(problems).toEqual([]);
  });
});

test.describe("language", () => {
  // A German browser still gets English: English is the primary language (AGENTS.md).
  test.use({ locale: "de-DE" });

  test("English by default, German only by explicit choice", async ({ page }) => {
    await page.goto("/sign-in");
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    await expect(page.locator("html")).toHaveAttribute("lang", "en");

    await page.getByLabel("Language").selectOption("de");
    await expect(page.getByRole("heading", { name: "Anmelden" })).toBeVisible();
    await expect(page.locator("html")).toHaveAttribute("lang", "de");

    await page.reload();
    await expect(page.getByRole("heading", { name: "Anmelden" })).toBeVisible();
    await page.getByLabel("Sprache").selectOption("en");
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  });
});

test.describe("signed in", () => {
  test.use({ storageState: STATE_FILE });

  for (const { path, heading, name } of [
    { path: "/", heading: "Overview", name: "overview" },
    { path: "/findings?id=fnd_e2e0000000000000001", heading: "Findings", name: "findings-detail" },
    { path: "/repositories", heading: "Repositories", name: "repositories" },
    { path: "/packages", heading: "Packages", name: "packages" },
    { path: "/gates?repositoryId=repo_e2eseeded000000001", heading: "Quality gates", name: "gates" },
    { path: "/settings", heading: "Settings", name: "settings" },
    { path: "/settings?section=updates", heading: "Settings", name: "settings-updates" },
    { path: "/settings?section=about", heading: "Settings", name: "settings-about" },
    { path: "/repositories/repo_e2eseeded000000001", heading: "seeded-app", name: "repository" },
    { path: "/audit-log", heading: "Audit log", name: "audit-log" },
  ]) {
    test(`${name} fits without horizontal scrolling`, async ({ page }, info) => {
      const problems = watchForProblems(page);
      await page.goto(path);
      await expect(page.getByRole("heading", { name: heading, exact: true })).toBeVisible();
      await page.waitForLoadState("networkidle");
      expect(await hasNoHorizontalScroll(page)).toBe(true);
      expect(await overflowingCards(page)).toEqual([]);
      await expect(page.getByRole("button", { name: /^Account: / })).toBeInViewport();
      await page.screenshot({ path: info.outputPath(`${name}.png`), fullPage: true });
      expect(problems).toEqual([]);
    });
  }

  test("filter controls never move when filters change", async ({ page }, info) => {
    await page.goto("/findings");
    const search = page.getByRole("searchbox", { name: "Filter by package or ID" });
    await expect(search).toBeVisible();
    const before = await search.boundingBox();

    const steps = [
      () => page.getByLabel("Known exploited only").check(),
      () => page.getByLabel("Fix available only").check(),
      () => page.getByRole("button", { name: "High", exact: true }).click(),
      () => page.getByRole("button", { name: "Accepted" }).click(),
      () => page.getByRole("button", { name: "Clear filters" }).click(),
    ];
    for (const [index, step] of steps.entries()) {
      await step();
      await page.waitForLoadState("networkidle");
      expect(await search.boundingBox()).toEqual(before);
      if (index === 1) {
        // Both checkboxes ticked: kept for visual review of the form controls.
        await page.screenshot({ path: info.outputPath("filters-checked.png") });
      }
    }
  });

  test("dark theme renders the signed-in screens", async ({ page }, info) => {
    const problems = watchForProblems(page);
    await page.emulateMedia({ colorScheme: "dark" });
    await page.goto("/findings?id=fnd_e2e0000000000000001&kev=1");
    await expect(page.getByRole("heading", { name: "Findings", exact: true })).toBeVisible();
    await page.waitForLoadState("networkidle");
    await page.screenshot({ path: info.outputPath("findings-dark.png") });
    await page.goto("/repositories?add=1");
    await expect(page.getByRole("dialog", { name: "Add a repository" })).toBeVisible();
    await page.getByLabel("Access token").check();
    await page.screenshot({ path: info.outputPath("add-repository-dark.png") });
    expect(problems).toEqual([]);
  });
});
