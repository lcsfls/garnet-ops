import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import { expect, type Page, test } from "@playwright/test";
import { E2E } from "./env.ts";
import { nextTotpPeriod, OWNER, STATE_FILE, totp, watchForProblems } from "./helpers.ts";

/**
 * In-app updates against the fake sidecar (fake-updater.ts, ADR 0007): the admin page,
 * the step-up sign-in before scheduling, the banner for everyone, cancel, progress and
 * the journal copied into the audit log.
 */
test.describe.configure({ mode: "serial" });
test.use({ storageState: STATE_FILE });
test.setTimeout(120_000);

const require = createRequire(new URL("../../../packages/db/package.json", import.meta.url));
const pg = require("pg") as {
  Client: new (options: {
    connectionString: string;
  }) => {
    connect(): Promise<void>;
    query(sql: string): Promise<unknown>;
    end(): Promise<void>;
  };
};

const fake = (path: string, body: unknown = {}) =>
  fetch(`http://127.0.0.1:${E2E.updaterPort}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });

/** Sets when every session signed in: an hour ago (older than the step-up window) or now. */
async function signedInAt(when: "an hour ago" | "now") {
  const client = new pg.Client({ connectionString: E2E.databaseUrl });
  await client.connect();
  try {
    await client.query(
      when === "now"
        ? "update session set created_at = now()"
        : "update session set created_at = now() - interval '1 hour'",
    );
    // Sign-ins of earlier tests (another member's, too) count against the per-minute limit;
    // this test's step-up is a sign-in of its own and must not inherit them.
    await client.query("delete from rate_limit where key like '%/sign-in/%' or key like '%/two-factor/%'");
  } finally {
    await client.end();
  }
}

const banner = (page: Page) => page.locator("main [data-state]").first();

test.beforeAll(async () => {
  await fake("/__test/reset");
});

test("scheduling needs a fresh sign-in, shows a banner to everyone and can be cancelled", async ({
  page,
}) => {
  const problems = watchForProblems(page);
  await signedInAt("an hour ago");
  await page.goto("/settings?section=updates");
  await expect(page.getByRole("heading", { name: "Updates", exact: true })).toBeVisible();
  await expect(page.getByText("Running version")).toBeVisible();
  await expect(page.getByLabel("Version", { exact: true })).toHaveValue("1.1.0");

  await page.getByRole("button", { name: "Schedule update" }).click();
  const stepUp = page.getByRole("dialog", { name: "Confirm it is you" });
  await expect(stepUp).toBeVisible();
  await nextTotpPeriod(page);
  const secret = readFileSync(E2E.totpSecretFile, "utf8").trim();
  await stepUp.getByLabel("Password").fill(OWNER.password);
  await stepUp.getByLabel("Code").fill(totp(secret));
  await stepUp.getByRole("button", { name: "Confirm" }).click();
  await expect(stepUp).toBeHidden();

  // The action is retried after the sign-in and the update is scheduled.
  await expect(page.getByText("The update to 1.1.0 is scheduled.")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Current update" })).toBeVisible();
  await expect(banner(page)).toHaveAttribute("data-state", "scheduled");
  await expect(banner(page)).toContainText("An update is scheduled.");
  await expect(banner(page)).toContainText(/Starts in \d+:\d\d/);

  // Every page shows the banner.
  await page.goto("/findings");
  await expect(banner(page)).toContainText("An update is scheduled.");

  await page.goto("/settings?section=updates");
  await page.getByRole("button", { name: "Cancel update" }).click();
  await expect(page.getByText("The update was cancelled, or its abort was requested.")).toBeVisible();
  await expect(page.locator("main [data-state]")).toHaveCount(0);

  // The sidecar's journal arrives in the audit log, with who asked.
  await page.goto("/audit-log?group=update");
  await expect(async () => {
    await page.reload();
    await expect(page.locator("tbody tr").filter({ hasText: "Update scheduled" })).toContainText(OWNER.email);
    await expect(page.locator("tbody tr").filter({ hasText: "Update cancelled" })).toHaveCount(1);
  }).toPass({ timeout: 45_000 });
  expect(problems).toEqual([]);
});

test("a running update shows its progress, a finished one its result", async ({ page }) => {
  const problems = watchForProblems(page);
  await signedInAt("now");
  await page.goto("/settings?section=updates");
  await page.getByLabel("Start").selectOption({ label: "in 1 hour" });
  await page.getByRole("button", { name: "Schedule update" }).click();
  await expect(banner(page)).toHaveAttribute("data-state", "scheduled");

  await fake("/__test/phase", { phase: "running" });
  await expect(banner(page)).toHaveAttribute("data-state", "running");
  await expect(banner(page)).toContainText("An update is in progress.");
  await expect(banner(page).getByRole("progressbar")).toHaveAttribute("value", "35");

  await fake("/__test/phase", { phase: "succeeded" });
  await expect(banner(page)).toHaveAttribute("data-state", "succeeded");
  await expect(banner(page)).toContainText("The update finished.");
  // The page reloads once, then shows the result until an admin acknowledges it.
  await page.waitForEvent("load", { timeout: 15_000 });
  await expect(page.getByRole("button", { name: "Acknowledge" })).toBeVisible();
  await page.getByRole("button", { name: "Acknowledge" }).click();
  await expect(page.getByText("The result was acknowledged.")).toBeVisible();
  await expect(page.locator("main [data-state]")).toHaveCount(0);
  expect(problems).toEqual([]);
});
