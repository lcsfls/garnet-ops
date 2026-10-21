import { mkdirSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { expect, test } from "@playwright/test";
import { E2E } from "./env.ts";
import {
  hasNoHorizontalScroll,
  nextTotpPeriod,
  OWNER,
  openAccountMenu,
  STATE_FILE,
  signOut,
  totp,
  watchForProblems,
} from "./helpers.ts";

test.setTimeout(120_000);

test("first-run setup, mandatory TOTP, backup code and TOTP sign-in", async ({ page }) => {
  const problems = watchForProblems(page);

  // A fresh installation sends every visitor to setup.
  await page.goto("/");
  await expect(page).toHaveURL(/\/setup$/);
  await expect(page.getByRole("heading", { name: "Set up GarnetOps" })).toBeVisible();
  expect(await hasNoHorizontalScroll(page)).toBe(true);

  // Setup without the one-time token is refused.
  await page.getByLabel("Setup token").fill("not-the-token");
  await page.getByLabel("Organisation name").fill(OWNER.organization);
  await page.getByLabel("Your name").fill(OWNER.name);
  await page.getByLabel("Email").fill(OWNER.email);
  await page.getByLabel("Password").fill(OWNER.password);
  await page.getByRole("button", { name: "Create owner account" }).click();
  await expect(page.getByRole("alert")).toHaveText("The setup token is not valid.");

  await page.getByLabel("Setup token").fill(E2E.setupToken);
  await page.getByRole("button", { name: "Create owner account" }).click();
  await expect(page).toHaveURL(/\/sign-in\?setup=done$/);
  await expect(page.getByRole("status")).toContainText("Setup is complete");

  // Wrong password, then the right one.
  await page.getByLabel("Email").fill(OWNER.email);
  await page.getByLabel("Password").fill("not-the-password-123");
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page.getByRole("alert")).toHaveText("Email or password is not correct.");
  await page.getByLabel("Password").fill(OWNER.password);
  await page.getByRole("button", { name: "Sign in" }).click();

  // Without a second factor the only way forward is enrolment, and the API stays closed.
  await expect(page).toHaveURL(/\/enroll$/);
  expect((await page.request.get("/api/v1/me")).status()).toBe(403);
  await page.goto("/");
  await expect(page).toHaveURL(/\/enroll$/);

  await page.getByLabel("Password").fill(OWNER.password);
  await page.getByRole("button", { name: "Start setup" }).click();
  await expect(page.getByRole("img", { name: "QR code for your authenticator app" })).toBeVisible();
  const secret = (await page.locator("code").innerText()).replace(/\s+/g, "");
  expect(secret).toMatch(/^[A-Z2-7]{16,}$/);
  // Kept for the step-up test (a later sign-in confirms an update); the database is thrown away.
  mkdirSync(dirname(E2E.totpSecretFile), { recursive: true });
  writeFileSync(E2E.totpSecretFile, secret, { mode: 0o600 });

  await page.getByLabel("Code", { exact: true }).fill(totp(secret) === "000000" ? "111111" : "000000");
  await page.getByRole("button", { name: "Confirm code" }).click();
  await expect(page.getByRole("alert")).toContainText("The code is not correct");
  await page.getByLabel("Code", { exact: true }).fill(totp(secret));
  await page.getByRole("button", { name: "Confirm code" }).click();

  // Backup codes are shown once; continuing needs an explicit confirmation.
  await expect(page.getByRole("heading", { name: "Save your backup codes" })).toBeVisible();
  const backupCodes = await page.locator("ul li").allInnerTexts();
  expect(backupCodes.length).toBeGreaterThanOrEqual(8);
  const finish = page.getByRole("button", { name: "Continue to GarnetOps" });
  await expect(finish).toBeDisabled();
  await page.getByLabel("I have saved my backup codes").check();
  await finish.click();

  await expect(page).toHaveURL(/\/$/);
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await openAccountMenu(page);
  await expect(page.getByText(`Signed in as ${OWNER.name}`)).toBeVisible();
  await expect(page.getByText(`${OWNER.organization} · Owner`)).toBeVisible();
  await page.keyboard.press("Escape");

  // The second factor cannot be switched off, and "trust this device" is refused.
  const origin = { origin: E2E.publicUrl };
  const disable = await page.request.post("/api/auth/two-factor/disable", {
    headers: origin,
    data: { password: OWNER.password },
  });
  expect(disable.status()).toBe(403);

  // Sign out, then sign in with a backup code.
  await signOut(page);
  await expect(page).toHaveURL(/\/sign-in$/);
  await page.getByLabel("Email").fill(OWNER.email);
  await page.getByLabel("Password").fill(OWNER.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/two-factor$/);
  expect((await page.request.get("/api/v1/me")).status()).toBe(401);

  const trust = await page.request.post("/api/auth/two-factor/verify-totp", {
    headers: origin,
    data: { code: totp(secret), trustDevice: true },
  });
  expect(trust.status()).toBe(400);

  await page.getByRole("button", { name: "Use a backup code instead" }).click();
  await page.getByLabel("Backup code").fill(backupCodes[0] ?? "");
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();

  // Sign out, then sign in with a fresh TOTP code.
  await signOut(page);
  await expect(page).toHaveURL(/\/sign-in$/);
  await page.getByLabel("Email").fill(OWNER.email);
  await page.getByLabel("Password").fill(OWNER.password);
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/two-factor$/);
  await nextTotpPeriod(page);
  await page.getByLabel("Code", { exact: true }).fill(totp(secret));
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();

  await page.context().storageState({ path: STATE_FILE });
  expect(problems).toEqual([]);
});
