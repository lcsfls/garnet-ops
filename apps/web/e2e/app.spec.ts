import { readFileSync } from "node:fs";
import { expect, type Page, test } from "@playwright/test";
import { E2E } from "./env.ts";
import { OWNER, STATE_FILE, watchForProblems } from "./helpers.ts";
import { SEEDED, seed } from "./seed.ts";

test.describe.configure({ mode: "serial" });
test.use({ storageState: STATE_FILE });

test.beforeAll(async () => {
  await seed();
});

test("overview tiles lead to the filtered list", async ({ page }) => {
  const problems = watchForProblems(page);
  await page.goto("/");
  const critical = page.getByRole("link", { name: /Critical open/ });
  await expect(critical).toContainText(String(SEEDED.critical));
  await critical.click();
  await expect(page).toHaveURL(/\/findings\?severity=critical$/);
  await expect(page.getByRole("navigation", { name: "Pagination" })).toContainText(
    `${SEEDED.critical} entries`,
  );

  await page.goto("/");
  await page.getByRole("link", { name: /Known exploited/ }).click();
  await expect(page).toHaveURL(/kev=1/);
  await expect(page.getByRole("navigation", { name: "Pagination" })).toContainText(
    `${SEEDED.knownExploited} entry`,
  );
  expect(problems).toEqual([]);
});

test("findings paginate with the position in the URL", async ({ page }) => {
  await page.goto("/findings");
  const pager = page.getByRole("navigation", { name: "Pagination" });
  await expect(pager).toContainText(`${SEEDED.total} entries`);
  await expect(page.locator("tbody tr")).toHaveCount(25);
  await pager.getByRole("button", { name: "Next page" }).click();
  await expect(page).toHaveURL(/cursor=/);
  await expect(page.locator("tbody tr")).toHaveCount(SEEDED.total - 25);
  await page.goBack();
  await expect(page.locator("tbody tr")).toHaveCount(25);
  await pager.getByLabel("Per page").selectOption("50");
  await expect(page.locator("tbody tr")).toHaveCount(SEEDED.total);
});

test("findings show score, exploit probability, publication and detection dates", async ({ page }) => {
  await page.goto("/findings");
  const header = page.locator("thead");
  for (const column of ["CVSS", "EPSS", "Published", "Detected on"]) {
    await expect(header.getByRole("columnheader", { name: column })).toBeVisible();
  }
  const row = page.getByRole("row", { name: new RegExp(SEEDED.hostileId) });
  await expect(row).toContainText("9.8");
  await expect(row).toContainText("21.3%");
  await expect(row).toContainText("Feb 15, 2021");
  // A value the database does not have is announced, not left blank.
  await expect(page.getByRole("row", { name: /CVE-2099-0002/ })).toContainText("Not available");
});

test("packages: find which repository contains a package, and its open findings", async ({ page }) => {
  const problems = watchForProblems(page);
  await page.goto("/packages");
  await expect(page.getByRole("navigation", { name: "Pagination" })).toContainText(
    `${SEEDED.packages} entries`,
  );
  await page.getByLabel("Filter by name, or name@version").fill("left-pad@1.3");
  const clean = page.getByRole("row", { name: /left-pad/ });
  await expect(clean).toContainText("1.3.0");
  await expect(clean).toContainText(SEEDED.repositoryName);
  await expect(clean).toContainText("MIT");
  await expect(clean).toContainText("None");
  await expect(page.locator("tbody tr")).toHaveCount(1);

  await page.getByLabel("Filter by name, or name@version").fill("");
  await page.getByLabel("With open findings only").check();
  await expect(page.getByRole("navigation", { name: "Pagination" })).toContainText(`${SEEDED.total} entries`);
  // The open findings badge leads to the findings; the repository name leads to its page.
  await page
    .getByRole("row", { name: /pkg-1 / })
    .getByRole("link", { name: /Critical/ })
    .click();
  await expect(page).toHaveURL(/\/findings\?.*q=pkg-1/);
  expect(problems).toEqual([]);
});

test("hostile scanner content is shown as text, never as markup or script links", async ({ page }) => {
  const problems = watchForProblems(page);
  await page.goto("/findings");
  await page.getByRole("button", { name: SEEDED.hostileId }).click();
  await expect(page).toHaveURL(/id=fnd_e2e/);
  const detail = page.getByRole("button", { name: "Close details" }).locator("xpath=ancestor::section[1]");
  await expect(detail).toContainText("<img src=x onerror=");
  await expect(detail.locator("img, script")).toHaveCount(0);
  await expect(detail.locator('a[href^="javascript:"]')).toHaveCount(0);
  const reference = detail.getByRole("link", { name: /advisories\.example\.test/ });
  await expect(reference).toHaveAttribute("rel", "noopener noreferrer");
  expect(await page.title()).toBe("GarnetOps");
  expect(problems).toEqual([]);
});

test("a risk is accepted with a reason and reopened", async ({ page }) => {
  await page.goto("/findings?severity=high");
  await page.locator("tbody tr").first().getByRole("button").click();
  await page.getByLabel("Reason").fill("Not reachable: only used in the test suite.");
  await page.getByRole("button", { name: "Accept risk" }).click();
  await expect(page.getByRole("button", { name: "Reopen" })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Pagination" })).toContainText(
    `${SEEDED.high - 1} entries`,
  );

  await page.getByRole("button", { name: "Reopen" }).click();
  await expect(page.getByRole("button", { name: "Accept risk" })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Pagination" })).toContainText(`${SEEDED.high} entries`);
});

test("repositories: add one, see it queued, remove it", async ({ page }) => {
  const problems = watchForProblems(page);
  await page.goto("/repositories");
  // Setup took the owner's zone from the browser; nightly scans run at 04:00 there (ADR 0005).
  await expect(
    page.getByText("Every repository is scanned each night at 4:00 AM (Europe/Berlin)."),
  ).toBeVisible();
  const seeded = page.getByRole("row", { name: new RegExp(SEEDED.repositoryName) });
  await expect(seeded.getByRole("link", { name: /Critical/ })).toContainText(String(SEEDED.critical));

  await page.getByRole("button", { name: "Add repository" }).click();
  const dialog = page.getByRole("dialog", { name: "Add a repository" });
  await dialog.getByLabel("Repository URL").fill("https://git.example.test/team/new-app.git");
  await dialog.getByLabel("Access token").check();
  await dialog.getByLabel("Read-only access token").fill("e2e-token-never-shown");
  await dialog.getByRole("button", { name: "Add and scan" }).click();
  await expect(dialog).toBeHidden();

  const added = page.getByRole("row", { name: /new-app/ });
  await expect(added).toContainText("Queued");
  await expect(page.getByText("e2e-token-never-shown")).toHaveCount(0);

  // Adding the same URL again is refused.
  await page.getByRole("button", { name: "Add repository" }).click();
  await dialog.getByLabel("Repository URL").fill("https://git.example.test/team/new-app.git");
  await dialog.getByRole("button", { name: "Add and scan" }).click();
  await expect(dialog.getByRole("alert")).toHaveText("This repository is already connected.");
  await dialog.getByRole("button", { name: "Cancel" }).first().click();

  await added.getByRole("button", { name: /Remove/ }).click();
  const confirm = page.getByRole("dialog", { name: "Remove new-app?" });
  // Cancelling keeps the repository.
  await confirm.getByRole("button", { name: "Cancel" }).click();
  await expect(confirm).toBeHidden();
  await expect(added).toBeVisible();
  await added.getByRole("button", { name: /Remove/ }).click();
  await confirm.getByRole("button", { name: "Remove", exact: true }).click();
  await expect(page.getByRole("row", { name: /new-app/ })).toHaveCount(0);
  expect(problems).toEqual([]);
});

test("repositories: add several at once with one token", async ({ page }) => {
  const problems = watchForProblems(page);
  await page.goto("/repositories");
  await page.getByRole("button", { name: "Add repository" }).click();
  const dialog = page.getByRole("dialog", { name: "Add a repository" });
  await dialog.getByRole("button", { name: "Add several at once" }).click();
  // Deploy keys are per repository, so the list offers no SSH access.
  await expect(dialog.getByLabel("Deploy key (SSH), created by GarnetOps")).toHaveCount(0);

  const urls = dialog.getByLabel("Repository URLs");
  await urls.fill(
    [
      "https://git.example.test/team/bulk-one.git",
      "git@git.example.test:team/bulk-ssh.git",
      "https://git.example.test/team/bulk-two.git",
    ].join("\n"),
  );
  await dialog.getByLabel("Access token").check();
  await dialog.getByLabel("Read-only access token").fill("e2e-bulk-token-never-shown");
  await dialog.getByRole("button", { name: "Add 3 and scan" }).click();
  await expect(dialog.getByRole("alert")).toContainText("git@git.example.test:team/bulk-ssh.git");

  // The already connected repository is skipped, the others are added and queued.
  await urls.fill(
    [
      "https://git.example.test/team/bulk-one.git",
      "",
      "https://git.example.test/team/seeded-app.git",
      "https://git.example.test/team/bulk-two.git",
      "https://git.example.test/team/bulk-one.git",
    ].join("\n"),
  );
  await dialog.getByRole("button", { name: "Add 3 and scan" }).click();
  const result = page.getByRole("dialog", { name: "Repositories added" });
  await expect(result).toContainText("2 repositories added.");
  await expect(result.getByRole("listitem")).toHaveText(["https://git.example.test/team/seeded-app.git"]);
  await result.getByRole("button", { name: "Close" }).last().click();

  for (const name of ["bulk-one", "bulk-two"]) {
    const row = page.getByRole("row", { name: new RegExp(name) });
    await expect(row).toContainText("Queued");
    await expect(row).toContainText("Token, read-only");
  }
  await expect(page.getByText("e2e-bulk-token-never-shown")).toHaveCount(0);

  // Remove them again; each one has its own copy of the token.
  for (const name of ["bulk-one", "bulk-two"]) {
    await page
      .getByRole("row", { name: new RegExp(name) })
      .getByRole("button", { name: /Remove/ })
      .click();
    await page
      .getByRole("dialog", { name: `Remove ${name}?` })
      .getByRole("button", { name: "Remove", exact: true })
      .click();
    await expect(page.getByRole("row", { name: new RegExp(name) })).toHaveCount(0);
  }
  expect(problems).toEqual([]);
});

test("repositories: an SSH repository gets a generated deploy key", async ({ page }) => {
  const problems = watchForProblems(page);
  await page.goto("/repositories");
  await page.getByRole("button", { name: "Add repository" }).click();
  const dialog = page.getByRole("dialog", { name: "Add a repository" });

  // A deploy key only goes with an SSH address.
  await dialog.getByLabel("Repository URL").fill("https://git.example.test/team/ssh-app.git");
  await dialog.getByLabel("Deploy key (SSH)").check();
  await dialog.getByRole("button", { name: "Add and create key" }).click();
  await expect(dialog.getByRole("alert")).toHaveText(
    "Use public access or a token with an https:// address, and a deploy key with an SSH address.",
  );

  await dialog.getByLabel("Repository URL").fill("git@git.example.test:team/ssh-app.git");
  await dialog.getByRole("button", { name: "Add and create key" }).click();
  const keyDialog = page.getByRole("dialog", { name: "Add the deploy key to the repository" });
  const publicKey = keyDialog.getByLabel("Public key");
  await expect(publicKey).toHaveValue(/^ssh-ed25519 [A-Za-z0-9+/]+=* garnetops-repo_[0-9a-z]+$/);
  const shown = await publicKey.inputValue();
  await expect(keyDialog.getByText("PRIVATE KEY")).toHaveCount(0);
  // No scan before the key is on the forge.
  await keyDialog.getByRole("button", { name: "Later" }).click();
  await expect(keyDialog).toBeHidden();

  const added = page.getByRole("row", { name: /ssh-app/ });
  await expect(added).toContainText("Not scanned yet");
  await added.getByRole("button", { name: "Deploy key: ssh-app" }).click();
  const details = page.getByRole("dialog", { name: "Deploy key for ssh-app" });
  await expect(details.getByLabel("Public key")).toHaveValue(shown);
  await expect(details.getByText("Pinned on the first connection.", { exact: false })).toBeVisible();
  await details.getByRole("button", { name: "Close" }).click();

  await added.getByRole("button", { name: /Remove/ }).click();
  await page
    .getByRole("dialog", { name: "Remove ssh-app?" })
    .getByRole("button", { name: "Remove", exact: true })
    .click();
  await expect(page.getByRole("row", { name: /ssh-app/ })).toHaveCount(0);
  expect(problems).toEqual([]);
});

test("sign-in events are in the audit log, failures included, never a password", async ({ page }) => {
  const problems = watchForProblems(page);
  await page.goto("/audit-log");
  await page.getByRole("button", { name: "Sign-in", exact: true }).click();
  await expect(page).toHaveURL(/group=auth/);
  const rows = page.locator("tbody tr");
  // From the auth flow: a wrong password, a refused attempt to switch off 2FA, a backup code, sign-outs.
  await expect(
    rows.filter({ hasText: "Sign-in with password" }).filter({ hasText: "Failed" }),
  ).not.toHaveCount(0);
  await expect(
    rows.filter({ hasText: "Sign-in with password" }).filter({ hasText: "Succeeded" }),
  ).not.toHaveCount(0);
  await expect(
    rows.filter({ hasText: "Second factor checked" }).filter({ hasText: "Failed" }),
  ).not.toHaveCount(0);
  await expect(rows.filter({ hasText: "Attempt to switch off the second factor (refused)" })).toHaveCount(1);
  await expect(rows.filter({ hasText: "Backup code used" })).not.toHaveCount(0);
  await expect(rows.filter({ hasText: "Signed out" })).not.toHaveCount(0);
  await expect(page.locator("body")).not.toContainText(OWNER.password);
  expect(problems).toEqual([]);
});

test("the nightly scan can be moved to another time and zone, and the change is audited", async ({
  page,
}) => {
  await page.goto("/settings");
  await expect(page.getByLabel("Scan all repositories every night")).toBeChecked();
  await page.getByLabel("Time", { exact: true }).fill("05:30");
  await page.getByLabel("Time zone").selectOption("Europe/Vienna");
  await page.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Saved." })).toBeVisible();

  await page.goto("/repositories");
  await expect(
    page.getByText("Every repository is scanned each night at 5:30 AM (Europe/Vienna)."),
  ).toBeVisible();

  await page.goto("/audit-log?group=organization");
  const row = page.locator("tbody tr").filter({ hasText: "Nightly scan changed" }).first();
  await expect(row).toContainText("05:30:00");
  await expect(row).toContainText("Europe/Vienna");

  // A zone the database does not know is refused by the API.
  const refused = await page.request.put("/api/v1/organization/scan-schedule", {
    headers: { origin: E2E.publicUrl },
    data: { enabled: true, localTime: "04:00", timeZone: "Europe/Atlantis" },
  });
  expect(refused.status()).toBe(422);
});

/** Opens the Export menu and downloads one format; returns the file name and content. */
async function download(page: Page, format: "CSV" | "Excel (XLSX)" | "PDF" | "Text (TXT)") {
  await page.getByRole("button", { name: "Export" }).click();
  const [file] = await Promise.all([
    page.waitForEvent("download"),
    page.getByRole("link", { name: format }).click(),
  ]);
  const path = await file.path();
  return { name: file.suggestedFilename(), content: readFileSync(path) };
}

test("findings download as CSV, Excel, PDF and text, with the filters that are set", async ({ page }) => {
  const problems = watchForProblems(page);
  await page.goto("/findings?severity=critical");
  await expect(page.getByRole("navigation", { name: "Pagination" })).toContainText(
    `${SEEDED.critical} entries`,
  );

  const csv = await download(page, "CSV");
  expect(csv.name).toMatch(/^garnetops-findings-\d{4}-\d{2}-\d{2}\.csv$/);
  const lines = csv.content.toString("utf8").trim().split("\r\n");
  expect(lines[0]).toContain("Severity,Vulnerability,Package");
  expect(lines).toHaveLength(1 + SEEDED.critical);
  expect(lines[1]).toContain(SEEDED.hostileId);

  const xlsx = await download(page, "Excel (XLSX)");
  expect(xlsx.name).toMatch(/\.xlsx$/);
  expect(xlsx.content.subarray(0, 2).toString("latin1")).toBe("PK");

  const pdf = await download(page, "PDF");
  expect(pdf.name).toMatch(/\.pdf$/);
  expect(pdf.content.subarray(0, 8).toString("latin1")).toBe("%PDF-1.4");

  const txt = await download(page, "Text (TXT)");
  const text = txt.content.toString("utf8");
  expect(text).toContain("Filters: state Open, severity Critical");
  expect(text).toContain(`Findings: ${SEEDED.critical}`);
  expect(problems).toEqual([]);
});

test("a repository opens its own page with scan and patch history", async ({ page }) => {
  const problems = watchForProblems(page);
  await page.goto("/repositories");
  await page.getByRole("link", { name: SEEDED.repositoryName, exact: true }).click();
  await expect(page).toHaveURL(/\/repositories\/repo_e2eseeded000000001$/);
  await expect(page.getByRole("heading", { name: SEEDED.repositoryName })).toBeVisible();
  await expect(page.getByRole("link", { name: /Critical open/ })).toContainText(String(SEEDED.critical));

  const scans = page.locator("section").filter({ has: page.getByRole("heading", { name: "Scan history" }) });
  await expect(scans.getByRole("row", { name: /Started by hand/ })).toContainText(
    `${SEEDED.total} new, 0 resolved`,
  );

  const patches = page
    .locator("section")
    .filter({ has: page.getByRole("heading", { name: "Patch history" }) });
  const fixed = patches.getByRole("row", { name: new RegExp(SEEDED.fixedId) });
  await expect(fixed).toContainText("pkg-fixed");
  await expect(fixed).toContainText("2.0.0 → 2.0.1");
  await expect(fixed).toContainText("7 days");

  // The download covers this repository only.
  const csv = await download(page, "CSV");
  expect(csv.name).toMatch(/^garnetops-findings-seeded-app-\d{4}-\d{2}-\d{2}\.csv$/);
  expect(csv.content.toString("utf8")).toContain(SEEDED.fixedId);

  await page.getByRole("link", { name: "All repositories" }).click();
  await expect(page).toHaveURL(/\/repositories$/);
  expect(problems).toEqual([]);
});
