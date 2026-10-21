import { readFileSync } from "node:fs";
import { expect, type Locator, type Page, test } from "@playwright/test";
import { E2E } from "./env.ts";
import { OWNER, STATE_FILE, totp, watchForProblems } from "./helpers.ts";
import { SEEDED, seed } from "./seed.ts";

test.describe.configure({ mode: "serial" });
test.use({ storageState: STATE_FILE });

test.beforeAll(async () => {
  await seed();
});

/** Rows keep their less frequent actions in the "…" menu (mockup). */
async function rowAction(row: Locator, action: string) {
  await row.getByRole("button", { name: /^More actions for/ }).click();
  await row.getByRole("menuitem", { name: action }).click();
}

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
  await page.getByRole("button", { name: "Accept risk …" }).click();
  const accept = page.getByRole("dialog", { name: /^Accept the risk of/ });
  await accept.getByLabel("Reason").fill("Not reachable: only used in the test suite.");
  await accept.getByRole("button", { name: "Accept risk", exact: true }).click();
  await expect(accept).toBeHidden();
  await expect(page.getByRole("button", { name: "Reopen" })).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Pagination" })).toContainText(
    `${SEEDED.high - 1} entries`,
  );

  await page.getByRole("button", { name: "Reopen" }).click();
  await expect(page.getByRole("button", { name: "Accept risk …" })).toBeVisible();
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

  await rowAction(added, "Remove");
  const confirm = page.getByRole("dialog", { name: "Remove new-app?" });
  // Cancelling keeps the repository.
  await confirm.getByRole("button", { name: "Cancel" }).click();
  await expect(confirm).toBeHidden();
  await expect(added).toBeVisible();
  await rowAction(added, "Remove");
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
    await rowAction(page.getByRole("row", { name: new RegExp(name) }), "Remove");
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
  await rowAction(added, "Deploy key");
  const details = page.getByRole("dialog", { name: "Deploy key for ssh-app" });
  await expect(details.getByLabel("Public key")).toHaveValue(shown);
  await expect(details.getByText("Pinned on the first connection.", { exact: false })).toBeVisible();
  await details.getByRole("button", { name: "Close" }).click();

  await rowAction(added, "Remove");
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
  // The whole row opens the repository (mockup), not only its name.
  await page
    .getByRole("row", { name: new RegExp(SEEDED.repositoryName) })
    .getByText("https://git.example.test/team/seeded-app.git")
    .click();
  await expect(page).toHaveURL(/\/repositories\/repo_e2eseeded000000001$/);
  await page.goBack();
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

test("search: Ctrl K finds repositories, vulnerabilities and packages", async ({ page }) => {
  const problems = watchForProblems(page);
  await page.goto("/");
  // The shortcut listener exists once the app has rendered.
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await page.keyboard.press("Control+k");
  const search = page.getByRole("dialog", { name: "Search" });
  const box = search.getByRole("combobox", { name: "Search" });
  await box.fill("CVE-2099-0001");
  await expect(search.getByRole("option", { name: /CVE-2099-0001\s*Vulnerability/ })).toBeVisible();
  await box.fill("seeded");
  const hit = search.getByRole("option", { name: /seeded-app\s*Repository/ });
  await expect(hit).toBeVisible();
  await box.press("Enter");
  await expect(page).toHaveURL(/\/repositories\/repo_e2eseeded000000001$/);
  await expect(page.getByRole("heading", { name: "seeded-app" })).toBeVisible();
  await page.keyboard.press("Control+k");
  await search.getByRole("combobox", { name: "Search" }).fill("pkg-1");
  await expect(search.getByRole("option", { name: /^pkg-1\s*Package/ }).first()).toBeVisible();
  expect(problems).toEqual([]);
});

test("sorting: every column pages through all rows exactly once, both directions", async ({ page }) => {
  const lists: { path: string; sorts: string[] }[] = [
    {
      path: "/findings?state=all",
      sorts: ["vulnerability", "cvss", "epss", "published", "package", "repository", "firstSeen"],
    },
    { path: "/packages?", sorts: ["name", "type", "repository", "findings", "severity"] },
    { path: "/repositories?", sorts: ["name", "critical", "high", "medium", "lastScan"] },
  ];
  for (const { path, sorts } of lists) {
    const all = await page.request.get(`${E2E.publicUrl}/api/v1${path}&pageSize=100`);
    const total = (await all.json()).total as number;
    for (const sort of sorts) {
      for (const dir of ["asc", "desc"]) {
        const seen: string[] = [];
        let cursor: string | null = null;
        do {
          const url: string = `${E2E.publicUrl}/api/v1${path}&sort=${sort}&dir=${dir}&pageSize=25${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`;
          const response = await page.request.get(url);
          expect(response.ok(), `${url}: ${response.status()}`).toBe(true);
          const body = (await response.json()) as { items: { id: string }[]; next: string | null };
          seen.push(...body.items.map((x) => x.id));
          cursor = body.next;
        } while (cursor);
        expect(new Set(seen).size, `${path} ${sort} ${dir}`).toBe(seen.length);
        expect(seen.length, `${path} ${sort} ${dir}`).toBe(total);
      }
    }
  }
});

test("sorting: a column header sorts the findings and says so", async ({ page }) => {
  await page.goto("/findings");
  const header = page.getByRole("columnheader", { name: /CVSS/ });
  await header.getByRole("button").click();
  await expect(page).toHaveURL(/sort=cvss/);
  await expect(header).toHaveAttribute("aria-sort", "descending");
  await expect(page.locator("tbody tr").first()).toContainText("9.8");
  await header.getByRole("button").click();
  await expect(header).toHaveAttribute("aria-sort", "ascending");
  await expect(page).toHaveURL(/dir=asc/);
  await header.getByRole("button").click();
  await expect(header).toHaveAttribute("aria-sort", "none");
});

test("quality gates: report by default, an admin blocks a rule, a pipeline checks with its token", async ({
  page,
  playwright,
}) => {
  const problems = watchForProblems(page);
  await page.goto("/gates");
  await expect(page.getByRole("heading", { name: "Quality gates", level: 1 })).toBeVisible();
  const critical = page.getByRole("group", { name: "Mode of Critical vulnerability with a fix" });
  // Nothing blocks until an admin says so (ADR 0008).
  await expect(critical.getByRole("button", { name: "Report" })).toHaveAttribute("aria-pressed", "true");
  await critical.getByRole("button", { name: "Block" }).click();
  await expect(critical.getByRole("button", { name: "Block" })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByRole("status").filter({ hasText: "Counts from the next run on." })).toBeVisible();

  const runs = page.locator("section").filter({ has: page.getByRole("heading", { name: "Recent runs" }) });
  await expect(runs.getByRole("row", { name: /seeded-app/ })).toContainText("With notes");
  await expect(runs.getByRole("row", { name: /seeded-app/ })).toContainText(
    "2 × Critical vulnerability with a fix",
  );

  // A token for the seeded repository, shown once.
  await page.getByRole("combobox", { name: "Repository" }).selectOption({ label: "seeded-app" });
  await page.getByLabel("Name of the token").fill("e2e pipeline");
  await page.getByRole("button", { name: "Create token" }).click();
  const token = (await page.locator("code").filter({ hasText: /^gog_/ }).textContent())?.trim() ?? "";
  expect(token).toMatch(/^gog_[A-Za-z0-9_-]{43}$/);
  await expect(page.getByText("e2e pipeline")).toBeVisible();

  // The CI side: no cookies, only the bearer token.
  const ci = await playwright.request.newContext({
    baseURL: E2E.publicUrl,
    storageState: { cookies: [], origins: [] },
  });
  const headers = { authorization: `Bearer ${token}` };
  const sha = "a".repeat(40);
  const check = await ci.post("/api/v1/gate/checks", { headers, data: { ref: "refs/pull/7/head", sha } });
  expect(check.status()).toBe(202);
  const { id } = (await check.json()) as { id: string };
  const again = await ci.post("/api/v1/gate/checks", { headers, data: { ref: "refs/pull/7/head", sha } });
  expect(((await again.json()) as { id: string }).id).toBe(id);
  const status = await ci.get(`/api/v1/gate/checks/${id}`, { headers });
  expect(await status.json()).toMatchObject({ id, state: "queued", result: null, rules: [] });
  expect((await ci.post("/api/v1/gate/checks", { headers, data: { ref: "--upload-pack=x" } })).status()).toBe(
    422,
  );
  expect((await ci.get("/api/v1/gate/checks/scan_e2eseeded000000001", { headers })).ok()).toBe(true);
  expect((await ci.get("/api/v1/findings", { headers })).status()).toBe(401);
  const wrong = { authorization: `Bearer gog_${"x".repeat(43)}` };
  expect((await ci.post("/api/v1/gate/checks", { headers: wrong, data: {} })).status()).toBe(401);

  // Revoked: the pipeline is refused at once.
  await page.getByRole("button", { name: "Revoke: e2e pipeline" }).click();
  await page
    .getByRole("dialog", { name: /Revoke the token e2e pipeline/ })
    .getByRole("button", { name: "Revoke" })
    .click();
  await expect(page.getByText("No token yet.")).toBeVisible();
  expect((await ci.get(`/api/v1/gate/checks/${id}`, { headers })).status()).toBe(401);
  await ci.dispose();

  // Back to the default, so later tests see the shipped behaviour.
  await critical.getByRole("button", { name: "Report" }).click();
  await expect(critical.getByRole("button", { name: "Report" })).toHaveAttribute("aria-pressed", "true");

  await page.goto("/repositories");
  await expect(page.getByRole("row", { name: /seeded-app/ })).toContainText("With notes");
  expect(problems).toEqual([]);
});

test("team: invite someone, they join with a second factor, change their role, remove them", async ({
  page,
  browser,
}) => {
  test.setTimeout(120_000);
  const problems = watchForProblems(page);
  await page.goto("/team");
  await expect(page.getByRole("heading", { name: "Team", level: 1 })).toBeVisible();
  await expect(page.getByRole("row", { name: new RegExp(OWNER.email) })).toContainText("Owner");

  await page.getByRole("button", { name: "Invite" }).click();
  const dialog = page.getByRole("dialog", { name: "Invite someone" });
  await dialog.getByLabel("Email address").fill("New.Person@e2e.test");
  await dialog.getByLabel("Member", { exact: true }).check();
  await dialog.getByRole("button", { name: "Create invitation link" }).click();
  const link = await dialog.getByLabel("Invitation link").inputValue();
  expect(link).toMatch(/\/invite#[A-Za-z0-9_-]{43}$/);
  await dialog.getByRole("button", { name: "Close" }).last().click();
  await expect(page.getByText("new.person@e2e.test")).toBeVisible();

  // The invited person, in a browser without the owner's session.
  const guest = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  const other = await guest.newPage();
  const path = new URL(link).pathname + new URL(link).hash;
  await other.goto(path);
  await expect(other.getByRole("heading", { name: "Join E2E Org" })).toBeVisible();
  await expect(other.getByText(`${OWNER.name} invited new.person@e2e.test as Member.`)).toBeVisible();
  await other.getByLabel("Your name").fill("Nina New");
  await other.getByLabel("Choose a password").fill("new-person-password-1");
  await other.getByRole("button", { name: "Join" }).click();
  await other.getByRole("link", { name: "Sign in" }).click();
  await other.getByLabel("Email").fill("new.person@e2e.test");
  await other.getByLabel("Password").fill("new-person-password-1");
  await other.getByRole("button", { name: "Sign in" }).click();
  // A second factor before anything else, like every account.
  await expect(other).toHaveURL(/\/enroll$/);
  await other.getByLabel("Password").fill("new-person-password-1");
  await other.getByRole("button", { name: "Start setup" }).click();
  const secret = (await other.locator("code").innerText()).replace(/\s+/g, "");
  await other.getByLabel("Code", { exact: true }).fill(totp(secret));
  await other.getByRole("button", { name: "Confirm code" }).click();
  await other.getByLabel("I have saved my backup codes").check();
  await other.getByRole("button", { name: "Continue to GarnetOps" }).click();
  await expect(other.getByRole("heading", { name: "Overview" })).toBeVisible();
  // A member sees no admin pages.
  await expect(other.getByRole("link", { name: "Team" })).toHaveCount(0);

  // The link works once.
  const again = await guest.newPage();
  await again.goto(path);
  await expect(again.getByRole("alert")).toContainText("This invitation link is not valid");

  // Role change, then removal: access ends at once.
  await page.reload();
  const row = page.getByRole("row", { name: /Nina New/ });
  await expect(row).toContainText("Set up");
  await row.getByRole("combobox", { name: "Role of Nina New" }).selectOption({ label: "Viewer" });
  await page.reload();
  await expect(page.getByRole("combobox", { name: "Role of Nina New" })).toHaveValue("viewer");
  // Nobody changes their own role; the owner row has no role control.
  await expect(page.getByRole("combobox", { name: `Role of ${OWNER.name}` })).toHaveCount(0);

  await page.getByRole("button", { name: "Remove Nina New" }).click();
  await page
    .getByRole("dialog", { name: "Remove Nina New from the team?" })
    .getByRole("button", { name: "Remove" })
    .click();
  await expect(page.getByRole("row", { name: /Nina New/ })).toHaveCount(0);
  expect((await other.request.get("/api/v1/me")).status()).toBe(401);
  await guest.close();

  await page.goto("/audit-log?group=team");
  for (const action of ["Invitation created", "Invitation accepted", "Role changed", "Member removed"]) {
    await expect(page.getByText(action).first()).toBeVisible();
  }
  expect(problems).toEqual([]);
});
