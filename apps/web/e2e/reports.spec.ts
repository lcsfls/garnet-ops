import { readFileSync } from "node:fs";
import { expect, type Locator, type Page, test } from "@playwright/test";
import { OWNER, STATE_FILE, watchForProblems } from "./helpers.ts";
import { EXPOSURE, SEEDED, sql } from "./seed.ts";

/**
 * Reports (ADR 0047): the report of a repository and of a host with their PDF, the organisation's security report from the
 * statistics page, the websites at a glance, and the report mail on the account page. Visibility is checked through the
 * API with a private repository of another member. The worker's part (matching a host) is played by rows. Everything this
 * file adds is removed again, so the projects after it see the data the app project left.
 */
test.describe.configure({ mode: "serial" });
test.use({ storageState: STATE_FILE });

const REPOSITORY = "repo_e2eseeded000000001";
const HOST = "agh_e2ereport0000000001";
const PRIVATE_REPOSITORY = "repo_e2ereportprivate001";
const organizationId = async () =>
  (await sql<{ id: string }>("select id from organization limit 1"))[0]?.id ?? "";
const ownerId = async () =>
  (await sql<{ id: string }>('select id from "user" where email = $1', [OWNER.email]))[0]?.id ?? "";

/** Clicks a download link and returns the file name and content. */
async function downloadFrom(page: Page, link: Locator) {
  const [file] = await Promise.all([page.waitForEvent("download"), link.click()]);
  return { name: file.suggestedFilename(), content: readFileSync(await file.path()) };
}

test.afterAll(async () => {
  await sql("delete from report_subscription");
  await sql("delete from report_mail_run");
  await sql("delete from notification_channel where id = 'nch_e2ereport'");
  await sql("delete from finding where repository_id = $1", [PRIVATE_REPOSITORY]);
  await sql("delete from repository where id = $1", [PRIVATE_REPOSITORY]);
  await sql(`delete from membership where user_id = 'user_e2ereportpat'`);
  await sql(`delete from "user" where id = 'user_e2ereportpat'`);
  await sql("delete from host_kernel_finding where host_id = $1", [HOST]);
  await sql("delete from agent_host where id = $1", [HOST]);
  await sql("delete from host_settings");
  await sql("delete from exposure_settings");
  await sql("delete from audit_log where action = 'report.exported'");
});

test("a repository's report says what was checked, what is open and what to do, and downloads as PDF", async ({
  page,
}) => {
  const problems = watchForProblems(page);
  await page.goto(`/repositories/${REPOSITORY}`);
  const report = page.locator("#report");
  await expect(report.getByRole("heading", { name: "Report", exact: true })).toBeVisible();
  await expect(report.getByTestId("report-open").locator('[data-severity="critical"]')).toContainText(
    `${SEEDED.critical} Critical`,
  );
  // Worst first: critical before high.
  const severities = await report
    .getByTestId("report-open")
    .locator("li")
    .evaluateAll((items) => items.map((item) => item.getAttribute("data-severity")));
  expect(severities.indexOf("critical")).toBeLessThan(severities.indexOf("high"));
  await expect(report.getByTestId("report-next-steps")).toContainText("known to be exploited");
  await expect(report.getByTestId("report-worst")).toContainText(SEEDED.hostileId);
  await expect(report.getByText("Last successful scan")).toBeVisible();

  const pdf = await downloadFrom(page, page.getByTestId("repository-report-download"));
  expect(pdf.name).toMatch(/^garnetops-report-seeded-app-\d{4}-\d{2}-\d{2}\.pdf$/);
  expect(pdf.content.subarray(0, 8).toString("latin1")).toBe("%PDF-1.4");
  expect((await sql("select 1 from audit_log where action = 'report.exported'")).length).toBeGreaterThan(0);
  expect(problems).toEqual([]);
});

test("the organisation report respects visibility: another member's private repository is in nobody else's", async ({
  page,
}) => {
  const org = await organizationId();
  await sql(
    `insert into "user" (id, name, email) values ('user_e2ereportpat', 'Pat Example', 'pat@example.test') on conflict do nothing`,
  );
  await sql(
    `insert into membership (organization_id, user_id, role) values ($1, 'user_e2ereportpat', 'member') on conflict do nothing`,
    [org],
  );
  await sql(
    `insert into repository (id, organization_id, name, url, auth_kind, visibility, owner_user_id)
     values ($1, $2, 'pats-private-tool', 'https://git.example.test/pat/private-tool.git', 'none', 'private', 'user_e2ereportpat')`,
    [PRIVATE_REPOSITORY, org],
  );
  await sql(
    `insert into finding (id, organization_id, repository_id, vulnerability_id, dedup_key, package_name, package_version,
       package_type, severity, severity_rank, state, first_seen_scan_id, last_seen_scan_id, first_seen_at, last_seen_at)
     select 'fnd_e2ereportprivate1', $1, $2, id, 'e2e-report-private', 'private-lib', '1.0.0', 'npm', 'critical', 5, 'open',
       'scan_x', 'scan_x', now(), now() from vulnerability order by id limit 1`,
    [org, PRIVATE_REPOSITORY],
  );

  const res = await page.request.get("/api/v1/reports/organization?days=7&tz=Europe/Berlin");
  expect(res.status()).toBe(200);
  const body = await res.text();
  expect(body).not.toContain("pats-private-tool");
  const json = JSON.parse(body) as { findings: { open: { critical: number } }; period: { days: number } };
  expect(json.period.days).toBe(7);
  // Exactly the open critical findings of the active repositories the owner sees: shared ones and their own private ones.
  const [visible] = await sql<{ n: number }>(
    `select count(*)::int as n from finding f join repository r on r.id = f.repository_id
     where f.state = 'open' and f.severity = 'critical' and r.inactive_at is null
       and (r.visibility = 'organization' or r.owner_user_id = $1)`,
    [await ownerId()],
  );
  expect(json.findings.open.critical).toBe(visible?.n);
  expect(json.findings.open.critical).toBeGreaterThanOrEqual(SEEDED.critical);
  // Its own report is a 404 for the owner of the organisation too (ADR 0030).
  expect((await page.request.get(`/api/v1/reports/repositories/${PRIVATE_REPOSITORY}`)).status()).toBe(404);
});

test("the statistics page downloads the organisation's security report for 7 or 30 days", async ({
  page,
}) => {
  const problems = watchForProblems(page);
  await page.goto("/statistics");
  await page.getByRole("button", { name: "Security report (PDF)" }).click();
  const dialog = page.getByRole("dialog", { name: "Security report" });
  await expect(dialog.getByLabel("Last 7 days")).toBeChecked();
  await dialog.getByLabel("Last 30 days").check();
  await expect(dialog.getByTestId("organization-report-download")).toHaveAttribute("href", /days=30/);
  await expect(dialog.getByTestId("organization-report-download")).toHaveAttribute(
    "href",
    /tz=Europe%2FBerlin/,
  );
  const pdf = await downloadFrom(page, dialog.getByTestId("organization-report-download"));
  expect(pdf.name).toMatch(/^garnetops-report-e2e-org-\d{4}-\d{2}-\d{2}\.pdf$/);
  expect(pdf.content.subarray(0, 8).toString("latin1")).toBe("%PDF-1.4");
  await expect(dialog).toBeHidden();
  expect(problems).toEqual([]);
});

test("websites at a glance: every site worst first, sortable, each row opens its report", async ({
  page,
}) => {
  const problems = watchForProblems(page);
  await sql(
    `insert into exposure_settings (organization_id, enabled) values ($1, true)
     on conflict (organization_id) do update set enabled = true`,
    [await organizationId()],
  );
  await page.goto("/websites");
  await page.getByRole("button", { name: "At a glance" }).click();
  await expect(page).toHaveURL(/view=overview/);
  const table = page.getByTestId("websites-overview");
  await expect(table.locator("tbody tr")).toHaveCount(EXPOSURE.total);
  // The site with the critical finding comes first.
  await expect(table.locator("tbody tr").first()).toHaveAttribute("data-website", EXPOSURE.main.value);
  await expect(table.locator(`tr[data-website="${EXPOSURE.main.value}"]`)).toContainText("Critical");

  await table.getByRole("button", { name: "Website" }).click();
  await expect(table.locator("tbody tr").first()).toHaveAttribute("data-website", EXPOSURE.address.value);
  await expect(table.locator("th").first()).toHaveAttribute("aria-sort", "ascending");

  await table.getByRole("link", { name: EXPOSURE.shop.value, exact: true }).click();
  await expect(page).toHaveURL(new RegExp(`/websites/${EXPOSURE.shop.id}\\?tab=report$`));
  await expect(page.getByTestId("websites-report")).toBeVisible();

  const report = await page.request.get("/api/v1/reports/organization?days=7");
  const json = (await report.json()) as { websites: { value: string }[] };
  expect(json.websites.map((w) => w.value)).toContain(EXPOSURE.main.value);
  expect(problems).toEqual([]);
});

test("a host's report names its last report, kernel and what to do, and downloads as PDF", async ({
  page,
}) => {
  const problems = watchForProblems(page);
  const org = await organizationId();
  await sql(
    `insert into host_settings (organization_id, enabled) values ($1, true)
     on conflict (organization_id) do update set enabled = true`,
    [org],
  );
  await sql(
    `insert into agent_host (id, organization_id, name, hostname, public_key, enrolled_at, last_inventory_at, kernel_release,
       kernel_matched_at, runtime)
     values ($1, $2, 'Build 7', 'build-07.example.lan', $3, now() - interval '10 days', now() - interval '3 days',
       '6.1.0-99-amd64', now() - interval '3 days', 'container')`,
    [HOST, org, "A".repeat(43)],
  );
  await sql(
    `insert into host_kernel_finding (id, organization_id, host_id, vulnerability_id, package_name, package_version, severity,
       severity_rank, first_seen_at, last_seen_at)
     select 'hkf_e2ereport1', $1, $2, id, 'linux', '6.1.0-99', 'high', 4, now(), now() from vulnerability order by id limit 1`,
    [org, HOST],
  );

  await page.goto(`/hosts/${HOST}`);
  const report = page.locator("#report");
  await expect(report.getByRole("heading", { name: "Report", exact: true })).toBeVisible();
  await expect(report).toContainText("not reporting for more than a day");
  await expect(report).toContainText("6.1.0-99-amd64: 1 open");
  await expect(
    report.getByTestId("report-next-steps").locator('[data-step="hostNotReporting"]'),
  ).toBeVisible();
  await expect(report.getByTestId("report-next-steps").locator('[data-step="kernelUpdate"]')).toContainText(
    "1 open vulnerability",
  );
  await expect(report.getByTestId("report-worst")).toContainText("kernel");

  const pdf = await downloadFrom(page, page.getByTestId("host-report-download"));
  expect(pdf.name).toMatch(/^garnetops-report-build-7-\d{4}-\d{2}-\d{2}\.pdf$/);
  expect(pdf.content.subarray(0, 8).toString("latin1")).toBe("%PDF-1.4");
  expect(problems).toEqual([]);
});

test("the report mail is chosen on the account page, and only with a mail channel", async ({ page }) => {
  const problems = watchForProblems(page);
  await page.goto("/account?section=notifications");
  const card = page.locator("#report-mail");
  await expect(card.getByRole("heading", { name: "Security report by email" })).toBeVisible();
  await expect(card.getByTestId("report-mail-unavailable")).toBeVisible();
  await expect(card.getByLabel("Weekly (Monday to Sunday, on Mondays)")).toBeDisabled();

  await sql(
    `insert into notification_channel (id, organization_id, name, kind, events, config)
     values ('nch_e2ereport', $1, 'Mail', 'smtp', '[]'::jsonb, $2::jsonb)`,
    [
      await organizationId(),
      JSON.stringify({
        host: "mail.example.test",
        port: 587,
        security: "starttls",
        from: "noreply@example.test",
        to: [],
      }),
    ],
  );
  await page.reload();
  await expect(card.getByTestId("report-mail-unavailable")).toHaveCount(0);
  const [zone] = await sql<{ zone: string }>(
    `select coalesce(u.time_zone, o.scan_time_zone) as zone from "user" u, organization o where u.email = $1 limit 1`,
    [OWNER.email],
  );
  await expect(card).toContainText(`(${zone?.zone})`);
  await expect(card.getByLabel("Off")).toBeChecked();
  await card.getByLabel("Weekly (Monday to Sunday, on Mondays)").check();
  await card.getByLabel("Attach the report as PDF").uncheck();
  await card.getByRole("button", { name: "Save report mail" }).click();
  await expect(page.getByText("Report mail saved.")).toBeVisible();
  const rows = await sql<{ frequency: string; attach_pdf: boolean }>(
    "select frequency, attach_pdf from report_subscription where user_id = $1",
    [await ownerId()],
  );
  expect(rows).toEqual([{ frequency: "weekly", attach_pdf: false }]);

  await card.getByLabel("Off").check();
  await card.getByRole("button", { name: "Save report mail" }).click();
  await expect.poll(async () => (await sql("select 1 from report_subscription")).length).toBe(0);
  expect(problems).toEqual([]);
});
