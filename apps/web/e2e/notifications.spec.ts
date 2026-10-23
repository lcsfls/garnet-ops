import { expect, type Page, test } from "@playwright/test";
import { OWNER, STATE_FILE, watchForProblems } from "./helpers.ts";
import { sql } from "./seed.ts";

/**
 * Personal notifications (ADR 0019): the bell and its panel, marking as read, links, the live
 * stream and the polling fallback, toasts (roles, pausing, errors that stay, keyboard, reduced
 * motion), and the matrix on the account page. The worker's part is played by rows and NOTIFY,
 * exactly what the real worker writes.
 */
test.describe.configure({ mode: "serial" });
test.use({ storageState: STATE_FILE });
test.setTimeout(90_000);

interface Seed {
  titleKey?: string;
  event?: string;
  params?: Record<string, string | number>;
  link?: string;
  /** SQL for created_at, e.g. "now() - interval '2 hours'". */
  at?: string;
  read?: boolean;
}

const ownerId = async () =>
  (await sql<{ id: string }>('select id from "user" where email = $1', [OWNER.email]))[0]?.id ?? "";
const organizationId = async () =>
  (await sql<{ id: string }>("select id from organization limit 1"))[0]?.id ?? "";

/** Writes one notification for the owner and announces it, as the worker does. */
async function notify(seed: Seed = {}): Promise<number> {
  const [row] = await sql<{ id: string }>(
    `insert into user_notification (user_id, organization_id, event, title_key, params, link, created_at, read_at)
     values ($1, $2, $3, $4, $5::jsonb, $6, ${seed.at ?? "now()"}, ${seed.read ? "now()" : "null"})
     returning id`,
    [
      await ownerId(),
      await organizationId(),
      seed.event ?? "gate.blocked",
      seed.titleKey ?? "gateBlocked",
      JSON.stringify(seed.params ?? { repository: "billing-portal", rules: 1 }),
      seed.link ?? "/gates",
    ],
  );
  const id = Number(row?.id);
  await sql("select pg_notify('user_notification', $1)", [JSON.stringify({ u: await ownerId(), id })]);
  return id;
}

const EVENTS = [
  "finding.new_critical",
  "gate.blocked",
  "scan.failed",
  "fix_pr.merged",
  "fix_pr.failed",
  "infra.host_key_changed",
  "infra.certificate_changed",
  "infra.sync_blocked",
  "unifi.certificate_changed",
  "unifi.device_offline",
  "unifi.firmware_update_available",
  "exposure.certificate_expiring",
  "exposure.verification_lost",
  "exposure.new_open_port",
  "exposure.risky_service",
  "team.invitation_accepted",
  "team.role_changed",
  "system.update_finished",
];
const reset = () => sql("delete from user_notification");
const bell = (page: Page) => page.getByRole("button", { name: /^Notifications/ });
const panel = (page: Page) => page.getByRole("region", { name: "Your notifications" });
const matrix = (page: Page) => page.getByTestId("notification-matrix");

test.beforeEach(async () => {
  const info = test.info();
  await reset();
  await sql("delete from notification_preference");
  await sql("delete from notification_channel");
  await sql("delete from rate_limit");
  // The workers of this run (fix pull requests) can still report something from an earlier spec while
  // the bell tests count notifications, so the owner mutes every event for them. The notifications here
  // are written by the tests themselves. The matrix tests need the defaults and so run unmuted.
  if (!info.titlePath.some((part) => part.startsWith("the matrix"))) {
    await sql(
      `insert into notification_preference (organization_id, user_id, event, in_app, email, scope)
       select $1, $2, e, false, false, 'all' from unnest($3::text[]) as e`,
      [await organizationId(), await ownerId(), [...EVENTS]],
    );
  }
});
test.afterEach(async () => {
  const info = test.info();
  if (info.status === info.expectedStatus) return;
  // For the report: what the database holds when a test fails (names only, no content).
  const rows = await sql<{ title_key: string; unread: boolean; created_at: string }>(
    "select title_key, read_at is null as unread, created_at from user_notification order by id",
  );
  console.log(`notifications at failure: ${JSON.stringify(rows)}`);
});
test.afterAll(async () => {
  await reset();
  await sql("delete from notification_preference");
  await sql("delete from notification_channel");
});

test("the bell shows the unread count and the panel lists notifications by day", async ({ page }) => {
  const problems = watchForProblems(page);
  // Oldest first: the list is in the order they were written, newest at the top.
  await notify({
    params: { repository: "long-ago", rules: 1 },
    at: "now() - interval '40 days'",
    read: true,
  });
  // Yesterday noon, in the user's zone (Europe/Berlin in this run).
  await notify({
    params: { repository: "yesterday", rules: 1 },
    at: "((date_trunc('day', now() at time zone 'Europe/Berlin') - interval '12 hours') at time zone 'Europe/Berlin')",
  });
  await notify({ titleKey: "scanFailed", event: "scan.failed", params: { repository: "today-two" } });
  await notify({ params: { repository: "today-one", rules: 2 } });

  await page.goto("/");
  await expect(bell(page)).toHaveAccessibleName("Notifications, 3 unread");
  await expect(page.getByTestId("bell-count")).toHaveText("3");
  // Nothing pulses or bounces.
  expect(await page.getByTestId("bell-count").evaluate((el) => getComputedStyle(el).animationName)).toBe(
    "none",
  );

  await bell(page).click();
  await expect(bell(page)).toHaveAttribute("aria-expanded", "true");
  const list = panel(page);
  await expect(list.getByRole("heading", { name: "Notifications", level: 2 })).toBeVisible();
  const days = await list.getByRole("heading", { level: 3 }).allInnerTexts();
  expect(days.slice(0, 2)).toEqual(["Today", "Yesterday"]);
  expect(days).toHaveLength(3);
  await expect(list.getByText("Quality gate blocked: today-one")).toBeVisible();
  await expect(list.getByText("Scan failed: today-two")).toBeVisible();
  await expect(list.getByText("Rules set to Block that matched: 2.")).toBeVisible();
  // Relative time, with the exact time on hover.
  const time = list.locator("time").first();
  await expect(time).toHaveText(/now|minute|second/i);
  expect(await time.getAttribute("title")).toMatch(/\d{4}/);
  // Unread is more than a colour: bold and announced.
  const unreadItem = list.locator("li[data-unread]").first();
  await expect(unreadItem).toContainText("Unread:");
  await expect(list.locator("li[data-unread]")).toHaveCount(3);
  await expect(list.getByRole("link", { name: "Notification settings" })).toHaveAttribute(
    "href",
    "/account?section=notifications",
  );
  expect(problems).toEqual([]);
});

test("UniFi notifications read as sentences, with a link to the network devices, in English and German", async ({
  page,
}) => {
  const problems = watchForProblems(page);
  await notify({
    titleKey: "unifiCertificateChanged",
    event: "unifi.certificate_changed",
    params: { name: "Main console" },
    link: "/settings?section=unifi",
  });
  await notify({
    titleKey: "unifiDeviceOffline",
    event: "unifi.device_offline",
    params: { name: "Main console", device: "ap-hall", count: 2 },
    link: "/servers?view=unifi",
  });
  await notify({
    titleKey: "unifiFirmwareUpdate",
    event: "unifi.firmware_update_available",
    // A device name is text from the console: it stays text.
    params: { name: "Main console", device: "<b>gateway</b>", count: 3 },
    link: "/servers?view=unifi",
  });
  await page.goto("/");
  await bell(page).click();
  const list = panel(page);
  await expect(list.getByText("UniFi certificate changed: Main console")).toBeVisible();
  await expect(list.getByText("UniFi device offline: ap-hall")).toBeVisible();
  await expect(list.getByText("Devices offline in two syncs in a row: 2, on Main console.")).toBeVisible();
  await expect(list.getByText("UniFi firmware update available: <b>gateway</b>")).toBeVisible();
  await expect(list.getByText("A maintenance hint, not a vulnerability check.")).toBeVisible();
  await expect(list.locator("b")).toHaveCount(0);
  await list.getByRole("link", { name: /UniFi device offline/ }).click();
  await expect(page).toHaveURL(/\/servers\?view=unifi$/);
  await expect(page.getByRole("heading", { name: "Network devices", level: 2 })).toBeVisible();

  await page.addInitScript(() => localStorage.setItem("garnetops.language", "de"));
  await page.goto("/");
  await expect(page.locator("html")).toHaveAttribute("lang", "de");
  await page.getByRole("button", { name: /^Benachrichtigungen/ }).click();
  const german = page.getByRole("region", { name: "Ihre Benachrichtigungen" });
  await expect(german.getByText("UniFi-Zertifikat geändert: Main console")).toBeVisible();
  await expect(german.getByText("UniFi-Gerät offline: ap-hall")).toBeVisible();
  await expect(german.getByText("UniFi-Firmware-Update verfügbar: <b>gateway</b>")).toBeVisible();
  expect(problems).toEqual([]);
});

test("Exposure notifications read as sentences, with a link to the asset, in English and German", async ({
  page,
}) => {
  const problems = watchForProblems(page);
  const link = "/exposure/exa_e2eseeded0000000001";
  await notify({
    titleKey: "exposureCertificateExpiring",
    event: "exposure.certificate_expiring",
    params: { asset: "example.com", days: 7 },
    link,
  });
  await notify({
    titleKey: "exposureCertificateExpired",
    event: "exposure.certificate_expiring",
    params: { asset: "shop.example.net", days: 0 },
    link,
  });
  await notify({
    titleKey: "exposureVerificationLost",
    event: "exposure.verification_lost",
    // A name is text: it stays text.
    params: { asset: "<b>old</b>.example.org" },
    link,
  });
  await notify({
    titleKey: "exposureNewOpenPort",
    event: "exposure.new_open_port",
    params: { asset: "example.com", count: 2, ports: "3306, 5432" },
    link,
  });
  await notify({
    titleKey: "exposureRiskyService",
    event: "exposure.risky_service",
    params: { asset: "example.com", count: 1, port: 3306, service: "mysql" },
    link,
  });
  await page.goto("/");
  await bell(page).click();
  const list = panel(page);
  await expect(list.getByText("Certificate expires soon: example.com")).toBeVisible();
  await expect(list.getByText("Days left on the certificate: 7.")).toBeVisible();
  await expect(list.getByText("Certificate expired: shop.example.net")).toBeVisible();
  await expect(list.getByText("Verification lost: <b>old</b>.example.org")).toBeVisible();
  await expect(list.getByText("Open since the last run (2): 3306, 5432.")).toBeVisible();
  await expect(list.getByText("Risky service reachable: example.com")).toBeVisible();
  await expect(list.locator("b")).toHaveCount(0);
  await list.getByRole("link", { name: /Risky service reachable/ }).click();
  await expect(page).toHaveURL(/\/exposure\/exa_e2eseeded0000000001$/);
  await expect(page.getByRole("heading", { name: "example.com", level: 1 })).toBeVisible();

  await page.addInitScript(() => localStorage.setItem("garnetops.language", "de"));
  await page.goto("/");
  await expect(page.locator("html")).toHaveAttribute("lang", "de");
  await page.getByRole("button", { name: /^Benachrichtigungen/ }).click();
  const german = page.getByRole("region", { name: "Ihre Benachrichtigungen" });
  await expect(german.getByText("Zertifikat läuft bald ab: example.com")).toBeVisible();
  await expect(german.getByText("Verifizierung verloren: <b>old</b>.example.org")).toBeVisible();
  await expect(german.getByText("Riskanter Dienst erreichbar: example.com")).toBeVisible();
  expect(problems).toEqual([]);
});

test("one notification is marked read, then all, and it sticks after a reload", async ({ page }) => {
  await notify({ params: { repository: "first", rules: 1 } });
  await notify({ params: { repository: "second", rules: 1 } });
  await notify({ params: { repository: "third", rules: 1 } });
  await page.goto("/");
  await expect(page.getByTestId("bell-count")).toHaveText("3");
  await bell(page).click();
  const list = panel(page);
  await list.locator("li", { hasText: "second" }).getByRole("button", { name: "Mark as read" }).click();
  await expect(page.getByTestId("bell-count")).toHaveText("2");
  await expect(list.locator("li[data-unread]")).toHaveCount(2);
  await expect(bell(page)).toHaveAccessibleName("Notifications, 2 unread");

  await list.getByRole("button", { name: "Mark all as read" }).click();
  await expect(page.getByTestId("bell-count")).toHaveCount(0);
  await expect(bell(page)).toHaveAccessibleName("Notifications");
  await expect(list.getByRole("button", { name: "Mark all as read" })).toBeDisabled();
  await expect(
    page.getByRole("status").filter({ hasText: "All notifications marked as read." }),
  ).toBeVisible();

  await page.reload();
  await expect(page.getByTestId("bell-count")).toHaveCount(0);
  const [{ unread }] = (await sql<{ unread: string }>(
    "select count(*) as unread from user_notification where read_at is null",
  )) as [{ unread: string }];
  expect(Number(unread)).toBe(0);
});

test("a notification opens its page and is marked read; Escape closes the panel; a bad link is only text", async ({
  page,
}) => {
  await notify({ params: { repository: "to-gates", rules: 1 }, link: "/gates" });
  await notify({
    params: { repository: "bad-link", rules: 1 },
    link: "https://evil.example/phish",
  });
  await page.goto("/");
  await expect(page.getByTestId("bell-count")).toHaveText("2");
  await bell(page).click();
  const list = panel(page);
  // The stored link is not an app path: it is shown, not followed.
  await expect(list.locator("li", { hasText: "bad-link" }).getByRole("link")).toHaveCount(0);
  await list.getByRole("link", { name: /to-gates/ }).click();
  await expect(page).toHaveURL(/\/gates$/);
  await expect(panel(page)).toHaveCount(0);
  await expect(page.getByTestId("bell-count")).toHaveText("1");
  const [row] = await sql<{ read_at: string | null }>(
    "select read_at from user_notification where params->>'repository' = 'to-gates'",
  );
  expect(row?.read_at).not.toBeNull();

  await bell(page).click();
  await expect(panel(page)).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(panel(page)).toHaveCount(0);
  await expect(bell(page)).toBeFocused();
});

test("older notifications load on request, and a lot of unread ones show 99+", async ({ page }) => {
  for (let i = 0; i < 105; i++) {
    await sql(
      `insert into user_notification (user_id, organization_id, event, title_key, params, link, created_at)
       values ($1, $2, 'gate.blocked', 'gateBlocked', $3::jsonb, '/gates', now() - ($4 || ' minutes')::interval)`,
      [await ownerId(), await organizationId(), JSON.stringify({ repository: `r${i}`, rules: 1 }), String(i)],
    );
  }
  await page.goto("/");
  await expect(page.getByTestId("bell-count")).toHaveText("99+");
  await bell(page).click();
  const list = panel(page);
  await expect(list.locator("li")).toHaveCount(30);
  await list.getByRole("button", { name: "Show older" }).click();
  await expect(list.locator("li")).toHaveCount(60);
});

test("a new notification arrives live: the count grows and a short message appears", async ({ page }) => {
  const problems = watchForProblems(page);
  await page.goto("/");
  await expect(bell(page)).toHaveAccessibleName("Notifications");
  // The stream is open once the panel says so.
  await bell(page).click();
  await expect(panel(page).getByText("Updates arrive as they happen.")).toBeVisible();
  await page.keyboard.press("Escape");

  await notify({ params: { repository: "live-one", rules: 4 } });
  await expect(page.getByTestId("bell-count")).toHaveText("1", { timeout: 8000 });
  const message = page.getByRole("status").filter({ hasText: "Quality gate blocked: live-one" });
  await expect(message).toBeVisible();
  // It offers the page, and takes no focus.
  await expect(message.getByRole("link", { name: "View" })).toHaveAttribute("href", "/gates");
  await expect(bell(page)).toBeFocused(); // Escape returned focus to the bell; the message did not take it
  await bell(page).click();
  await expect(panel(page).getByText("Quality gate blocked: live-one")).toBeVisible();

  // A burst never piles up more than three messages, and the newest one is among them.
  await page.keyboard.press("Escape");
  for (let i = 0; i < 4; i++) await notify({ params: { repository: `burst-${i}`, rules: 1 } });
  await expect(page.getByTestId("bell-count")).toHaveText("5", { timeout: 8000 });
  await expect(page.getByRole("status").filter({ hasText: "burst-3" })).toBeVisible();
  expect(await page.locator("[data-toast]").count()).toBeLessThanOrEqual(3);
  expect(problems).toEqual([]);
});

test("without the stream the list is polled every 30 seconds", async ({ page }) => {
  test.setTimeout(120_000);
  await page.route("**/api/v1/me/notifications/stream", (route) => route.abort());
  await page.goto("/");
  await expect(bell(page)).toHaveAccessibleName("Notifications");
  await bell(page).click();
  await expect(panel(page).getByText("Checking for new notifications every 30 seconds.")).toBeVisible();
  await page.keyboard.press("Escape");
  await notify({ params: { repository: "polled", rules: 1 } });
  await expect(page.getByTestId("bell-count")).toHaveText("1", { timeout: 45_000 });
});

test("another person's notification never reaches this bell", async ({ page }) => {
  const [other] = await sql<{ id: string }>('select id from "user" where email <> $1 limit 1', [OWNER.email]);
  test.skip(!other, "no second account in this database");
  await sql(
    `insert into user_notification (user_id, organization_id, event, title_key, params, link)
     values ($1, $2, 'gate.blocked', 'gateBlocked', '{"repository":"not-yours","rules":1}', '/gates')`,
    [other?.id, await organizationId()],
  );
  await sql("select pg_notify('user_notification', $1)", [JSON.stringify({ u: other?.id, id: 1 })]);
  await page.goto("/");
  await expect(bell(page)).toHaveAccessibleName("Notifications");
  await bell(page).click();
  await expect(panel(page).getByText("not-yours")).toHaveCount(0);
  await expect(panel(page).getByText("No notifications yet.")).toBeVisible();
  const res = await page.request.get("/api/v1/me/notifications");
  expect(JSON.stringify(await res.json())).not.toContain("not-yours");
  await sql("delete from user_notification where params->>'repository' = 'not-yours'");
});

test.describe("toasts", () => {
  test("a saved setting shows a message that closes by itself and takes no focus", async ({ page }) => {
    const problems = watchForProblems(page);
    await page.goto("/settings");
    const save = page.getByRole("button", { name: "Save", exact: true }).first();
    await save.focus();
    await save.press("Enter");
    const message = page.getByRole("status").filter({ hasText: "Saved." });
    await expect(message).toBeVisible();
    // Kind is carried by words for screen readers and a shape, not only by colour.
    await expect(message.getByText("Done:")).toBeAttached();
    await expect(message).toHaveAttribute("aria-live", "polite");
    // The message did not take the focus (the Save button is disabled while it saves, so it lost it already).
    expect(await page.evaluate(() => document.activeElement?.closest("[aria-label='Messages']"))).toBeNull();
    // Bottom right of the window.
    const box = await message.boundingBox();
    const view = page.viewportSize();
    expect(box && view && box.x + box.width <= view.width && box.y + box.height <= view.height).toBe(true);
    expect(box && view && box.x > view.width / 2 && box.y > view.height / 2).toBe(true);
    await expect(message).toBeHidden({ timeout: 12_000 });
    expect(problems).toEqual([]);
  });

  test("hovering a message pauses it", async ({ page }) => {
    await page.goto("/settings");
    await page.getByRole("button", { name: "Save", exact: true }).first().click();
    const message = page.getByRole("status").filter({ hasText: "Saved." });
    await expect(message).toBeVisible();
    await message.hover();
    // Longer than its time (6 seconds): it is still there while the pointer is on it.
    await page.waitForTimeout(8000);
    await expect(message).toBeVisible();
    await page.mouse.move(5, 5);
    await expect(message).toBeHidden({ timeout: 12_000 });
  });

  test("an error stays until it is closed, is announced at once, and the close button is reached with the keyboard", async ({
    page,
  }) => {
    await notify({ params: { repository: "will-fail", rules: 1 } });
    await page.route("**/api/v1/me/notifications/*/read", (route) =>
      route.fulfill({ status: 500, body: "" }),
    );
    await page.goto("/");
    await bell(page).click();
    await panel(page).getByRole("button", { name: "Mark as read" }).click();
    const alert = page.getByRole("alert").filter({ hasText: "That did not work. Try again." });
    await expect(alert).toBeVisible();
    await expect(alert).toHaveAttribute("aria-live", "assertive");
    await expect(alert.getByText("Error:")).toBeAttached();
    await page.waitForTimeout(8000);
    await expect(alert).toBeVisible();
    // Keyboard: Alt+Shift+T moves to the messages; Enter on the close button closes it.
    await page.keyboard.press("Escape");
    await page.keyboard.press("Alt+Shift+T");
    const close = alert.getByRole("button", { name: "Close message" });
    await expect(close).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(alert).toHaveCount(0);
  });

  test("reduced motion switches the movement off", async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto("/settings");
    await page.getByRole("button", { name: "Save", exact: true }).first().click();
    const message = page.getByRole("status").filter({ hasText: "Saved." });
    await expect(message).toBeVisible();
    expect(await message.evaluate((el) => getComputedStyle(el).animationName)).toBe("none");
  });
});

test.describe("the matrix on the account page", () => {
  test("lists the events by group, explains the relation to the organisation's channels, and disables email without a mail channel", async ({
    page,
  }) => {
    const problems = watchForProblems(page);
    await page.goto("/account?section=notifications");
    await expect(page.getByRole("heading", { name: "Notifications", level: 2 })).toBeVisible();
    const table = matrix(page);
    await expect(table.getByRole("rowheader")).toHaveCount(18); // one row per event; the group rows are column groups
    for (const group of ["Code", "Infrastructure", "Account and team", "System"]) {
      await expect(table.getByRole("columnheader", { name: group })).toBeVisible();
    }
    // The UniFi events (ADR 0022) are in the Infrastructure group, for owners and admins, in the app by default.
    for (const [event, label] of [
      ["unifi.certificate_changed", "A UniFi certificate changed"],
      ["unifi.device_offline", "A UniFi device is offline"],
      ["unifi.firmware_update_available", "A UniFi firmware update is available"],
      // The exposure events (ADR 0023) likewise.
      ["exposure.certificate_expiring", "An exposed certificate expires soon"],
      ["exposure.verification_lost", "An asset lost its verification"],
      ["exposure.new_open_port", "A new port is open on an asset"],
      ["exposure.risky_service", "A risky service is reachable from the internet"],
    ] as const) {
      const row = table.locator(`tr[data-event='${event}']`);
      await expect(row.getByRole("rowheader")).toContainText(label);
      await expect(row.getByRole("checkbox", { name: `${label}: in the app` })).toBeChecked();
      await expect(row.getByRole("checkbox", { name: `${label}: by email` })).toBeDisabled();
    }
    await expect(page.getByText("The shared channels of your organisation")).toBeVisible();
    await expect(page.getByRole("link", { name: "Open the organisation channels" })).toHaveAttribute(
      "href",
      "/settings?section=notifications",
    );
    // Defaults: in app on, email off and not available.
    const gate = table.locator("tr[data-event='gate.blocked']");
    await expect(gate.getByRole("checkbox", { name: "A quality gate blocked: in the app" })).toBeChecked();
    const email = gate.getByRole("checkbox", { name: "A quality gate blocked: by email" });
    await expect(email).toBeDisabled();
    await expect(email).not.toBeChecked();
    await expect(page.getByText("Email is not available")).toBeVisible();
    await expect(page.getByText("Add an SMTP or Microsoft Graph channel under Settings")).toBeVisible();
    // Fix pull requests default to the person's own requests.
    await expect(table.locator("tr[data-event='fix_pr.merged']").getByRole("combobox")).toHaveValue("mine");
    await expect(gate.getByRole("combobox")).toHaveValue("all");
    expect(problems).toEqual([]);
  });

  test("saves a choice and shows it again after a reload; restoring the defaults asks for a save", async ({
    page,
  }) => {
    await page.goto("/account?section=notifications");
    const table = matrix(page);
    const save = page.getByRole("button", { name: "Save", exact: true });
    await expect(save).toBeDisabled();
    const gate = table.locator("tr[data-event='gate.blocked']");
    await gate.getByRole("checkbox", { name: "A quality gate blocked: in the app" }).uncheck();
    const critical = table.locator("tr[data-event='finding.new_critical']");
    await critical.getByRole("combobox").selectOption("mine");
    await expect(save).toBeEnabled();
    await save.click();
    await expect(page.getByRole("status").filter({ hasText: "Notification settings saved." })).toBeVisible();
    await expect(save).toBeDisabled();

    await page.reload();
    await expect(
      gate.getByRole("checkbox", { name: "A quality gate blocked: in the app" }),
    ).not.toBeChecked();
    await expect(critical.getByRole("combobox")).toHaveValue("mine");
    const rows = await sql<{ event: string; in_app: boolean; scope: string }>(
      "select event, in_app, scope from notification_preference order by event",
    );
    expect(rows.find((r) => r.event === "gate.blocked")).toMatchObject({ in_app: false, scope: "all" });
    expect(rows.find((r) => r.event === "finding.new_critical")).toMatchObject({
      in_app: true,
      scope: "mine",
    });

    await page.getByRole("button", { name: "Restore defaults" }).click();
    await expect(gate.getByRole("checkbox", { name: "A quality gate blocked: in the app" })).toBeChecked();
    await expect(critical.getByRole("combobox")).toHaveValue("all");
    await expect(save).toBeEnabled();
    await save.click();
    await expect(page.getByRole("status").filter({ hasText: "Notification settings saved." })).toBeVisible();
  });

  test("email can be chosen once the organisation has a mail channel, and falls away with it", async ({
    page,
  }) => {
    const org = await organizationId();
    await sql(
      `insert into notification_channel (id, organization_id, name, kind, language, events, config)
       values ('nch_e2e_mail', $1, 'Ops mail', 'smtp', 'en', '["scan.failed"]'::jsonb,
         '{"host":"smtp.example.lan","port":465,"security":"tls","from":"noreply@example.com","to":["ops@example.com"]}'::jsonb)`,
      [org],
    );
    await page.goto("/account?section=notifications");
    const failed = matrix(page).locator("tr[data-event='scan.failed']");
    const email = failed.getByRole("checkbox", { name: "A scan failed: by email" });
    await expect(email).toBeEnabled();
    await expect(page.getByText(`Email goes to ${OWNER.email} only`)).toBeVisible();
    await email.check();
    await page.getByRole("button", { name: "Save", exact: true }).click();
    await expect(page.getByRole("status").filter({ hasText: "Notification settings saved." })).toBeVisible();
    await page.reload();
    await expect(email).toBeChecked();

    // The channel is removed: the choice is not shown as active any more.
    await sql("delete from notification_channel");
    await page.reload();
    await expect(email).toBeDisabled();
    await expect(email).not.toBeChecked();
    await expect(page.getByText("Email is not available")).toBeVisible();
  });

  test("Settings → Notifications points to the personal settings", async ({ page }) => {
    await page.goto("/settings?section=notifications");
    await expect(
      page.getByText("These channels are shared destinations for the whole organisation."),
    ).toBeVisible();
    await page.getByRole("link", { name: "My notification settings" }).click();
    await expect(page).toHaveURL(/\/account\?section=notifications$/);
    await expect(matrix(page)).toBeVisible();
  });

  test("German labels", async ({ page }) => {
    await page.addInitScript(() => localStorage.setItem("garnetops.language", "de"));
    await notify({ params: { repository: "billing", rules: 2 } });
    await page.goto("/account?section=notifications");
    await expect(page.getByRole("heading", { name: "Benachrichtigungen", level: 2 })).toBeVisible();
    await expect(matrix(page).getByRole("columnheader", { name: "In der App" })).toBeVisible();
    await expect(page.getByText("E-Mail ist nicht verfügbar")).toBeVisible();
    await page.getByRole("button", { name: /^Benachrichtigungen, 1 ungelesen/ }).click();
    await expect(page.getByText("Quality Gate blockiert: billing")).toBeVisible();
    await expect(page.getByText("Heute")).toBeVisible();
  });
});
