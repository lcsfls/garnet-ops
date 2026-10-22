import { expect, type Locator, test } from "@playwright/test";
import {
  contentWidth,
  hasNoHorizontalScroll,
  misalignedFormRows,
  overflowingCards,
  STATE_FILE,
  sidebarFooterOnOneLine,
  watchForProblems,
} from "./helpers.ts";
import { AI, ATTACKS, FIXES, PROXMOX, restoreWazuh, sql, WAZUH } from "./seed.ts";

/** Layout baseline (AGENTS.md rule 5): every screen fits at 1080p with 100, 125 and 150 % scaling. */
test.describe("signed out", () => {
  test("sign-in fits without horizontal scrolling", async ({ page }, info) => {
    const problems = watchForProblems(page);
    await page.goto("/sign-in");
    await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
    expect(await hasNoHorizontalScroll(page)).toBe(true);
    await expect(page.getByRole("button", { name: "Sign in", exact: true })).toBeInViewport();
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
    { path: "/servers", heading: "Servers", name: "servers" },
    { path: "/servers?view=proxmox", heading: "Servers", name: "proxmox" },
    {
      path: "/servers?view=proxmox&pxFlag=stale&pxSort=mem&pxType=qemu",
      heading: "Servers",
      name: "proxmox-filtered",
    },
    { path: "/servers?view=wazuh", heading: "Servers", name: "wazuh-agents" },
    { path: "/xdr", heading: "XDR", name: "xdr" },
    { path: "/attacks", heading: "Attacks", name: "attacks" },
    {
      path: "/attacks?period=7d&country=DE&sort=lastSeen&dir=asc",
      heading: "Attacks",
      name: "attacks-filtered",
    },
    { path: "/settings?section=attacks", heading: "Settings", name: "settings-attacks" },
    {
      path: "/xdr?period=30d&status=disconnected&sort=vulnerabilities",
      heading: "XDR",
      name: "xdr-filtered",
    },
    { path: "/servers/host_e2eseeded000000001", heading: "web-01", name: "server" },
    { path: "/servers/host_e2eseeded000000003", heading: "mail-01", name: "server-host-key-changed" },
    { path: "/servers/host_e2eseeded000000005", heading: "db-01", name: "server-failed" },
    { path: "/gates?repositoryId=repo_e2eseeded000000001", heading: "Quality gates", name: "gates" },
    { path: "/fixes", heading: "Fix proposals", name: "fixes" },
    { path: `/fixes?id=${FIXES.key("pkg-2")}`, heading: "Fix proposals", name: "fixes-detail" },
    { path: "/fixes?view=prs", heading: "Fix proposals", name: "fixes-pull-requests" },
    { path: "/settings", heading: "Settings", name: "settings" },
    { path: "/account", heading: "Account", name: "account" },
    { path: "/account?section=password", heading: "Account", name: "account-password" },
    { path: "/account?section=authenticator", heading: "Account", name: "account-authenticator" },
    { path: "/account?section=passkeys", heading: "Account", name: "account-passkeys" },
    { path: "/account?section=sessions", heading: "Account", name: "account-sessions" },
    { path: "/settings?section=updates", heading: "Settings", name: "settings-updates" },
    { path: "/settings?section=notifications", heading: "Settings", name: "settings-notifications" },
    { path: "/settings?section=proxmox", heading: "Settings", name: "settings-proxmox" },
    { path: "/settings?section=xdr", heading: "Settings", name: "settings-xdr" },
    { path: "/settings?section=ai", heading: "Settings", name: "settings-ai" },
    { path: `/findings?id=${AI.talked.findingId}&ai=1`, heading: "Findings", name: "findings-ai" },
    { path: "/settings?section=about", heading: "Settings", name: "settings-about" },
    { path: "/repositories/repo_e2eseeded000000001", heading: "seeded-app", name: "repository" },
    { path: "/audit-log", heading: "Audit log", name: "audit-log" },
    { path: "/team", heading: "Team", name: "team" },
  ]) {
    test(`${name} fits without horizontal scrolling`, async ({ page }, info) => {
      const problems = watchForProblems(page);
      await page.goto(path);
      await expect(page.getByRole("heading", { name: heading, exact: true })).toBeVisible();
      await page.waitForLoadState("networkidle");
      expect(await hasNoHorizontalScroll(page)).toBe(true);
      expect(await overflowingCards(page)).toEqual([]);
      expect(await misalignedFormRows(page)).toEqual([]);
      expect(await sidebarFooterOnOneLine(page)).toBe(true);
      await expect(page.getByRole("button", { name: /^Account: / })).toBeInViewport();
      await page.screenshot({ path: info.outputPath(`${name}.png`), fullPage: true });
      expect(problems).toEqual([]);
    });
  }

  test("settings: sections, form and help follow the content width and stay inside it", async ({
    page,
  }, info) => {
    const problems = watchForProblems(page);
    for (const section of [
      "scanning",
      "notifications",
      "proxmox",
      "xdr",
      "attacks",
      "ai",
      "updates",
      "about",
    ]) {
      await page.goto(`/settings?section=${section}`);
      await expect(page.getByRole("heading", { name: "Settings", exact: true })).toBeVisible();
      await expect(page.getByRole("heading", { name: "Good to know" })).toBeVisible();
      await page.waitForLoadState("networkidle");
      const content = await contentWidth(page);
      const boxes = await page.evaluate(() => {
        const rect = (el: Element | null | undefined) => {
          const b = el?.getBoundingClientRect();
          return b ? { left: b.left, right: b.right, top: b.top, bottom: b.bottom } : null;
        };
        const main = document.querySelector("main[data-content]");
        const help = Array.from(document.querySelectorAll("main section")).find((s) =>
          s.querySelector("h2")?.textContent?.startsWith("Good to know"),
        );
        const form = document.querySelector("[data-testid='settings-form']");
        const nav = document.querySelector("main nav[aria-label='Settings sections']");
        return { main: rect(main), help: rect(help), form: rect(form), nav: rect(nav) };
      });
      const { main, help, form, nav } = boxes;
      expect(main && help && form && nav, section).toBeTruthy();
      if (!(main && help && form && nav)) continue;
      // Nothing sticks out of the content area, whatever the step.
      expect(help.right, `${section}: help inside the content area`).toBeLessThanOrEqual(main.right + 1);
      expect(form.right, `${section}: form inside the content area`).toBeLessThanOrEqual(main.right + 1);
      if (content >= 1450) {
        // Wide: sections, form and help side by side.
        expect(help.left, `${section}: help beside the form`).toBeGreaterThanOrEqual(form.right - 1);
        expect(form.left).toBeGreaterThanOrEqual(nav.right - 1);
      } else {
        // Below wide: the help is under the form, never beside it and never cut off.
        expect(help.top, `${section}: help below the form`).toBeGreaterThanOrEqual(form.bottom - 1);
      }
      if (content >= 768)
        expect(form.left, `${section}: form beside the sections`).toBeGreaterThanOrEqual(nav.right - 1);
      else expect(form.top, `${section}: form below the sections`).toBeGreaterThanOrEqual(nav.bottom - 1);
      expect(await hasNoHorizontalScroll(page), section).toBe(true);
      expect(await overflowingCards(page), section).toEqual([]);
      expect(await misalignedFormRows(page), section).toEqual([]);
      await page.screenshot({ path: info.outputPath(`settings-${section}.png`), fullPage: true });
    }
    expect(problems).toEqual([]);
  });

  test("the nightly scan time and time zone share one line of labels and one line of controls", async ({
    page,
  }) => {
    await page.goto("/settings");
    await expect(page.getByLabel("Time", { exact: true })).toBeVisible();
    await expect(page.getByLabel("Time zone")).toBeVisible();
    const tops = await page.evaluate(() => {
      const top = (selector: string) => document.querySelector(selector)?.getBoundingClientRect().top ?? -1;
      return {
        timeLabel: top("label[for='nightly-time']"),
        zoneLabel: top("label[for='nightly-zone']"),
        timeInput: top("#nightly-time"),
        zoneInput: top("#nightly-zone"),
      };
    });
    const content = await contentWidth(page);
    // From 28 rem of card width the two sit side by side (the card is narrower than the content area).
    if (content >= 768) {
      expect(Math.abs(tops.timeLabel - tops.zoneLabel)).toBeLessThanOrEqual(1);
      expect(Math.abs(tops.timeInput - tops.zoneInput)).toBeLessThanOrEqual(1);
    }
    expect(await misalignedFormRows(page)).toEqual([]);
  });

  test("settings and the account page stay inside the content area in small windows and in German", async ({
    page,
  }) => {
    const problems = watchForProblems(page);
    // German texts are longer; 760 px is a small window next to the wider sidebar.
    await page.addInitScript(() => localStorage.setItem("garnetops.language", "de"));
    const paths = [
      "/settings",
      "/settings?section=notifications",
      "/settings?section=proxmox",
      "/settings?section=xdr",
      "/settings?section=attacks",
      "/settings?section=ai",
      "/settings?section=updates",
      "/settings?section=about",
      "/account",
      "/account?section=password",
      "/account?section=authenticator",
      "/account?section=passkeys",
      "/account?section=sessions",
    ];
    const height = page.viewportSize()?.height ?? 800;
    for (const width of [760, 900]) {
      await page.setViewportSize({ width, height });
      for (const path of paths) {
        await page.goto(path);
        await expect(page.locator("html")).toHaveAttribute("lang", "de");
        await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
        await page.waitForLoadState("networkidle");
        expect(await hasNoHorizontalScroll(page), `${width} ${path}`).toBe(true);
        expect(await overflowingCards(page), `${width} ${path}`).toEqual([]);
        expect(await misalignedFormRows(page), `${width} ${path}`).toEqual([]);
        expect(await sidebarFooterOnOneLine(page), `${width} ${path}`).toBe(true);
      }
    }
    expect(problems).toEqual([]);
  });

  test("the account dialogs fit the screen", async ({ page }, info) => {
    const problems = watchForProblems(page);
    const fits = (dialog: Locator) =>
      dialog.evaluate((el) => {
        const box = el.getBoundingClientRect();
        return el.scrollWidth <= el.clientWidth + 1 && box.left >= 0 && box.right <= window.innerWidth;
      });
    await page.goto("/account?section=passkeys");
    await page.getByRole("button", { name: "Add a passkey" }).click();
    const add = page.getByRole("dialog", { name: "Add a passkey" });
    await expect(add).toBeVisible();
    await page.screenshot({ path: info.outputPath("account-add-passkey.png") });
    expect(await fits(add)).toBe(true);
    await page.keyboard.press("Escape");

    await page.goto("/account?section=authenticator");
    await page.getByRole("button", { name: "Replace authenticator app" }).click();
    const replace = page.getByRole("dialog", { name: "Replace the authenticator app" });
    await expect(replace).toBeVisible();
    await page.screenshot({ path: info.outputPath("account-replace-authenticator.png") });
    expect(await fits(replace)).toBe(true);
    await page.keyboard.press("Escape");

    await page.getByRole("button", { name: "Create new backup codes" }).click();
    const codes = page.getByRole("dialog", { name: "Create new backup codes?" });
    await expect(codes).toBeVisible();
    expect(await fits(codes)).toBe(true);
    expect(await hasNoHorizontalScroll(page)).toBe(true);
    expect(problems).toEqual([]);
  });

  test("the add server dialogs fit the screen, with the script and the host key step", async ({
    page,
  }, info) => {
    const problems = watchForProblems(page);
    await page.goto("/servers?add=1");
    const wizard = page.getByRole("dialog", { name: "Add a server" });
    await expect(wizard).toBeVisible();
    await page.screenshot({ path: info.outputPath("add-server-1.png") });
    const fits = async () =>
      wizard.evaluate((el) => {
        const box = el.getBoundingClientRect();
        return el.scrollWidth <= el.clientWidth + 1 && box.left >= 0 && box.right <= window.innerWidth;
      });
    expect(await fits()).toBe(true);

    await wizard.getByLabel("Address", { exact: true }).fill("layout-01.example.test");
    await wizard.getByRole("button", { name: "Add server and continue" }).click();
    await expect(wizard).toContainText("Step 2 of 4");
    await wizard.getByRole("button", { name: "Copy script" }).first().click();
    await expect(wizard.getByLabel("Script", { exact: true })).toBeVisible();
    await page.screenshot({ path: info.outputPath("add-server-2.png") });
    expect(await fits()).toBe(true);
    await wizard.getByRole("button", { name: "One command" }).click();
    await wizard.getByRole("button", { name: "Create command" }).click();
    await expect(wizard.getByLabel("Command to run on the server")).toBeVisible();
    await page.screenshot({ path: info.outputPath("add-server-2-command.png") });
    expect(await fits()).toBe(true);

    await wizard.getByRole("button", { name: "Continue" }).click();
    await expect(wizard).toContainText("Step 3 of 4");
    await page.screenshot({ path: info.outputPath("add-server-3.png") });
    expect(await fits()).toBe(true);
    expect(await hasNoHorizontalScroll(page)).toBe(true);

    // Clean up what this test added (the viewports run one after another on the same database).
    await sql("delete from host where address = 'layout-01.example.test'");
    expect(problems).toEqual([]);
  });

  test("the Proxmox dialogs fit the screen: guest, add as server, connection and certificate", async ({
    page,
  }, info) => {
    const problems = watchForProblems(page);
    const fits = (dialog: Locator) =>
      dialog.evaluate((el) => {
        const box = el.getBoundingClientRect();
        return el.scrollWidth <= el.clientWidth + 1 && box.left >= 0 && box.right <= window.innerWidth;
      });
    await page.goto(`/servers?view=proxmox&guest=${PROXMOX.guests.cache.id}`);
    const guest = page.getByRole("dialog", { name: "cache-01" });
    await expect(guest).toBeVisible();
    await page.screenshot({ path: info.outputPath("proxmox-guest.png") });
    expect(await fits(guest)).toBe(true);

    await page.goto(`/servers?view=proxmox&addGuest=${PROXMOX.guests.app.id}`);
    const wizard = page.getByRole("dialog", { name: "Add a server" });
    await expect(wizard).toContainText("Addresses known for this guest: 192.0.2.61, 2001:db8::61");
    await page.screenshot({ path: info.outputPath("proxmox-add-as-server.png") });
    expect(await fits(wizard)).toBe(true);

    await page.goto("/settings?section=proxmox");
    await page.getByRole("button", { name: "Add connection" }).click();
    const connection = page.getByRole("dialog", { name: "Connect Proxmox VE" });
    await expect(connection).toBeVisible();
    await page.screenshot({ path: info.outputPath("proxmox-connection.png") });
    expect(await fits(connection)).toBe(true);
    await page.keyboard.press("Escape");

    await page
      .getByRole("listitem")
      .filter({ hasText: PROXMOX.changed.name })
      .getByRole("button", { name: "Review the change" })
      .click();
    const certificate = page.getByRole("dialog", { name: "The certificate of Moved lab changed" });
    await expect(certificate).toBeVisible();
    await page.screenshot({ path: info.outputPath("proxmox-certificate.png") });
    expect(await fits(certificate)).toBe(true);
    expect(await hasNoHorizontalScroll(page)).toBe(true);
    expect(problems).toEqual([]);
  });

  test("XDR uses wide screens: more columns from wide on, the most from xwide on, and nothing is lost below", async ({
    page,
  }, info) => {
    const problems = watchForProblems(page);
    await page.goto("/xdr");
    await expect(page.getByRole("heading", { name: "XDR", level: 1 })).toBeVisible();
    await page.waitForLoadState("networkidle");
    // The content area is the main area without sidebar and page padding (AGENTS.md rule 5).
    const content = await contentWidth(page);
    const agents = page
      .locator("section")
      .filter({ has: page.getByRole("heading", { name: "Agents", exact: true }) });
    const header = (name: string) => agents.getByRole("columnheader", { name, exact: true });
    // Always there.
    await expect(header("Agent")).toBeVisible();
    await expect(header("Status")).toBeVisible();
    await expect(header("Vulnerabilities")).toBeVisible();
    await expect(header("Server")).toBeVisible();
    // From wide (content 1450 px, 1080p at 100 %): system and last keep-alive; from xwide (1900 px): version and groups.
    for (const [name, from] of [
      ["System", 1450],
      ["Last keep-alive", 1450],
      ["Version", 1900],
      ["Groups", 1900],
    ] as const) {
      if (content >= from) await expect(header(name)).toBeVisible();
      else await expect(header(name)).toBeHidden();
    }
    // Below wide the address moves under the name instead of disappearing.
    const web = agents.getByTestId(`agent-${WAZUH.agents.web.agentId}`);
    await expect(web).toContainText("192.0.2.21");
    // The periods table and the three cards side by side need the room; below it they stack, still complete.
    const alerts = page
      .locator("section")
      .filter({ has: page.getByRole("heading", { name: "Alerts", exact: true }) });
    if (content >= 1450) await expect(alerts.getByRole("heading", { name: "All periods" })).toBeVisible();
    else await expect(alerts.getByRole("heading", { name: "All periods" })).toBeHidden();
    const cards = ["MITRE ATT&CK tactics", "Busiest agents", "Vulnerabilities on agents"].map((name) =>
      page.locator("section").filter({ has: page.getByRole("heading", { name, exact: true }) }),
    );
    const boxes = await Promise.all(cards.map((c) => c.boundingBox()));
    expect(boxes.every(Boolean)).toBe(true);
    if (content >= 1900) {
      // Three across.
      expect(Math.abs((boxes[0]?.y ?? 0) - (boxes[2]?.y ?? 99999))).toBeLessThan(40);
    } else if (content >= 1450) {
      // Two across, the third below.
      expect(Math.abs((boxes[0]?.y ?? 0) - (boxes[1]?.y ?? 99999))).toBeLessThan(40);
      expect((boxes[2]?.y ?? 0) > (boxes[0]?.y ?? 0) + 100).toBe(true);
    }
    expect(await hasNoHorizontalScroll(page)).toBe(true);
    expect(await overflowingCards(page)).toEqual([]);
    await page.screenshot({ path: info.outputPath("xdr-columns.png"), fullPage: true });
    expect(problems).toEqual([]);
  });

  test("Attacks uses wide screens: more columns and figures from wide on, the most from xwide on, and nothing is lost below", async ({
    page,
  }, info) => {
    const problems = watchForProblems(page);
    // The reputation column is part of the layout when it is switched on.
    const [org] = await sql<{ id: string }>("select id from organization limit 1");
    await sql(
      "insert into attack_settings (organization_id, osint_enabled, osint_provider, osint_acknowledged_at) values ($1, true, 'abuseipdb', now()) on conflict (organization_id) do update set osint_enabled = true, osint_provider = 'abuseipdb', osint_acknowledged_at = now()",
      [org?.id],
    );
    await sql(
      `insert into attack_osint_result (id, organization_id, provider, ip, score, reports, last_reported_at, checked_at)
       values ('osr_layout0000000001', $1, 'abuseipdb', $2, 91, 120, now() - interval '3 hours', now())`,
      [org?.id, ATTACKS.ips.de],
    );
    try {
      await page.goto("/attacks");
      await expect(page.getByRole("heading", { name: "Attacks", level: 1 })).toBeVisible();
      await expect(page.getByTestId("attack-map").locator("svg")).toBeVisible();
      await page.waitForLoadState("networkidle");
      // The content area is the main area without sidebar and page padding (AGENTS.md rule 5).
      const content = await contentWidth(page);
      const table = page.getByTestId("attack-table");
      const header = (name: string) => table.getByRole("columnheader", { name, exact: true });
      // Always there.
      await expect(header("Address")).toBeVisible();
      await expect(header("Alerts")).toBeVisible();
      await expect(header("Abuse score")).toBeVisible();
      // Country and network from 768 px of content; groups, machines and last seen from wide; first seen from xwide.
      for (const [name, from] of [
        ["Country", 768],
        ["Network", 768],
        ["Rule groups", 1450],
        ["Machines", 1450],
        ["Last seen", 1450],
        ["First seen", 1900],
      ] as const) {
        if (content >= from) await expect(header(name), name).toBeVisible();
        else await expect(header(name), name).toBeHidden();
      }
      // Below the country column the country and the network move under the address; nothing disappears.
      const de = page.getByTestId(`attack-row-${ATTACKS.ips.de}`);
      await expect(de).toContainText("Germany");
      await expect(de).toContainText("AS64500");
      // Figures: four always, five from wide, six from xwide.
      const figures = page.getByTestId("attack-figures");
      await expect(figures.locator('[data-figure="agents"]')).toBeVisible();
      if (content >= 1450) await expect(figures.locator('[data-figure="internal"]')).toBeVisible();
      else await expect(figures.locator('[data-figure="internal"]')).toBeHidden();
      if (content >= 1900) await expect(figures.locator('[data-figure="unlocated"]')).toBeVisible();
      else await expect(figures.locator('[data-figure="unlocated"]')).toBeHidden();
      // The map and the lists: stacked below wide, map left and two lists right from wide, three across from xwide.
      const box = async (name: string) =>
        page
          .locator("section")
          .filter({ has: page.getByRole("heading", { name, exact: true }) })
          .boundingBox();
      const [map, countries, networks] = await Promise.all([
        box("Origin of the alerts"),
        box("Countries"),
        box("Networks"),
      ]);
      expect(map && countries && networks).toBeTruthy();
      if (content >= 1900) {
        expect(Math.abs((map?.y ?? 0) - (countries?.y ?? 9999))).toBeLessThan(40);
        expect(Math.abs((countries?.y ?? 0) - (networks?.y ?? 9999))).toBeLessThan(40);
      } else if (content >= 1450) {
        expect(Math.abs((map?.y ?? 0) - (countries?.y ?? 9999))).toBeLessThan(40);
        expect((networks?.y ?? 0) > (countries?.y ?? 0) + 40).toBe(true);
        expect((networks?.x ?? 0) > (map?.x ?? 0) + 100).toBe(true);
      } else {
        expect((countries?.y ?? 0) > (map?.y ?? 0) + 100).toBe(true);
      }
      expect(await hasNoHorizontalScroll(page)).toBe(true);
      expect(await overflowingCards(page)).toEqual([]);
      await page.screenshot({ path: info.outputPath("attacks-columns.png"), fullPage: true });
    } finally {
      await sql("delete from attack_osint_result");
      await sql("delete from attack_settings");
    }
    expect(problems).toEqual([]);
  });

  test("the Attacks settings fit the screen with their dialogs", async ({ page }, info) => {
    const problems = watchForProblems(page);
    await page.goto("/settings?section=attacks");
    await expect(page.getByRole("heading", { name: "Location data", level: 2 })).toBeVisible();
    await page.waitForLoadState("networkidle");
    expect(await hasNoHorizontalScroll(page)).toBe(true);
    expect(await overflowingCards(page)).toEqual([]);
    await page.getByRole("button", { name: "Delete stored addresses now" }).click();
    const dialog = page.getByRole("dialog", { name: "Delete all stored source addresses?" });
    await expect(dialog).toBeVisible();
    await page.screenshot({ path: info.outputPath("attacks-purge.png") });
    const box = await dialog.boundingBox();
    expect(
      (box?.x ?? -1) >= 0 && (box?.x ?? 0) + (box?.width ?? 0) <= (page.viewportSize()?.width ?? 0),
    ).toBe(true);
    await dialog.getByRole("button", { name: "Cancel" }).click();
    expect(problems).toEqual([]);
  });

  test("the XDR dialogs fit the screen: enrollment helper, connection and certificate", async ({
    page,
  }, info) => {
    const problems = watchForProblems(page);
    const fits = (dialog: Locator) =>
      dialog.evaluate((el) => {
        const box = el.getBoundingClientRect();
        return el.scrollWidth <= el.clientWidth + 1 && box.left >= 0 && box.right <= window.innerWidth;
      });
    await page.goto("/xdr?enroll=1");
    const enrollment = page.getByRole("dialog", { name: "Enroll an agent" });
    await expect(enrollment.getByTestId("enrollment-output")).toBeVisible();
    await page.screenshot({ path: info.outputPath("xdr-enrollment.png") });
    expect(await fits(enrollment)).toBe(true);
    await enrollment.getByLabel("My manager asks for an enrollment password").check();
    await enrollment.getByLabel("Operating system").selectOption("windows");
    expect(await fits(enrollment)).toBe(true);
    await page.keyboard.press("Escape");

    await page.goto("/settings?section=xdr");
    await page.getByRole("button", { name: `Edit connection: ${WAZUH.connection.name}` }).click();
    const connection = page.getByRole("dialog", { name: `Edit ${WAZUH.connection.name}` });
    await expect(connection).toBeVisible();
    await connection.getByText("How do I create the read-only users?").click();
    await page.screenshot({ path: info.outputPath("xdr-connection.png") });
    expect(await fits(connection)).toBe(true);
    await page.keyboard.press("Escape");

    // A changed certificate, the most text a dialog of this kind shows.
    await sql(
      `update wazuh_endpoint set cert_status = 'changed', candidate_fingerprint = $1,
         candidate_subject = 'CN=rebuilt.example.lan, O=Example, OU=A rather long organisational unit name',
         candidate_issuer = 'CN=rebuilt.example.lan', candidate_valid_from = now(), candidate_valid_to = now() + interval '1 year',
         candidate_ca_trusted = false, candidate_seen_at = now() where kind = 'indexer'`,
      [Array.from({ length: 32 }, (_, i) => (i + 16).toString(16).toUpperCase()).join(":")],
    );
    try {
      await page.goto("/settings?section=xdr");
      await page
        .getByTestId("xdr-endpoint-indexer")
        .getByRole("button", { name: "Review certificate change" })
        .click();
      const certificate = page.getByRole("dialog", { name: "The certificate of the indexer changed" });
      await expect(certificate).toBeVisible();
      await page.screenshot({ path: info.outputPath("xdr-certificate.png") });
      expect(await fits(certificate)).toBe(true);
      expect(await hasNoHorizontalScroll(page)).toBe(true);
    } finally {
      await restoreWazuh();
    }
    expect(problems).toEqual([]);
  });

  test("the AI conversation sits beside list and detail from xwide on, and behind a click below it", async ({
    page,
  }, info) => {
    const problems = watchForProblems(page);
    const width = page.viewportSize()?.width ?? 0;
    const height = page.viewportSize()?.height ?? 0;
    await page.goto(`/findings?id=${AI.talked.findingId}`);
    await expect(page.getByRole("heading", { name: "Findings", exact: true })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Test vulnerability 2." })).toBeVisible();
    await page.waitForLoadState("networkidle");
    const panel = page.getByRole("region", { name: "AI triage" });

    if (width >= 2400) {
      // xwide (AGENTS.md rule 5): list, detail and conversation side by side, no click needed.
      await expect(panel).toBeVisible();
      await expect(panel.getByText("Does the update break anything?")).toBeVisible();
      const [list, detail, ai] = await Promise.all([
        page.getByRole("table").boundingBox(),
        page.getByRole("heading", { name: "Test vulnerability 2." }).boundingBox(),
        panel.boundingBox(),
      ]);
      expect(list && detail && ai).toBeTruthy();
      expect((list?.x ?? 0) + (list?.width ?? 0)).toBeLessThanOrEqual((detail?.x ?? 0) + 1);
      expect((detail?.x ?? 0) + (detail?.width ?? 0)).toBeLessThanOrEqual((ai?.x ?? 0) + 1);
      expect(Math.abs((detail?.y ?? 0) - (ai?.y ?? 0))).toBeLessThan(80);
      // The conversation keeps its question box in view, and its text scrolls inside the pane.
      expect((ai?.y ?? 0) + (ai?.height ?? 0)).toBeLessThanOrEqual(height);
      await expect(panel.getByLabel("Ask a follow-up")).toBeInViewport();
      await page.screenshot({ path: info.outputPath("findings-three-panes.png") });
    } else {
      await expect(panel).toHaveCount(0);
      await page.getByRole("button", { name: "Ask AI" }).click();
      const drawer = page.getByRole("dialog", { name: "AI triage" });
      await expect(drawer.getByText("Does the update break anything?")).toBeVisible();
      const box = await drawer.boundingBox();
      expect((box?.x ?? 0) + (box?.width ?? 0)).toBeLessThanOrEqual(width + 1);
      expect(box?.height ?? 0).toBeLessThanOrEqual(height + 1);
      await expect(drawer.getByLabel("Ask a follow-up")).toBeInViewport();
      await page.screenshot({ path: info.outputPath("findings-ai-drawer.png") });
    }
    expect(await hasNoHorizontalScroll(page)).toBe(true);
    expect(await overflowingCards(page)).toEqual([]);
    expect(problems).toEqual([]);
  });

  test("fix pull request screens fit with write access on: card, Renovate, Create PR and a failed token", async ({
    page,
  }, info) => {
    const problems = watchForProblems(page);
    const fits = (dialog: Locator) =>
      dialog.evaluate((el) => {
        const box = el.getBoundingClientRect();
        return el.scrollWidth <= el.clientWidth + 1 && box.left >= 0 && box.right <= window.innerWidth;
      });
    // Write access as the worker would have left it, with a long address and a warning.
    await sql(
      `insert into secret (id, organization_id, purpose, sealed, vault_key_id)
       select 'sec_layoutwrite', id, 'forge-write-token', '{}'::jsonb, 'k' from organization limit 1`,
    );
    await sql(
      `insert into repository_write_access (repository_id, organization_id, secret_id, forge_kind, api_base_url, status, status_reason, warning)
       select 'repo_e2eseeded000000001', organization_id, 'sec_layoutwrite', 'gitea',
         'https://a-rather-long-forge-name.internal.example.lan:8443/some/sub/path/for/the/forge/api/v1', 'ok', null, 'broad-token'
       from repository where id = 'repo_e2eseeded000000001'`,
    );
    try {
      await page.goto("/repositories/repo_e2eseeded000000001");
      const card = page
        .locator("section")
        .filter({ has: page.getByRole("heading", { name: "Fix pull requests", level: 2 }) });
      await expect(card).toContainText("Turned on");
      await expect(card).toContainText("reaches more than this repository");
      expect(await hasNoHorizontalScroll(page)).toBe(true);
      expect(await overflowingCards(page)).toEqual([]);
      await page.screenshot({ path: info.outputPath("repository-write-access.png"), fullPage: true });

      await card.getByRole("button", { name: "Replace token …" }).click();
      const replace = page.getByRole("dialog", { name: "Replace the write token" });
      await expect(replace).toBeVisible();
      await page.screenshot({ path: info.outputPath("write-access-dialog.png") });
      expect(await fits(replace)).toBe(true);
      await page.keyboard.press("Escape");

      await card.getByRole("button", { name: "Renovate config" }).click();
      const renovate = page.getByRole("dialog", { name: "Renovate configuration" });
      await expect(renovate.getByRole("textbox", { name: "Renovate configuration" })).toHaveValue(
        /vulnerabilityAlerts/,
      );
      await page.screenshot({ path: info.outputPath("renovate-dialog.png") });
      expect(await fits(renovate)).toBe(true);
      await page.keyboard.press("Escape");

      await page.goto("/fixes");
      await expect(page.getByRole("heading", { name: "Fix proposals", exact: true })).toBeVisible();
      await page.waitForLoadState("networkidle");
      await page.getByRole("button", { name: "Create PR" }).first().click();
      const create = page.getByRole("dialog", { name: "Create a pull request" });
      await expect(create).toBeVisible();
      await page.screenshot({ path: info.outputPath("create-pr-dialog.png") });
      expect(await fits(create)).toBe(true);
      await page.keyboard.press("Escape");
      expect(await hasNoHorizontalScroll(page)).toBe(true);
      expect(await overflowingCards(page)).toEqual([]);

      // A token the forge rejects.
      await sql(
        "update repository_write_access set status = 'failed', status_reason = 'token-rejected', warning = null where repository_id = 'repo_e2eseeded000000001'",
      );
      await page.goto("/repositories/repo_e2eseeded000000001");
      await expect(
        page
          .locator("section")
          .filter({ has: page.getByRole("heading", { name: "Fix pull requests", level: 2 }) }),
      ).toContainText("The forge rejected the write token");
      expect(await hasNoHorizontalScroll(page)).toBe(true);
      await page.goto("/fixes");
      await expect(page.getByRole("row", { name: /pkg-2/ })).toContainText("The write token does not work");
      expect(await hasNoHorizontalScroll(page)).toBe(true);
      expect(await overflowingCards(page)).toEqual([]);
    } finally {
      await sql("delete from secret where id = 'sec_layoutwrite'");
    }
    expect(problems).toEqual([]);
  });

  test("the import dialog fits the screen", async ({ page }, info) => {
    await page.goto("/servers?import=1");
    const dialog = page.getByRole("dialog", { name: "Import servers" });
    await expect(dialog).toBeVisible();
    await page.screenshot({ path: info.outputPath("import-servers.png") });
    expect(await dialog.evaluate((el) => el.scrollWidth <= el.clientWidth + 1)).toBe(true);
  });

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
