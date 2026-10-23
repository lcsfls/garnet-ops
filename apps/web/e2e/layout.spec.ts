import { expect, type Locator, type Page, type TestInfo, test } from "@playwright/test";
import {
  contentWidth,
  hasNoHorizontalScroll,
  misalignedFormRows,
  overflowingCards,
  STATE_FILE,
  sidebarFooterOnOneLine,
  watchForProblems,
} from "./helpers.ts";
import {
  AI,
  ATTACKS,
  addUnifiEvent,
  EXPOSURE,
  FIXES,
  PROXMOX,
  resetSystemStatus,
  restoreWazuh,
  setUnifiIps,
  signedInAt,
  sql,
  UNIFI,
  WAZUH,
} from "./seed.ts";

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

test.describe("signed out, with the directory sign-in on", () => {
  test("the directory form fits without horizontal scrolling", async ({ page }, info) => {
    const problems = watchForProblems(page);
    await page.goto("/sign-in?via=directory");
    await expect(page.getByRole("button", { name: "Directory account", exact: true })).toHaveAttribute(
      "aria-pressed",
      "true",
    );
    await expect(page.getByLabel("User name")).toBeVisible();
    expect(await hasNoHorizontalScroll(page)).toBe(true);
    await expect(page.getByRole("button", { name: "Sign in with directory account" })).toBeInViewport();
    await page.screenshot({ path: info.outputPath("sign-in-directory.png") });
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
    { path: "/servers?view=unifi", heading: "Servers", name: "unifi" },
    {
      path: "/servers?view=unifi&ufFlag=update&ufSort=firmware&ufDir=desc",
      heading: "Servers",
      name: "unifi-filtered",
    },
    { path: "/servers?view=wazuh", heading: "Servers", name: "wazuh-agents" },
    { path: "/exposure", heading: "Exposure", name: "exposure" },
    {
      path: "/exposure?status=attention&sort=critical&dir=desc",
      heading: "Exposure",
      name: "exposure-filtered",
    },
    { path: `/exposure/${EXPOSURE.main.id}`, heading: EXPOSURE.main.value, name: "exposure-asset" },
    { path: `/exposure/${EXPOSURE.main.id}?tab=ports`, heading: EXPOSURE.main.value, name: "exposure-ports" },
    { path: `/exposure/${EXPOSURE.main.id}?tab=tls`, heading: EXPOSURE.main.value, name: "exposure-tls" },
    { path: `/exposure/${EXPOSURE.main.id}?tab=http`, heading: EXPOSURE.main.value, name: "exposure-http" },
    {
      path: `/exposure/${EXPOSURE.main.id}?tab=history`,
      heading: EXPOSURE.main.value,
      name: "exposure-history",
    },
    { path: `/exposure/${EXPOSURE.shop.id}`, heading: EXPOSURE.shop.value, name: "exposure-asset-shop" },
    { path: `/exposure/${EXPOSURE.lost.id}`, heading: EXPOSURE.lost.value, name: "exposure-asset-lost" },
    {
      path: `/exposure/${EXPOSURE.address.id}`,
      heading: EXPOSURE.address.value,
      name: "exposure-asset-address",
    },
    {
      path: `/exposure/${EXPOSURE.hostile.id}`,
      heading: EXPOSURE.hostile.value,
      name: "exposure-asset-hostile",
    },
    { path: "/settings?section=exposure", heading: "Settings", name: "settings-exposure" },
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
    { path: "/account?section=notifications", heading: "Account", name: "account-notifications" },
    { path: "/settings?section=updates", heading: "Settings", name: "settings-updates" },
    { path: "/settings?section=notifications", heading: "Settings", name: "settings-notifications" },
    { path: "/settings?section=proxmox", heading: "Settings", name: "settings-proxmox" },
    { path: "/settings?section=unifi", heading: "Settings", name: "settings-unifi" },
    { path: "/settings?section=xdr", heading: "Settings", name: "settings-xdr" },
    { path: "/settings?section=ai", heading: "Settings", name: "settings-ai" },
    { path: "/settings?section=signin", heading: "Settings", name: "settings-signin" },
    { path: `/findings?id=${AI.talked.findingId}&ai=1`, heading: "Findings", name: "findings-ai" },
    { path: "/settings?section=about", heading: "Settings", name: "settings-about" },
    { path: "/repositories/repo_e2eseeded000000001", heading: "seeded-app", name: "repository" },
    { path: "/audit-log", heading: "Audit log", name: "audit-log" },
    { path: "/system", heading: "System status", name: "system" },
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
      "signin",
      "notifications",
      "proxmox",
      "unifi",
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
    // 22 pages at two widths, each waited for until the network is idle: more than the default 30 s.
    test.setTimeout(150_000);
    const problems = watchForProblems(page);
    // German texts are longer; 760 px is a small window next to the wider sidebar.
    await page.addInitScript(() => localStorage.setItem("garnetops.language", "de"));
    const paths = [
      "/settings",
      "/settings?section=signin",
      "/settings?section=notifications",
      "/settings?section=proxmox",
      "/settings?section=unifi",
      "/servers?view=unifi",
      "/exposure",
      `/exposure/${EXPOSURE.main.id}`,
      `/exposure/${EXPOSURE.main.id}?tab=ports`,
      `/exposure/${EXPOSURE.shop.id}`,
      "/settings?section=exposure",
      "/settings?section=xdr",
      "/settings?section=attacks",
      "/settings?section=ai",
      "/settings?section=updates",
      "/settings?section=about",
      "/system",
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

  test("Exposure uses wide screens: more columns, figures and panes from wide on, the most from xwide on, and nothing is lost below", async ({
    page,
  }, info) => {
    const problems = watchForProblems(page);
    await page.goto("/exposure");
    await expect(page.getByRole("heading", { name: "Exposure", level: 1 })).toBeVisible();
    await page.waitForLoadState("networkidle");
    const content = await contentWidth(page);
    const table = page.getByTestId("exposure-table");
    const header = (name: string) => table.getByRole("columnheader", { name, exact: true });
    for (const name of ["Asset", "Critical", "High", "Medium"]) {
      await expect(header(name)).toBeVisible();
    }
    // Verification, stage 2 and last check from 48 rem (768 px) of content, stage 1, certificate and low from wide (1450 px), location from xwide (1900 px).
    for (const [name, from] of [
      ["Verification", 768],
      ["Stage 2", 768],
      ["Last check", 768],
      ["Stage 1", 1450],
      ["Certificate", 1450],
      ["Low", 1450],
      ["Location", 1900],
    ] as const) {
      if (content >= from) await expect(header(name)).toBeVisible();
      else await expect(header(name)).toBeHidden();
    }
    // Below wide the certificate and stage 1 move under the name instead of disappearing.
    const main = page.locator(`tr[data-asset="${EXPOSURE.main.value}"]`);
    await expect(main).toContainText("in 12 days");
    await expect(main).toContainText("Done");
    // The figures are part of the wide step; more of them from xwide.
    const figures = page.getByTestId("exposure-figures");
    if (content >= 1450) {
      await expect(figures.getByRole("link", { name: /^Assets/ })).toBeVisible();
      if (content >= 1900) await expect(figures.getByRole("link", { name: /^Critical open/ })).toBeVisible();
      else await expect(figures.getByRole("link", { name: /^Critical open/ })).toBeHidden();
    } else {
      await expect(figures).toBeHidden();
    }
    expect(await hasNoHorizontalScroll(page)).toBe(true);
    expect(await overflowingCards(page)).toEqual([]);
    await page.screenshot({ path: info.outputPath("exposure-columns.png"), fullPage: true });

    // One asset: tabs below wide; from wide the findings have a pane of their own; from xwide everything is side by side.
    await page.goto(`/exposure/${EXPOSURE.main.id}`);
    await expect(page.getByRole("heading", { name: EXPOSURE.main.value, level: 1 })).toBeVisible();
    await page.waitForLoadState("networkidle");
    const tabs = page.getByRole("group", { name: "Sections" });
    const findings = page.getByTestId("exposure-findings");
    const dnsCard = page
      .locator("section")
      .filter({ has: page.getByRole("heading", { name: "DNS", exact: true }) });
    const portsCard = page
      .locator("section")
      .filter({ has: page.getByRole("heading", { name: "Ports", exact: true }) });
    if (content >= 1900) {
      await expect(tabs).toBeHidden();
      await expect(findings).toBeVisible();
      await expect(dnsCard).toBeVisible();
      await expect(portsCard).toBeVisible();
      const [a, b, c] = await Promise.all([
        findings.locator("xpath=ancestor::section[1]").boundingBox(),
        dnsCard.boundingBox(),
        portsCard.boundingBox(),
      ]);
      // Three columns: the cards start at the same height and sit side by side.
      expect(Math.abs((a?.y ?? 0) - (b?.y ?? 99999))).toBeLessThan(8);
      expect((b?.x ?? 0) > (a?.x ?? 0) + 200).toBe(true);
      expect((c?.x ?? 0) > (b?.x ?? 0) + 200).toBe(true);
    } else if (content >= 1450) {
      await expect(tabs).toBeVisible();
      await expect(tabs.getByRole("button", { name: "Findings" })).toBeHidden();
      await expect(findings).toBeVisible();
      await expect(dnsCard).toBeVisible();
      const [a, b] = await Promise.all([findings.boundingBox(), dnsCard.boundingBox()]);
      expect((b?.x ?? 0) > (a?.x ?? 0) + 200).toBe(true);
    } else {
      await expect(tabs.getByRole("button", { name: "Findings" })).toBeVisible();
      await expect(findings).toBeVisible();
      await expect(dnsCard).toBeHidden();
      await tabs.getByRole("button", { name: "Ports" }).click();
      await expect(page.getByTestId("exposure-ports")).toBeVisible();
      await expect(findings).toBeHidden();
    }
    expect(await hasNoHorizontalScroll(page)).toBe(true);
    expect(await overflowingCards(page)).toEqual([]);
    await page.screenshot({ path: info.outputPath("exposure-asset-panes.png"), fullPage: true });
    expect(problems).toEqual([]);
  });

  test("System status uses the width: one column of reading width, two from wide, three from xwide, in English and German", async ({
    page,
  }, info) => {
    // Two languages with a full page each, waited for until the network is idle.
    test.setTimeout(90_000);
    const problems = watchForProblems(page);
    await resetSystemStatus();
    // Busy queues, one with a long wait, so the queue table has its widest content (badges in the figures).
    await sql(
      `insert into pgboss.job (name, start_after, data) values
         ('scan.repository', now() - interval '30 minutes', '{"e2e":"system-status"}'), ('scan.repository', now(), '{"e2e":"system-status"}'), ('host.keyscan', now() - interval '2 minutes', '{"e2e":"system-status"}')`,
    );
    try {
      await checkSystemStatusLayout(page, info);
    } finally {
      await sql("delete from pgboss.job where data->>'e2e' = 'system-status'");
    }
    expect(problems).toEqual([]);
  });

  test("System status stays inside a small window, in English and German, with busy queues", async ({
    page,
  }) => {
    test.setTimeout(90_000);
    const problems = watchForProblems(page);
    await resetSystemStatus();
    await sql(
      `insert into pgboss.job (name, start_after, data) values ('scan.repository', now() - interval '30 minutes', '{"e2e":"system-status"}'), ('host.keyscan', now(), '{"e2e":"system-status"}')`,
    );
    try {
      const height = page.viewportSize()?.height ?? 800;
      for (const language of ["en", "de"]) {
        await page.addInitScript((l) => localStorage.setItem("garnetops.language", l), language);
        for (const width of [760, 900]) {
          await page.setViewportSize({ width, height });
          await page.goto("/system");
          await expect(page.locator("html")).toHaveAttribute("lang", language);
          await expect(page.getByTestId("worker-queues")).toBeVisible();
          await page.getByTestId("worker-idle-queues").locator("summary").click();
          await page.waitForLoadState("networkidle");
          expect(await hasNoHorizontalScroll(page), `${language} ${width}`).toBe(true);
          expect(await overflowingCards(page), `${language} ${width}`).toEqual([]);
        }
      }
    } finally {
      await sql("delete from pgboss.job where data->>'e2e' = 'system-status'");
    }
    expect(problems).toEqual([]);
  });

  async function checkSystemStatusLayout(page: Page, info: TestInfo) {
    for (const language of ["en", "de"]) {
      await page.addInitScript((l) => localStorage.setItem("garnetops.language", l), language);
      await page.goto("/system");
      await expect(page.locator("html")).toHaveAttribute("lang", language);
      await expect(page.getByTestId("system-vulndb")).toBeVisible();
      await page.waitForLoadState("networkidle");
      // The idle queues are behind a click; open them, so the longest table is measured too.
      await page.getByTestId("worker-idle-queues").locator("summary").click();
      const content = await contentWidth(page);
      const boxes = await page.evaluate(() =>
        Array.from(document.querySelectorAll("[data-testid^='system-'][class*='break-inside-avoid']")).map(
          (cell) => {
            const b = cell.getBoundingClientRect();
            return {
              id: cell.getAttribute("data-testid"),
              left: Math.round(b.left),
              width: Math.round(b.width),
            };
          },
        ),
      );
      expect(
        boxes.map((b) => b.id),
        language,
      ).toEqual([
        "system-vulndb",
        "system-scanners",
        "system-local-build",
        "system-geoip",
        "system-integrations",
        "system-worker",
        "system-app",
      ]);
      const columns = new Set(boxes.map((b) => b.left)).size;
      const expected = content >= 1900 ? 3 : content >= 1450 ? 2 : 1;
      expect(columns, `${language}: columns at a content width of ${content}`).toBe(expected);
      if (content < 1450) {
        // Reading width on the base step: one column, not wider than 72 rem.
        expect(Math.max(...boxes.map((b) => b.width))).toBeLessThanOrEqual(72 * 16 + 1);
      }
      expect(await hasNoHorizontalScroll(page), language).toBe(true);
      expect(await overflowingCards(page), language).toEqual([]);
      // Every card is whole: its bottom is below its top and nothing is cut at the right.
      const cut = await page.evaluate(() =>
        Array.from(
          document.querySelectorAll(
            "[data-testid^='system-'] section, [data-testid^='system-'] td, [data-testid^='system-'] li",
          ),
        )
          .filter((el) => (el as HTMLElement).scrollWidth > (el as HTMLElement).clientWidth + 1)
          .map((el) => (el.textContent ?? "").trim().slice(0, 50)),
      );
      expect(cut, language).toEqual([]);
      // The content area scrolls on its own, so a tall window shows the whole page in the picture.
      const size = page.viewportSize() ?? { width: 1280, height: 720 };
      await page.setViewportSize({ width: size.width, height: 3200 });
      await page.screenshot({ path: info.outputPath(`system-${language}.png`) });
      await page.setViewportSize(size);
    }
  }

  test("the Exposure dialogs fit the screen, in English and German: add, verify, stage 2 and Certificate Transparency", async ({
    page,
  }, info) => {
    const problems = watchForProblems(page);
    const fits = (dialog: Locator) =>
      dialog.evaluate((el) => {
        const box = el.getBoundingClientRect();
        return (
          el.scrollWidth <= el.clientWidth + 1 &&
          box.left >= 0 &&
          box.right <= window.innerWidth &&
          box.top >= 0 &&
          box.bottom <= window.innerHeight + 1
        );
      });
    const shown = async (name: string | RegExp, shot: string) => {
      const dialog = page.getByRole("dialog", { name });
      await expect(dialog).toBeVisible();
      expect(await fits(dialog), shot).toBe(true);
      expect(await hasNoHorizontalScroll(page), shot).toBe(true);
      await page.screenshot({ path: info.outputPath(`${shot}.png`) });
    };
    await page.goto("/exposure?add=1");
    await shown("Add an asset", "exposure-add");
    await page.goto(`/exposure/${EXPOSURE.shop.id}?verify=1`);
    await shown(`Verify ${EXPOSURE.shop.value}`, "exposure-verify");
    await page.goto(`/exposure/${EXPOSURE.shop.id}?stage2=1`);
    await shown(/^Switch on stage 2 for /, "exposure-stage2-warning");
    await page.getByRole("dialog").getByText("The ports", { exact: true }).click();
    await shown(/^Switch on stage 2 for /, "exposure-stage2-ports");
    await page.goto(`/exposure/${EXPOSURE.main.id}?stage2=1`);
    await shown(/^Stage 2 for /, "exposure-stage2-on");
    await page.goto("/settings?section=exposure");
    await page.getByTestId("ct-section").getByRole("button", { name: "Switch on" }).click();
    await shown(/^Send domain names to /, "exposure-ct");

    // German texts are longer.
    await page.addInitScript(() => localStorage.setItem("garnetops.language", "de"));
    await page.goto("/exposure?add=1");
    await expect(page.locator("html")).toHaveAttribute("lang", "de");
    await shown("Asset hinzufügen", "exposure-add-de");
    await page.goto(`/exposure/${EXPOSURE.shop.id}?verify=1`);
    await shown(`${EXPOSURE.shop.value} verifizieren`, "exposure-verify-de");
    await page.goto(`/exposure/${EXPOSURE.shop.id}?stage2=1`);
    await shown(/^Stufe 2 für .* einschalten$/, "exposure-stage2-warning-de");
    await page.getByRole("dialog").getByText("Die Ports", { exact: true }).click();
    await shown(/^Stufe 2 für .* einschalten$/, "exposure-stage2-ports-de");
    await page.goto("/settings?section=exposure");
    await page.getByTestId("ct-section").getByRole("button", { name: "Einschalten" }).click();
    await shown(/^Domainnamen an .* senden\?$/, "exposure-ct-de");
    for (const path of [
      "/exposure",
      `/exposure/${EXPOSURE.main.id}`,
      `/exposure/${EXPOSURE.main.id}?tab=ports`,
    ]) {
      await page.goto(path);
      await page.waitForLoadState("networkidle");
      expect(await hasNoHorizontalScroll(page), path).toBe(true);
      expect(await overflowingCards(page), path).toEqual([]);
    }
    expect(problems).toEqual([]);
  });

  test("grades: the column, the help and the open note fit at every width, in English and German", async ({
    page,
  }, info) => {
    const problems = watchForProblems(page);
    const inside = (box: { x: number; width: number } | null) => {
      const width = page.viewportSize()?.width ?? 0;
      return box !== null && box.x >= 0 && box.x + box.width <= width;
    };
    for (const { path, name } of [
      { path: "/repositories", name: "repositories" },
      { path: "/servers", name: "servers" },
    ]) {
      await page.goto(path);
      await expect(page.getByRole("columnheader", { name: /Grade/ })).toBeVisible();
      await page.waitForLoadState("networkidle");
      await page.getByText("How grades work").click();
      await expect(page.getByText("The grade is display only")).toBeVisible();
      expect(await hasNoHorizontalScroll(page), `${name} with the help open`).toBe(true);
      expect(await overflowingCards(page), `${name} with the help open`).toEqual([]);
      await page.getByText("How grades work").click();

      // The F badge of the first graded row, with its note open.
      const badge = page.getByRole("link", { name: /^F: / }).first();
      await badge.hover();
      const tip = page.getByRole("tooltip");
      await expect(tip).toBeVisible();
      expect(inside(await tip.boundingBox()), `${name}: the note is inside the window`).toBe(true);
      expect(await hasNoHorizontalScroll(page), `${name} with the note open`).toBe(true);
      await page.screenshot({ path: info.outputPath(`grades-${name}.png`), fullPage: true });
      await page.mouse.move(0, 0);
    }

    // German texts are longer; 1100 px is the smallest window the lists are made for.
    await page.addInitScript(() => localStorage.setItem("garnetops.language", "de"));
    const height = page.viewportSize()?.height ?? 800;
    for (const width of [1100, 1280]) {
      await page.setViewportSize({ width, height });
      for (const path of ["/repositories", "/servers", "/repositories/repo_e2eseeded000000001"]) {
        await page.goto(path);
        await expect(page.locator("html")).toHaveAttribute("lang", "de");
        await expect(page.getByRole("heading", { level: 1 })).toBeVisible();
        await page.waitForLoadState("networkidle");
        expect(await hasNoHorizontalScroll(page), `${width} ${path}`).toBe(true);
        expect(await overflowingCards(page), `${width} ${path}`).toEqual([]);
      }
    }
    expect(problems).toEqual([]);
  });

  test("the directory settings with a test result, and the link dialog, fit the screen", async ({
    page,
  }, info) => {
    const problems = watchForProblems(page);
    const fits = (dialog: Locator) =>
      dialog.evaluate((el) => {
        const box = el.getBoundingClientRect();
        return el.scrollWidth <= el.clientWidth + 1 && box.left >= 0 && box.right <= window.innerWidth;
      });
    await page.goto("/settings?section=signin");
    await expect(page.getByRole("heading", { name: "Directory sign-in", level: 2 })).toBeVisible();
    // A test result adds a long distinguished name, groups and the servers to the page.
    await page.locator("#directory-test-user").fill("jdoe");
    await page.getByTestId("directory-test").click();
    await expect(page.getByTestId("directory-test-result").getByText("Works", { exact: true })).toBeVisible();
    await page.waitForLoadState("networkidle");
    expect(await hasNoHorizontalScroll(page)).toBe(true);
    expect(await overflowingCards(page)).toEqual([]);
    expect(await misalignedFormRows(page)).toEqual([]);
    await page.screenshot({ path: info.outputPath("settings-signin-result.png"), fullPage: true });

    // The link dialog with a person whose address differs shows the warnings.
    await page.goto("/team");
    await expect(page.getByRole("heading", { name: "Team", level: 1 })).toBeVisible();
    const row = page.getByRole("table").getByRole("row").filter({ hasText: "account.tester@e2e.test" });
    await row.getByRole("button", { name: /^Link .* to the directory$/ }).click();
    const dialog = page.getByRole("dialog", { name: /^Link .* to the directory$/ });
    await dialog.getByLabel("Directory user name").fill("bwilson");
    await dialog.getByRole("button", { name: "Look up" }).click();
    await expect(dialog.getByTestId("link-result")).toContainText("Different address");
    await page.screenshot({ path: info.outputPath("team-link-dialog.png") });
    expect(await fits(dialog)).toBe(true);
    expect(await hasNoHorizontalScroll(page)).toBe(true);
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
    // Adding a server needs a sign-in from the last ten minutes, and the later viewports run well after the first one.
    await signedInAt("now");
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
      await expect(page.getByTestId("attack-globe").locator("svg[role='img']")).toBeVisible();
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
      // The globe, the latest events and the lists: stacked below wide; from wide the globe is left and the events and
      // the countries are right of it; from xwide the globe, the events and the lists are three across.
      const box = async (name: string) =>
        page
          .locator("section")
          .filter({ has: page.getByRole("heading", { name, exact: true }) })
          .boundingBox();
      const [map, events, countries, networks] = await Promise.all([
        box("Origin of the alerts"),
        box("Latest events"),
        box("Countries"),
        box("Networks"),
      ]);
      expect(map && events && countries && networks).toBeTruthy();
      const at = (b: { x: number; y: number } | null, axis: "x" | "y") => b?.[axis] ?? Number.NaN;
      if (content >= 1900) {
        expect(Math.abs(at(map, "y") - at(events, "y"))).toBeLessThan(40);
        expect(Math.abs(at(events, "y") - at(countries, "y"))).toBeLessThan(40);
        expect(at(events, "x")).toBeGreaterThan(at(map, "x") + 100);
        expect(at(countries, "x")).toBeGreaterThan(at(events, "x") + 100);
        expect(Math.abs(at(networks, "x") - at(countries, "x"))).toBeLessThan(40);
        expect(at(networks, "y")).toBeGreaterThan(at(countries, "y") + 40);
      } else if (content >= 1450) {
        expect(Math.abs(at(map, "y") - at(events, "y"))).toBeLessThan(40);
        expect(at(events, "x")).toBeGreaterThan(at(map, "x") + 100);
        expect(Math.abs(at(countries, "x") - at(events, "x"))).toBeLessThan(40);
        expect(at(countries, "y")).toBeGreaterThan(at(events, "y") + 40);
        expect(at(networks, "y")).toBeGreaterThan(at(map, "y") + 100);
      } else {
        // One column, in reading order: the globe first, then the events, the countries and the networks.
        expect(at(events, "y")).toBeGreaterThan(at(map, "y") + 100);
        expect(at(countries, "y")).toBeGreaterThan(at(events, "y") + 40);
        expect(at(networks, "y")).toBeGreaterThan(at(countries, "y") + 40);
        expect(Math.abs(at(events, "x") - at(map, "x"))).toBeLessThan(5);
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

  for (const language of ["en", "de"] as const) {
    test(`Network devices: the cards, the table and the preview dialog fit at every width (${language})`, async ({
      page,
    }, info) => {
      const problems = watchForProblems(page);
      await page.addInitScript((lang) => localStorage.setItem("garnetops.language", lang), language);
      await page.goto("/servers?view=unifi");
      await expect(page.locator("html")).toHaveAttribute("lang", language);
      const table = page.getByTestId("uf-devices");
      await expect(table.locator("tbody tr")).toHaveCount(UNIFI.total);
      await page.waitForLoadState("networkidle");
      const content = await contentWidth(page);
      expect(await hasNoHorizontalScroll(page)).toBe(true);
      expect(await overflowingCards(page)).toEqual([]);
      // Information never disappears: below wide, site and address move under the name; wide adds columns; xwide more.
      const visible = async (n: number) => table.locator("thead th").nth(n).isVisible();
      expect(await visible(0)).toBe(true); // device
      expect(await visible(3)).toBe(true); // status
      expect(await visible(4)).toBe(true); // firmware
      expect(await visible(1)).toBe(content >= 1450); // site
      expect(await visible(2)).toBe(content >= 1450); // address
      expect(await visible(5)).toBe(content >= 1900); // uptime
      const rowsFit = await page.evaluate(() => {
        const t = document.querySelector("[data-testid='uf-devices']");
        if (!t) return false;
        return Array.from(t.querySelectorAll("tbody td")).every((td) => td.scrollWidth <= td.clientWidth + 1);
      });
      expect(rowsFit).toBe(true);
      await expect(
        page
          .locator("section")
          .filter({ has: page.getByRole("heading", { name: UNIFI.main.name, exact: true }) }),
      ).toBeVisible();
      await page.screenshot({ path: info.outputPath(`unifi-${language}.png`), fullPage: true });

      // The preview dialog fits the window.
      await page.goto("/settings?section=unifi");
      await page.waitForLoadState("networkidle");
      await page
        .getByRole("listitem")
        .filter({ hasText: UNIFI.main.name })
        .first()
        .getByTestId("uf-ips")
        .getByRole("button")
        .first()
        .click();
      const dialog = page.getByRole("dialog");
      await expect(dialog).toBeVisible();
      const box = await dialog.boundingBox();
      const viewport = page.viewportSize() ?? { width: 0, height: 0 };
      expect(box && box.x >= 0 && box.x + box.width <= viewport.width).toBe(true);
      expect(await hasNoHorizontalScroll(page)).toBe(true);
      await page.screenshot({ path: info.outputPath(`unifi-ips-dialog-${language}.png`) });
      expect(problems).toEqual([]);
    });

    test(`Rights beyond viewing: the warning, the list and the dialog fit at every width (${language})`, async ({
      page,
    }, info) => {
      const problems = watchForProblems(page);
      await page.addInitScript((lang) => localStorage.setItem("garnetops.language", lang), language);
      await sql("update unifi_connection set ips_rights = $2::jsonb where id = $1", [
        UNIFI.main.id,
        JSON.stringify(["role: Super Admin", "super_admin", `role: ${"Long role name ".repeat(3).trim()}`]),
      ]);
      try {
        await page.goto("/settings?section=unifi");
        await expect(page.locator("html")).toHaveAttribute("lang", language);
        const ips = page
          .getByRole("listitem")
          .filter({ hasText: UNIFI.main.name })
          .first()
          .getByTestId("uf-ips");
        await expect(ips.getByTestId("uf-rights-blocked")).toBeVisible();
        await page.waitForLoadState("networkidle");
        expect(await hasNoHorizontalScroll(page)).toBe(true);
        expect(await overflowingCards(page)).toEqual([]);
        await page.screenshot({ path: info.outputPath(`unifi-rights-${language}.png`), fullPage: true });
        await ips
          .getByRole("button", { name: language === "en" ? "Review rights" : "Rechte prüfen" })
          .click();
        const dialog = page.getByRole("dialog");
        await expect(dialog.getByTestId("uf-rights-list").getByRole("listitem")).toHaveCount(3);
        const box = await dialog.boundingBox();
        const viewport = page.viewportSize() ?? { width: 0, height: 0 };
        expect(
          box && box.x >= 0 && box.x + box.width <= viewport.width && box.y + box.height <= viewport.height,
        ).toBe(true);
        expect(await hasNoHorizontalScroll(page)).toBe(true);
        await page.screenshot({ path: info.outputPath(`unifi-rights-dialog-${language}.png`) });
        expect(problems).toEqual([]);
      } finally {
        await sql("update unifi_connection set ips_rights = '[]' where id = $1", [UNIFI.main.id]);
      }
    });

    test(`Attacks with UniFi events: the legend, the blocked lines and the list fit at every width (${language})`, async ({
      page,
    }, info) => {
      const problems = watchForProblems(page);
      await page.addInitScript((lang) => localStorage.setItem("garnetops.language", lang), language);
      const [org] = await sql<{ id: string }>("select id from organization limit 1");
      await sql(
        "insert into attack_settings (organization_id, home_country, home_lat, home_lon) values ($1, 'DE', 50.94, 6.96) on conflict (organization_id) do update set home_country = 'DE', home_lat = 50.94, home_lon = 6.96",
        [org?.id],
      );
      await setUnifiIps(true);
      try {
        await addUnifiEvent({
          ip: ATTACKS.ips.fr,
          signature:
            "ET SCAN Example SSH brute force with a rather long signature text that has to be cut by the layout",
          agoMinutes: 2,
        });
        await addUnifiEvent({
          ip: ATTACKS.ips.de,
          signature: "ET WEB Example probe",
          action: "alerted",
          destPort: 8443,
        });
        await page.goto("/attacks");
        await expect(page.locator("html")).toHaveAttribute("lang", language);
        const globe = page.getByTestId("attack-globe");
        const svg = globe.locator("svg[role='img']");
        await expect(svg).toBeVisible();
        await expect(svg.locator('[data-arc="FR:blocked"] path')).toHaveAttribute("d", /^M/, {
          timeout: 4000,
        });
        await expect(page.getByTestId("attack-events").getByTestId("attack-event").first()).toBeVisible();
        await expect(page.getByTestId("unifi-status")).toBeVisible();
        await page.waitForLoadState("networkidle");
        expect(await hasNoHorizontalScroll(page)).toBe(true);
        expect(await overflowingCards(page)).toEqual([]);
        // The legend names the blocked lines and stays inside the window.
        const blocked = globe.getByTestId("legend-blocked");
        await expect(blocked).toContainText(language === "en" ? "Blocked by UniFi" : "Von UniFi blockiert");
        const legend = await blocked.boundingBox();
        expect(legend).toBeTruthy();
        if (legend) {
          expect(legend.x).toBeGreaterThanOrEqual(0);
          expect(legend.x + legend.width).toBeLessThanOrEqual(page.viewportSize()?.width ?? 0);
        }
        const rowsFit = await page.evaluate(() => {
          const list = document.querySelector("[data-testid='attack-events']");
          if (!list) return false;
          return Array.from(list.querySelectorAll("li")).every((li) => li.scrollWidth <= li.clientWidth + 1);
        });
        expect(rowsFit).toBe(true);
        await page.screenshot({ path: info.outputPath(`attacks-unifi-${language}.png`), fullPage: true });
      } finally {
        await setUnifiIps(false);
        await sql("delete from attack_settings");
      }
      expect(problems).toEqual([]);
    });
  }

  for (const language of ["en", "de"] as const) {
    test(`Attacks: the globe, the latest events and the lists fit at every width (${language})`, async ({
      page,
    }, info) => {
      const problems = watchForProblems(page);
      await page.addInitScript((lang) => localStorage.setItem("garnetops.language", lang), language);
      // A home location, so the lines are part of the picture.
      const [org] = await sql<{ id: string }>("select id from organization limit 1");
      await sql(
        "insert into attack_settings (organization_id, home_country, home_lat, home_lon) values ($1, 'DE', 50.94, 6.96) on conflict (organization_id) do update set home_country = 'DE', home_lat = 50.94, home_lon = 6.96",
        [org?.id],
      );
      try {
        await page.goto("/attacks");
        await expect(page.locator("html")).toHaveAttribute("lang", language);
        const globe = page.getByTestId("attack-globe");
        const svg = globe.locator("svg[role='img']");
        await expect(svg).toBeVisible();
        await expect(svg.locator('[data-arc="DE"] path')).toHaveAttribute("d", /^M/, { timeout: 4000 });
        await expect(page.getByTestId("attack-events").getByTestId("attack-event").first()).toBeVisible();
        await page.waitForLoadState("networkidle");
        const content = await contentWidth(page);
        const viewport = page.viewportSize() ?? { width: 0, height: 0 };

        // The picture is square, stays inside its card and the window, and is large enough to read.
        const picture = await svg.boundingBox();
        const card = await page
          .locator("section")
          .filter({
            has: page.getByRole("heading", {
              name: language === "en" ? "Origin of the alerts" : "Herkunft der Alarme",
              exact: true,
            }),
          })
          .boundingBox();
        expect(picture && card).toBeTruthy();
        if (picture && card) {
          expect(Math.abs(picture.width - picture.height)).toBeLessThanOrEqual(1);
          expect(picture.width).toBeGreaterThanOrEqual(240);
          expect(picture.x).toBeGreaterThanOrEqual(card.x - 1);
          expect(picture.x + picture.width).toBeLessThanOrEqual(card.x + card.width + 1);
          expect(picture.x + picture.width).toBeLessThanOrEqual(viewport.width);
          // From wide the globe shares the first screen with the events: at least a third of it is above the fold.
          if (content >= 1450) expect(picture.y + picture.height / 3).toBeLessThan(viewport.height);
        }
        // The legend, the hint and the rotation button are inside the card, not cut off.
        await expect(
          globe.getByRole("button", { name: language === "en" ? "Pause rotation" : "Drehung anhalten" }),
        ).toBeVisible();
        await expect(
          globe.getByRole("listitem").filter({ hasText: language === "en" ? "Your network" : "Ihr Netz" }),
        ).toBeVisible();
        // The events: every row inside its card, no text running out of it.
        expect(await hasNoHorizontalScroll(page)).toBe(true);
        expect(await overflowingCards(page)).toEqual([]);
        const rowsFit = await page.evaluate(() => {
          const list = document.querySelector("[data-testid='attack-events']");
          if (!list) return false;
          return Array.from(list.querySelectorAll("li")).every((li) => li.scrollWidth <= li.clientWidth + 1);
        });
        expect(rowsFit).toBe(true);
        await page.screenshot({ path: info.outputPath(`attacks-globe-${language}.png`), fullPage: true });
      } finally {
        await sql("delete from attack_settings");
      }
      expect(problems).toEqual([]);
    });

    test(`XDR latest alerts and the Attacks settings fit at every width (${language})`, async ({
      page,
    }, info) => {
      const problems = watchForProblems(page);
      await page.addInitScript((lang) => localStorage.setItem("garnetops.language", lang), language);
      await page.goto("/xdr");
      await expect(page.locator("html")).toHaveAttribute("lang", language);
      const card = page.getByTestId("xdr-latest-alerts");
      await expect(card).toBeVisible();
      await page.waitForLoadState("networkidle");
      expect(await hasNoHorizontalScroll(page)).toBe(true);
      expect(await overflowingCards(page)).toEqual([]);
      const content = await contentWidth(page);
      // The address column appears from 36 rem of the card, the agent column from 48 rem; nothing is lost below.
      await expect(page.getByTestId("xdr-latest-alert").first()).toContainText(ATTACKS.ips.internal);
      if (content >= 1450) await expect(card.locator("th").nth(2)).toBeVisible();
      await page.screenshot({ path: info.outputPath(`xdr-latest-${language}.png`), fullPage: true });

      await page.goto("/settings?section=attacks");
      await expect(
        page.getByRole("heading", { name: language === "en" ? "Home location" : "Heimatstandort", level: 2 }),
      ).toBeVisible();
      await expect(
        page.getByRole("heading", { name: language === "en" ? "Live feed" : "Live-Feed", level: 2 }),
      ).toBeVisible();
      await page.waitForLoadState("networkidle");
      expect(await hasNoHorizontalScroll(page)).toBe(true);
      expect(await overflowingCards(page)).toEqual([]);
      expect(await misalignedFormRows(page)).toEqual([]);
      await page.screenshot({
        path: info.outputPath(`settings-attacks-live-${language}.png`),
        fullPage: true,
      });
      expect(problems).toEqual([]);
    });
  }

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

  test("the notification panel, a message and the matrix fit the window at every width, in English and German", async ({
    page,
  }, info) => {
    const problems = watchForProblems(page);
    const [owner] = await sql<{ id: string; organization_id: string }>(
      `select u."id", m."organization_id" from "user" u join membership m on m.user_id = u.id where m.role = 'owner' limit 1`,
    );
    const insert = async (repository: string, minutes: number) => {
      const [row] = await sql<{ id: string }>(
        `insert into user_notification (user_id, organization_id, event, title_key, params, link, created_at)
         values ($1, $2, 'gate.blocked', 'gateBlocked', $3::jsonb, '/gates', now() - ($4 || ' minutes')::interval)
         returning id`,
        [owner?.id, owner?.organization_id, JSON.stringify({ repository, rules: 1 }), String(minutes)],
      );
      return row?.id;
    };
    try {
      await sql("delete from user_notification");
      // A long name must wrap inside the panel, not widen it.
      const longName = `very-long-repository-name-${"x".repeat(60)}`;
      for (let i = 8; i > 0; i--) await insert(i === 4 ? longName : `repo-${i}`, i * 90);
      for (const language of ["en", "de"]) {
        await page.addInitScript((lang) => localStorage.setItem("garnetops.language", lang), language);
        await page.goto("/");
        const bell = page.getByRole("button", { name: /^(Notifications|Benachrichtigungen)/ });
        await expect(bell).toBeInViewport();
        await bell.click();
        const panel = page.getByRole("region", { name: /^(Your notifications|Ihre Benachrichtigungen)$/ });
        await expect(panel.locator("li").first()).toBeVisible();
        const view = page.viewportSize() ?? { width: 0, height: 0 };
        const box = await panel.boundingBox();
        expect(box, "panel is shown").not.toBeNull();
        if (box) {
          expect(box.x, `${language}: panel inside on the left`).toBeGreaterThanOrEqual(0);
          expect(box.x + box.width, `${language}: panel inside on the right`).toBeLessThanOrEqual(view.width);
          expect(box.y + box.height, `${language}: panel inside at the bottom`).toBeLessThanOrEqual(
            view.height,
          );
        }
        expect(await panel.evaluate((el) => el.scrollWidth <= el.clientWidth + 1)).toBe(true);
        expect(await hasNoHorizontalScroll(page)).toBe(true);
        // The bell stays left of the account menu, at the same height.
        const bellBox = await bell.boundingBox();
        const menuBox = await page.getByRole("button", { name: /^(Account|Konto): / }).boundingBox();
        expect(bellBox && menuBox && bellBox.x + bellBox.width <= menuBox.x).toBe(true);
        await page.screenshot({ path: info.outputPath(`notification-panel-${language}.png`) });
        await page.keyboard.press("Escape");

        // A message arrives while the panel is closed: bottom right, inside the window.
        const id = await insert(`fresh-${language}`, 0);
        await sql("select pg_notify('user_notification', $1)", [
          JSON.stringify({ u: owner?.id, id: Number(id) }),
        ]);
        const message = page.locator("[data-toast]").first();
        await expect(message).toBeVisible({ timeout: 8000 });
        const toastBox = await message.boundingBox();
        if (toastBox) {
          expect(toastBox.x + toastBox.width).toBeLessThanOrEqual(view.width);
          expect(toastBox.y + toastBox.height).toBeLessThanOrEqual(view.height);
          expect(toastBox.x).toBeGreaterThanOrEqual(0);
        }
        await page.screenshot({ path: info.outputPath(`notification-toast-${language}.png`) });
        await sql("delete from user_notification where params->>'repository' like 'fresh-%'");
      }
    } finally {
      await sql("delete from user_notification");
    }
    expect(problems).toEqual([]);
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
