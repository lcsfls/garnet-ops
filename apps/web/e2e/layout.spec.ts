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
import { AI, EXPOSURE, FIXES, resetSystemStatus, sql } from "./seed.ts";

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
    { path: "/settings?section=ai", heading: "Settings", name: "settings-ai" },
    { path: "/settings?section=signin", heading: "Settings", name: "settings-signin" },
    { path: `/findings?id=${AI.talked.findingId}&ai=1`, heading: "Findings", name: "findings-ai" },
    { path: "/settings?section=about", heading: "Settings", name: "settings-about" },
    { path: "/repositories/repo_e2eseeded000000001", heading: "seeded-app", name: "repository" },
    { path: "/audit-log", heading: "Audit log", name: "audit-log" },
    { path: "/system", heading: "System status", name: "system" },
    { path: "/statistics", heading: "Statistics", name: "statistics" },
    { path: "/statistics?days=365", heading: "Statistics", name: "statistics-365" },
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
    for (const section of ["scanning", "signin", "notifications", "ai", "updates", "about"]) {
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
    // 14 pages at two widths, each waited for until the network is idle: more than the default 30 s.
    test.setTimeout(150_000);
    const problems = watchForProblems(page);
    // German texts are longer; 760 px is a small window next to the wider sidebar.
    await page.addInitScript(() => localStorage.setItem("garnetops.language", "de"));
    const paths = [
      "/settings",
      "/settings?section=signin",
      "/settings?section=notifications",
      "/settings?section=ai",
      "/settings?section=updates",
      "/settings?section=about",
      "/system",
      "/statistics",
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
         ('scan.repository', now() - interval '30 minutes', '{"e2e":"system-status"}'), ('scan.repository', now(), '{"e2e":"system-status"}'), ('notify.deliver', now() - interval '2 minutes', '{"e2e":"system-status"}')`,
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
      `insert into pgboss.job (name, start_after, data) values ('scan.repository', now() - interval '30 minutes', '{"e2e":"system-status"}'), ('notify.deliver', now(), '{"e2e":"system-status"}')`,
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

  test("grades: the column, the help and the open note fit at every width, in English and German", async ({
    page,
  }, info) => {
    const problems = watchForProblems(page);
    const inside = (box: { x: number; width: number } | null) => {
      const width = page.viewportSize()?.width ?? 0;
      return box !== null && box.x >= 0 && box.x + box.width <= width;
    };
    for (const { path, name } of [{ path: "/repositories", name: "repositories" }]) {
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
      for (const path of ["/repositories", "/repositories/repo_e2eseeded000000001"]) {
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

/** Website monitoring (ADR 0023, 0033): the module is on for these screens only. */
test.describe("signed in, with website monitoring on", () => {
  test.use({ storageState: STATE_FILE });
  test.beforeAll(async () => {
    await sql(`insert into exposure_settings (organization_id, enabled)
               select id, true from organization
               on conflict (organization_id) do update set enabled = true`);
  });
  test.afterAll(async () => {
    await sql("update exposure_settings set enabled = false");
  });

  for (const { path, heading, name } of [
    { path: "/websites", heading: "Websites", name: "websites" },
    {
      path: "/websites?status=attention&sort=critical&dir=desc",
      heading: "Websites",
      name: "websites-filtered",
    },
    { path: `/websites/${EXPOSURE.main.id}`, heading: EXPOSURE.main.value, name: "website" },
    { path: `/websites/${EXPOSURE.main.id}?tab=ports`, heading: EXPOSURE.main.value, name: "website-ports" },
    { path: `/websites/${EXPOSURE.main.id}?tab=tls`, heading: EXPOSURE.main.value, name: "website-tls" },
    {
      path: `/websites/${EXPOSURE.main.id}?tab=availability`,
      heading: EXPOSURE.main.value,
      name: "website-availability",
    },
    { path: `/websites/${EXPOSURE.main.id}?tab=http`, heading: EXPOSURE.main.value, name: "website-http" },
    {
      path: `/websites/${EXPOSURE.main.id}?tab=history`,
      heading: EXPOSURE.main.value,
      name: "website-history",
    },
    { path: `/websites/${EXPOSURE.main.id}?verify=1`, heading: EXPOSURE.main.value, name: "website-verify" },
    { path: `/websites/${EXPOSURE.main.id}?stage2=1`, heading: EXPOSURE.main.value, name: "website-stage2" },
    { path: "/settings?section=modules", heading: "Settings", name: "settings-modules" },
  ]) {
    test(`${name} fits without horizontal scrolling`, async ({ page }, info) => {
      const problems = watchForProblems(page);
      await page.goto(path);
      await expect(page.getByRole("heading", { name: heading, exact: true, level: 1 })).toBeVisible();
      await page.waitForLoadState("networkidle");
      expect(await hasNoHorizontalScroll(page)).toBe(true);
      expect(await overflowingCards(page)).toEqual([]);
      expect(await misalignedFormRows(page)).toEqual([]);
      await page.screenshot({ path: info.outputPath(`${name}.png`), fullPage: true });
      expect(problems).toEqual([]);
    });
  }
});

/** Hosts and containers (ADR 0034): a host with two containers, written as the agent would have reported them. */
test.describe("signed in, with hosts and containers on", () => {
  test.use({ storageState: STATE_FILE });
  const IMAGE = "d".repeat(64);
  test.beforeAll(async () => {
    const [org] = await sql<{ id: string }>("select id from organization limit 1");
    await sql(
      `insert into host_settings (organization_id, enabled) values ($1, true)
       on conflict (organization_id) do update set enabled = true`,
      [org?.id],
    );
    await sql(
      `insert into agent_host (id, organization_id, name, hostname, public_key, agent_version, docker_version, os, enrolled_at, last_seen_at, last_inventory_at)
       values ('hst_layout', $1, 'build-runner-with-a-long-name-01', 'build-runner-with-a-long-name-01.example.lan', $2, '0.0.12', '27.3.1', 'Debian GNU/Linux 12 (bookworm)', now(), now(), now())
       on conflict do nothing`,
      [org?.id, "k".repeat(43)],
    );
    await sql(
      `insert into container_image (organization_id, image_id, tags, digests, labels, source_key, distro, packages, package_count, packages_at, matched_at, first_seen_at, last_seen_at)
       values ($1, $2, '["git.example.test/team/seeded-app:1.4.0"]', '[]', '{"org.opencontainers.image.source":"https://git.example.test/team/seeded-app"}',
               'git.example.test/team/seeded-app', 'Alpine Linux v3.24', '[]', 0, now(), now(), now(), now())
       on conflict do nothing`,
      [org?.id, IMAGE],
    );
    for (const [id, name, ref] of [
      ["1", "seeded-app-with-a-rather-long-container-name", "git.example.test/team/seeded-app:1.4.0"],
      [
        "2",
        "edge",
        "registry.example.com/infrastructure/very/long/path/to/an/image:2024.10.29-build.1234-alpine",
      ],
    ]) {
      await sql(
        `insert into host_container (host_id, container_id, organization_id, name, image_ref, image_id, state, first_seen_at, last_seen_at)
         values ('hst_layout', $1, $2, $3, $4, $5, 'running', now(), now()) on conflict do nothing`,
        [id?.repeat(64), org?.id, name, ref, IMAGE],
      );
    }
  });
  test.afterAll(async () => {
    await sql("delete from agent_host where id = 'hst_layout'");
    await sql("delete from container_image where image_id = $1", [IMAGE]);
    await sql("update host_settings set enabled = false");
  });

  for (const { path, heading, name } of [
    { path: "/hosts", heading: "Agents", name: "hosts" },
    { path: "/hosts/hst_layout", heading: "build-runner-with-a-long-name-01", name: "host" },
    { path: `/hosts/images/${IMAGE}`, heading: "git.example.test/team/seeded-app:1.4.0", name: "host-image" },
    { path: "/repositories/repo_e2eseeded000000001", heading: "seeded-app", name: "repository-running" },
  ]) {
    test(`${name} fits without horizontal scrolling`, async ({ page }, info) => {
      const problems = watchForProblems(page);
      await page.goto(path);
      await expect(page.getByRole("heading", { name: heading, exact: true, level: 1 })).toBeVisible();
      await page.waitForLoadState("networkidle");
      expect(await hasNoHorizontalScroll(page)).toBe(true);
      expect(await overflowingCards(page)).toEqual([]);
      await page.screenshot({ path: info.outputPath(`${name}.png`), fullPage: true });
      expect(problems).toEqual([]);
    });
  }
});
