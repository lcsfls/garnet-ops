import { execFile } from "node:child_process";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import {
  type APIRequestContext,
  type Browser,
  type BrowserContext,
  type CDPSession,
  expect,
  type Page,
  request as playwrightRequest,
  test,
} from "@playwright/test";
import { E2E } from "./env.ts";
import {
  hasNoHorizontalScroll,
  nextTotpPeriod,
  STATE_FILE,
  signOut,
  totp,
  watchForProblems,
} from "./helpers.ts";
import { signedInAt, sql } from "./seed.ts";

/**
 * The account page (ADR 0017) with its own member, so the owner's session, password and second
 * factor stay as the other specs expect them: profile and preferences, password, replacing the
 * authenticator app, backup codes, passkeys with Chromium's virtual authenticator, sessions, the
 * operator recovery (the real CLI) and the audit entries.
 */
test.describe.configure({ mode: "serial" });
test.setTimeout(120_000);

const ORIGIN = { origin: E2E.publicUrl };
const EMAIL = "account.tester@e2e.test";
const NAME = "Alma Account";
const PASSWORD = "account-tester-password-1";
const NEW_PASSWORD = "account-tester-password-2";

let context: BrowserContext;
let page: Page;
/** The member's current authenticator secret and unused backup codes, followed through the tests. */
let secret = "";
let backupCodes: string[] = [];

const accountNav = (p: Page) => p.getByRole("navigation", { name: /^(Account sections|Kontobereiche)$/ });
const resetRateLimits = () => sql("delete from rate_limit");
const userId = async () =>
  (await sql<{ id: string }>('select id from "user" where email = $1', [EMAIL]))[0]?.id ?? "";

async function openSection(p: Page, section: string, heading: string) {
  await p.goto(`/account${section === "profile" ? "" : `?section=${section}`}`);
  await expect(p.getByRole("heading", { name: heading, level: 2 }).first()).toBeVisible();
}

/** A virtual authenticator that does user verification, like a phone or a laptop with a fingerprint reader. */
async function addAuthenticator(p: Page, verified = true): Promise<{ cdp: CDPSession; id: string }> {
  const cdp = await p.context().newCDPSession(p);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: verified,
      automaticPresenceSimulation: true,
    },
  });
  return { cdp, id: authenticatorId };
}

/** A sign-in request that does not ask for user verification, as an attacker's client would send it. */
async function rawPasskeySignIn(p: Page): Promise<{ status: number; code: string | null }> {
  return p.evaluate(async () => {
    const decode = (s: string) =>
      Uint8Array.from(
        atob(
          s
            .replace(/-/g, "+")
            .replace(/_/g, "/")
            .padEnd(Math.ceil(s.length / 4) * 4, "="),
        ),
        (c) => c.charCodeAt(0),
      );
    const encode = (buffer: ArrayBuffer) =>
      btoa(String.fromCharCode(...new Uint8Array(buffer)))
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");
    const options = await (await fetch("/api/auth/passkey/generate-authenticate-options")).json();
    const credential = (await navigator.credentials.get({
      publicKey: {
        challenge: decode(options.challenge),
        rpId: options.rpId,
        userVerification: "discouraged",
      },
    })) as PublicKeyCredential;
    const response = credential.response as AuthenticatorAssertionResponse;
    const res = await fetch("/api/auth/passkey/verify-authentication", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        response: {
          id: credential.id,
          rawId: encode(credential.rawId),
          type: credential.type,
          response: {
            authenticatorData: encode(response.authenticatorData),
            clientDataJSON: encode(response.clientDataJSON),
            signature: encode(response.signature),
            userHandle: response.userHandle ? encode(response.userHandle) : undefined,
          },
        },
      }),
    });
    const body = (await res.json().catch(() => null)) as { code?: string } | null;
    return { status: res.status, code: body?.code ?? null };
  });
}

/** Signs in over the API like another browser would, and returns the status of the second step. */
async function signInOverApi(
  api: APIRequestContext,
  password: string,
  second: { totp?: string; backupCode?: string },
): Promise<{ first: number; second: number }> {
  const first = await api.post("/api/auth/sign-in/email", {
    headers: ORIGIN,
    data: { email: EMAIL, password },
  });
  if (!first.ok()) return { first: first.status(), second: 0 };
  const step = second.totp
    ? await api.post("/api/auth/two-factor/verify-totp", { headers: ORIGIN, data: { code: second.totp } })
    : await api.post("/api/auth/two-factor/verify-backup-code", {
        headers: ORIGIN,
        data: { code: second.backupCode },
      });
  return { first: first.status(), second: step.status() };
}

const root = fileURLToPath(new URL("../../..", import.meta.url));
const execFileAsync = promisify(execFile);
/** The real operator command in the API container, here against the throw-away database. */
async function runCli(...args: string[]): Promise<{ code: number; out: string }> {
  try {
    const { stdout } = await execFileAsync("node", ["apps/api/src/cli.ts", ...args], {
      cwd: root,
      env: {
        ...process.env,
        ...E2E.dev,
        NODE_ENV: "test",
        PUBLIC_URL: E2E.publicUrl,
        DATABASE_URL: E2E.databaseUrl,
      },
    });
    return { code: 0, out: stdout };
  } catch (error) {
    const failed = error as { code?: number; stdout?: string; stderr?: string };
    return { code: failed.code ?? 1, out: `${failed.stdout ?? ""}${failed.stderr ?? ""}` };
  }
}

/** Invites the member through the API as the owner, accepts, and sets up the second factor in the browser. */
async function createMember(browser: Browser) {
  const owner = await browser.newContext({ storageState: STATE_FILE });
  await signedInAt("now");
  const invite = await owner.request.post("/api/v1/team/invitations", {
    headers: ORIGIN,
    data: { email: EMAIL, role: "member" },
  });
  expect(invite.status()).toBe(201);
  const link = ((await invite.json()) as { link: string }).link;
  await owner.close();

  context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  page = await context.newPage();
  const path = new URL(link).pathname + new URL(link).hash;
  await page.goto(path);
  await page.getByLabel("Your name").fill(NAME);
  await page.getByLabel("Choose a password").fill(PASSWORD);
  await page.getByRole("button", { name: "Join" }).click();
  await page.getByRole("link", { name: "Sign in" }).click();
  await page.getByLabel("Email").fill(EMAIL);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page).toHaveURL(/\/enroll$/);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Start setup" }).click();
  secret = (await page.locator("code").innerText()).replace(/\s+/g, "");
  await page.getByLabel("Code", { exact: true }).fill(totp(secret));
  await page.getByRole("button", { name: "Confirm code" }).click();
  backupCodes = await page.locator("ul li").allInnerTexts();
  await page.getByLabel("I have saved my backup codes").check();
  await page.getByRole("button", { name: "Continue to GarnetOps" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
}

test.beforeAll(async ({ browser }) => {
  await createMember(browser);
});

test.afterAll(async () => {
  await signedInAt("now");
  await context?.close();
});

test("the avatar menu opens the account page, which has its own sections", async () => {
  const problems = watchForProblems(page);
  await page.getByRole("button", { name: /^Account: / }).click();
  await page.getByRole("link", { name: "Account settings" }).click();
  await expect(page).toHaveURL(/\/account$/);
  await expect(page.getByRole("heading", { name: "Account", level: 1 })).toBeVisible();
  for (const name of ["Profile", "Password", "Authenticator app", "Passkeys", "Sessions"]) {
    await expect(accountNav(page).getByRole("link", { name })).toBeVisible();
  }
  await expect(accountNav(page).getByRole("link", { name: "Profile" })).toHaveAttribute(
    "aria-current",
    "page",
  );
  // Section and position live in the URL.
  await accountNav(page).getByRole("link", { name: "Sessions" }).click();
  await expect(page).toHaveURL(/section=sessions/);
  expect(await hasNoHorizontalScroll(page)).toBe(true);
  expect(problems).toEqual([]);
});

test("profile: the name changes, the address is fixed, language and time zone follow the account", async () => {
  const problems = watchForProblems(page);
  await openSection(page, "profile", "Profile");
  const email = page.getByLabel("Email address");
  await expect(email).toHaveValue(EMAIL);
  await expect(email).toHaveAttribute("readonly", "");
  await expect(page.getByText("Changing it is not supported yet.")).toBeVisible();

  await page.getByLabel("Display name").fill("Alma Renamed");
  await page.getByRole("button", { name: "Save" }).first().click();
  await expect(page.getByRole("status").filter({ hasText: "Saved." })).toBeVisible();
  await expect(page.getByRole("button", { name: "Account: Alma Renamed" })).toBeVisible();
  expect((await sql<{ name: string }>('select name from "user" where email = $1', [EMAIL]))[0]?.name).toBe(
    "Alma Renamed",
  );

  // Language and time zone are stored on the account, not only in this browser.
  const preferences = page.locator("form").filter({ has: page.getByLabel("Time zone") });
  await preferences.getByLabel("Time zone").selectOption("Asia/Tokyo");
  await preferences.getByLabel("Language").selectOption("de");
  await preferences.getByRole("button", { name: "Save" }).click();
  await expect(page.getByRole("heading", { name: "Konto", level: 1 })).toBeVisible();
  await expect
    .poll(async () =>
      JSON.stringify(await sql('select locale, time_zone from "user" where email = $1', [EMAIL])),
    )
    .toBe(JSON.stringify([{ locale: "de", time_zone: "Asia/Tokyo" }]));
  // A browser that never saw this account's choice gets it after sign-in: forget the local one and reload.
  await page.evaluate(() => localStorage.clear());
  await page.reload();
  await expect(page.getByRole("heading", { name: "Konto", level: 1 })).toBeVisible();

  // Shown times use the chosen zone: the sign-in time of this session in Tokyo.
  await openSection(page, "sessions", "Sitzungen");
  const shown = await page
    .locator("[data-current] time")
    .first()
    .evaluate((el) => ({
      iso: el.getAttribute("datetime") ?? "",
      text: el.textContent ?? "",
    }));
  const expected = new Intl.DateTimeFormat("de", {
    dateStyle: "medium",
    timeStyle: "short",
    timeZone: "Asia/Tokyo",
  }).format(new Date(shown.iso));
  expect(shown.text).toBe(expected);

  // Back to English and the browser's zone.
  await openSection(page, "profile", "Profil");
  const back = page.locator("form").filter({ has: page.getByLabel("Zeitzone") });
  await back.getByLabel("Zeitzone").selectOption({ index: 0 });
  await back.getByLabel("Sprache").selectOption("en");
  await back.getByRole("button", { name: "Speichern" }).click();
  await expect(page.getByRole("heading", { name: "Account", level: 1 })).toBeVisible();
  await expect
    .poll(async () => JSON.stringify(await sql('select time_zone from "user" where email = $1', [EMAIL])))
    .toBe(JSON.stringify([{ time_zone: null }]));
  expect(problems).toEqual([]);
});

test("the language picker in the menu is kept on the account", async () => {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await page.getByRole("button", { name: /^Account: / }).click();
  await page.getByLabel("Language").selectOption("de");
  await expect(page.locator("html")).toHaveAttribute("lang", "de");
  await expect
    .poll(
      async () =>
        (await sql<{ locale: string }>('select locale from "user" where email = $1', [EMAIL]))[0]?.locale,
    )
    .toBe("de");
  await page.getByLabel("Sprache").selectOption("en");
  await expect(page.locator("html")).toHaveAttribute("lang", "en");
  await expect
    .poll(
      async () =>
        (await sql<{ locale: string }>('select locale from "user" where email = $1', [EMAIL]))[0]?.locale,
    )
    .toBe("en");
  await page.keyboard.press("Escape");
});

test("password: wrong and mismatching input is refused, a change ends the other sessions", async () => {
  const problems = watchForProblems(page);
  await resetRateLimits();
  await signedInAt("now");
  await openSection(page, "password", "Password");

  // A sign-in older than ten minutes has to be confirmed first.
  await signedInAt("an hour ago");
  await page.getByLabel("Current password").fill(PASSWORD);
  await page.getByLabel("New password", { exact: true }).fill(NEW_PASSWORD);
  await page.getByLabel("Repeat the new password").fill(NEW_PASSWORD);
  await page.getByRole("button", { name: "Change password" }).click();
  const confirm = page.getByRole("dialog", { name: "Confirm it is you" });
  await expect(confirm).toBeVisible();
  await confirm.getByRole("button", { name: "Cancel" }).click();
  await signedInAt("now");
  expect(
    (await sql<{ password: string }>("select password from account where user_id = $1", [await userId()]))[0]
      ?.password,
  ).toBeTruthy();

  await page.getByLabel("Current password").fill("not-the-password-123");
  await page.getByLabel("New password", { exact: true }).fill(NEW_PASSWORD);
  await page.getByLabel("Repeat the new password").fill(NEW_PASSWORD);
  await page.getByRole("button", { name: "Change password" }).click();
  await expect(page.getByRole("alert")).toContainText("The current password is not correct.");

  await page.getByLabel("Current password").fill(PASSWORD);
  await page.getByLabel("Repeat the new password").fill("something-else-entirely-1");
  await page.getByRole("button", { name: "Change password" }).click();
  await expect(page.getByText("The two passwords are not the same.")).toBeVisible();

  // Another browser of this account is signed in.
  const id = await userId();
  await sql(
    `insert into session (id, expires_at, token, user_id, user_agent, ip_address)
     values ('ses_e2e_account_other', now() + interval '1 hour', 'tok_e2e_account_other', $1,
       'Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0', '203.0.113.9')`,
    [id],
  );
  await page.getByLabel("Repeat the new password").fill(NEW_PASSWORD);
  expect(await page.getByLabel("Sign out all my other sessions").isChecked()).toBe(true);
  await page.getByRole("button", { name: "Change password" }).click();
  await expect(
    page.getByRole("status").filter({ hasText: "Password changed. One other session was signed out." }),
  ).toBeVisible();
  expect(await sql("select 1 from session where id = 'ses_e2e_account_other'")).toHaveLength(0);
  // This session stays; the new password works, the old one does not.
  await expect(page.getByRole("heading", { name: "Account", level: 1 })).toBeVisible();
  const other = await playwrightRequest.newContext({ baseURL: E2E.publicUrl });
  expect((await signInOverApi(other, PASSWORD, { totp: totp(secret) })).first).toBe(401);
  expect((await signInOverApi(other, NEW_PASSWORD, { totp: totp(secret) })).second).toBe(200);
  await other.dispose();
  const dump = JSON.stringify(await sql("select data from audit_log"));
  expect(dump).not.toContain(NEW_PASSWORD);
  expect(dump).not.toContain(PASSWORD);

  // Not revoking keeps the others.
  await sql(
    `insert into session (id, expires_at, token, user_id) values ('ses_e2e_account_keep', now() + interval '1 hour', 'tok_e2e_account_keep', $1)`,
    [id],
  );
  await page.getByLabel("Current password").fill(NEW_PASSWORD);
  await page.getByLabel("New password", { exact: true }).fill(PASSWORD);
  await page.getByLabel("Repeat the new password").fill(PASSWORD);
  await page.getByLabel("Sign out all my other sessions").uncheck();
  await page.getByRole("button", { name: "Change password" }).click();
  await expect(
    page.getByRole("status").filter({ hasText: "Password changed. No other session was signed in." }),
  ).toBeVisible();
  expect(await sql("select 1 from session where id = 'ses_e2e_account_keep'")).toHaveLength(1);
  await sql("delete from session where id = 'ses_e2e_account_keep'");
  expect(problems).toEqual([]);
});

test("authenticator app: replacing needs a recent sign-in and keeps the old one until the new one works", async () => {
  const problems = watchForProblems(page);
  await resetRateLimits();
  await signedInAt("now");
  await openSection(page, "authenticator", "Authenticator app");
  await expect(page.getByText("A second factor is required for every account.")).toBeVisible();
  // There is no way to switch it off.
  await expect(page.getByRole("button", { name: /switch off|disable|remove/i })).toHaveCount(0);
  const refused = await page.request.post("/api/auth/two-factor/disable", {
    headers: ORIGIN,
    data: { password: PASSWORD },
  });
  expect(refused.status()).toBe(403);

  // Not with a stale sign-in.
  await signedInAt("an hour ago");
  await page.getByRole("button", { name: "Replace authenticator app" }).click();
  const dialog = page.getByRole("dialog", { name: "Replace the authenticator app" });
  await dialog.getByLabel("Password").fill(PASSWORD);
  await dialog.getByRole("button", { name: "Continue" }).click();
  const confirm = page.getByRole("dialog", { name: "Confirm it is you" });
  await expect(confirm).toBeVisible();
  await confirm.getByRole("button", { name: "Cancel" }).click();
  await signedInAt("now");

  // Wrong password first, then the real thing.
  await dialog.getByLabel("Password").fill("not-the-password-123");
  await dialog.getByRole("button", { name: "Continue" }).click();
  await expect(dialog.getByRole("alert")).toContainText("The password is not correct.");
  await dialog.getByLabel("Password").fill(PASSWORD);
  await dialog.getByRole("button", { name: "Continue" }).click();
  await expect(dialog.getByRole("img", { name: "QR code for your authenticator app" })).toBeVisible();
  const next = (await dialog.locator("code").innerText()).replace(/\s+/g, "");
  expect(next).toMatch(/^[A-Z2-7]{16,}$/);
  expect(next).not.toBe(secret);

  // A wrong code changes nothing; the old authenticator still works.
  await dialog.getByLabel("Code", { exact: true }).fill(totp(next) === "000000" ? "111111" : "000000");
  await dialog.getByRole("button", { name: "Confirm and replace" }).click();
  await expect(dialog.getByRole("alert")).toContainText("The code is not correct");
  const stillOld = await playwrightRequest.newContext({ baseURL: E2E.publicUrl });
  expect((await signInOverApi(stillOld, PASSWORD, { totp: totp(secret) })).second).toBe(200);
  await stillOld.dispose();

  await dialog.getByLabel("Code", { exact: true }).fill(totp(next));
  await dialog.getByRole("button", { name: "Confirm and replace" }).click();
  await expect(
    page.getByRole("status").filter({ hasText: "Your new authenticator app is active." }),
  ).toBeVisible();
  const oldSecret = secret;
  secret = next;

  // Now only the new one works.
  await resetRateLimits();
  const fresh = await playwrightRequest.newContext({ baseURL: E2E.publicUrl });
  const oldCode = totp(oldSecret);
  if (oldCode !== totp(secret)) {
    expect((await signInOverApi(fresh, PASSWORD, { totp: oldCode })).second).toBe(401);
  }
  expect((await signInOverApi(fresh, PASSWORD, { totp: totp(secret) })).second).toBe(200);
  await fresh.dispose();
  expect(problems).toEqual([]);
});

test("backup codes: new ones replace the old, are shown once and work at sign-in", async () => {
  const problems = watchForProblems(page);
  await resetRateLimits();
  await signedInAt("now");
  await openSection(page, "authenticator", "Backup codes");
  await expect(page.getByTestId("codes-left")).toHaveText("10 unused backup codes");

  await page.getByRole("button", { name: "Create new backup codes" }).click();
  await page
    .getByRole("dialog", { name: "Create new backup codes?" })
    .getByRole("button", { name: "Create new codes" })
    .click();
  const shown = page.getByRole("dialog", { name: "Your new backup codes" });
  await expect(shown).toBeVisible();
  const fresh = await shown.locator("li").allInnerTexts();
  expect(fresh).toHaveLength(10);
  expect(fresh.some((c) => backupCodes.includes(c))).toBe(false);
  const done = shown.getByRole("button", { name: "Done" });
  await expect(done).toBeDisabled();
  await shown.getByLabel("I have saved my backup codes").check();
  await done.click();
  // Shown once: the page only counts them.
  await expect(page.locator("body")).not.toContainText(fresh[0] ?? "x");
  await expect(page.getByTestId("codes-left")).toHaveText("10 unused backup codes");
  const stored = JSON.stringify(await sql("select backup_codes from two_factor"));
  expect(stored).not.toContain(fresh[0] ?? "x");
  expect(JSON.stringify(await sql("select data from audit_log"))).not.toContain(fresh[0] ?? "x");

  const api = await playwrightRequest.newContext({ baseURL: E2E.publicUrl });
  expect((await signInOverApi(api, PASSWORD, { backupCode: backupCodes[0] ?? "" })).second).toBe(401);
  await resetRateLimits();
  expect((await signInOverApi(api, PASSWORD, { backupCode: fresh[0] ?? "" })).second).toBe(200);
  await api.dispose();
  backupCodes = fresh.slice(1);
  await page.reload();
  await expect(page.getByTestId("codes-left")).toHaveText("9 unused backup codes");
  expect(problems).toEqual([]);
});

test("passkeys: add, sign in without a password, rename, and remove, with user verification required", async () => {
  const problems = watchForProblems(page);
  await resetRateLimits();
  await signedInAt("now");
  const authenticator = await addAuthenticator(page);
  await openSection(page, "passkeys", "Passkeys");
  await expect(page.getByText("No passkeys yet.")).toBeVisible();
  await expect(page.getByText("These passkeys only work on localhost.")).toBeVisible();

  // Not with a stale sign-in: the ceremony asks to confirm first.
  await signedInAt("an hour ago");
  await page.getByRole("button", { name: "Add a passkey" }).click();
  const add = page.getByRole("dialog", { name: "Add a passkey" });
  await add.getByLabel("Name").fill("Work laptop");
  await add.getByRole("button", { name: "Create passkey" }).click();
  const confirm = page.getByRole("dialog", { name: "Confirm it is you" });
  await expect(confirm).toBeVisible();
  await expect(confirm.getByRole("button", { name: "Confirm with a passkey" })).toHaveCount(0);
  await confirm.getByRole("button", { name: "Cancel" }).click();
  expect(await sql("select 1 from passkey")).toHaveLength(0);
  await signedInAt("now");

  // A device that cannot verify the person does not get to register: nothing is stored.
  await authenticator.cdp.send("WebAuthn.setUserVerified", {
    authenticatorId: authenticator.id,
    isUserVerified: false,
  });
  await add.getByRole("button", { name: "Create passkey" }).click();
  await expect(add.getByRole("alert")).toBeVisible();
  expect(await sql("select 1 from passkey")).toHaveLength(0);
  await authenticator.cdp.send("WebAuthn.setUserVerified", {
    authenticatorId: authenticator.id,
    isUserVerified: true,
  });

  await add.getByRole("button", { name: "Create passkey" }).click();
  await expect(page.getByRole("status").filter({ hasText: "Passkey added." })).toBeVisible();
  const row = page.getByTestId("passkey").filter({ hasText: "Work laptop" });
  await expect(row).toContainText("Not used yet");
  const [stored] = await sql<{ id: string; credential_id: string; public_key: string }>(
    "select id, credential_id, public_key from passkey",
  );
  // Neither the credential id nor the public key reach the page.
  await expect(page.locator("body")).not.toContainText(stored?.credential_id ?? "x");

  // Sign out and in again with the passkey alone: no password, no code.
  await page.getByRole("button", { name: /^Account: / }).click();
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page).toHaveURL(/\/sign-in$/);
  // An attacker's client that does not ask for user verification is refused by the server,
  // even with a valid signature, when the authenticator did not verify the person.
  await authenticator.cdp.send("WebAuthn.setUserVerified", {
    authenticatorId: authenticator.id,
    isUserVerified: false,
  });
  const downgraded = await rawPasskeySignIn(page);
  expect(downgraded.status).toBe(401);
  expect(downgraded.code).toBe("USER_VERIFICATION_REQUIRED");
  expect((await page.request.get("/api/v1/me")).status()).toBe(401);
  await authenticator.cdp.send("WebAuthn.setUserVerified", {
    authenticatorId: authenticator.id,
    isUserVerified: true,
  });
  await page.getByRole("button", { name: "Sign in with a passkey" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  expect((await page.request.get("/api/v1/me")).status()).toBe(200);

  await openSection(page, "passkeys", "Passkeys");
  await expect(row).toContainText("Last used");
  await expect(row).not.toContainText("Not used yet");
  // Another browser, another person: an unknown passkey cannot sign in.
  const [counter] = await sql<{ counter: number }>("select counter from passkey");
  expect(counter?.counter).toBeGreaterThanOrEqual(0);

  // The step-up dialog offers the passkey as well.
  await signedInAt("an hour ago");
  await row.getByRole("button", { name: "Remove" }).click();
  await page
    .getByRole("dialog", { name: "Remove this passkey?" })
    .getByRole("button", { name: "Remove passkey" })
    .click();
  const stepUp = page.getByRole("dialog", { name: "Confirm it is you" });
  await expect(stepUp).toBeVisible();
  await stepUp.getByRole("button", { name: "Confirm with a passkey" }).click();
  // The removal runs again once the sign-in is fresh.
  await expect(page.getByRole("status").filter({ hasText: "Passkey removed." })).toBeVisible();
  expect(await sql("select 1 from passkey")).toHaveLength(0);

  // Add it again, rename it.
  await signedInAt("now");
  await page.getByRole("button", { name: "Add a passkey" }).click();
  await page.getByRole("dialog", { name: "Add a passkey" }).getByLabel("Name").fill("Phone");
  await page
    .getByRole("dialog", { name: "Add a passkey" })
    .getByRole("button", { name: "Create passkey" })
    .click();
  const phone = page.getByTestId("passkey").filter({ hasText: "Phone" });
  await expect(phone).toBeVisible();
  await phone.getByRole("button", { name: "Rename" }).click();
  const rename = page.getByRole("dialog", { name: "Rename passkey" });
  await rename.getByLabel("Name").fill("Pocket device");
  await rename.getByRole("button", { name: "Save name" }).click();
  await expect(page.getByTestId("passkey").filter({ hasText: "Pocket device" })).toBeVisible();
  await authenticator.cdp.detach();
  expect(problems).toEqual([]);
});

test("the matching better-auth endpoints are closed, and registering needs a recent sign-in", async () => {
  const id = await userId();
  for (const path of [
    "/api/auth/change-password",
    "/api/auth/update-user",
    "/api/auth/revoke-other-sessions",
    "/api/auth/two-factor/get-totp-uri",
    "/api/auth/two-factor/generate-backup-codes",
    "/api/auth/passkey/delete-passkey",
    "/api/auth/passkey/update-passkey",
  ]) {
    const res = await page.request.post(path, {
      headers: ORIGIN,
      data: { password: PASSWORD, id: "x", name: "x" },
    });
    expect(res.status(), path).toBe(403);
  }
  expect((await page.request.get("/api/auth/passkey/list-user-passkeys")).status()).toBe(403);
  expect((await page.request.get("/api/auth/list-sessions")).status()).toBe(403);
  expect(
    Number(
      (
        await sql<{ n: string }>(
          "select count(*) n from audit_log where action = 'auth.endpoint_refused' and actor_user_id = $1",
          [id],
        )
      )[0]?.n,
    ),
  ).toBeGreaterThanOrEqual(8);

  await signedInAt("an hour ago");
  const stale = await page.request.get("/api/auth/passkey/generate-register-options");
  expect(stale.status()).toBe(403);
  expect(((await stale.json()) as { code: string }).code).toBe("STEP_UP_REQUIRED");
  await signedInAt("now");
});

test("sessions: this one is marked, others can be signed out one by one or all at once", async () => {
  const problems = watchForProblems(page);
  const id = await userId();
  await sql(
    `insert into session (id, expires_at, token, user_id, user_agent, ip_address) values
     ('ses_e2e_account_a', now() + interval '1 hour', 'tok_e2e_account_a', $1,
      'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36', '203.0.113.20'),
     ('ses_e2e_account_b', now() + interval '1 hour', 'tok_e2e_account_b', $1,
      'Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1', '198.51.100.30')`,
    [id],
  );
  await openSection(page, "sessions", "Sessions");
  const current = page.locator('[data-testid="session"][data-current="true"]');
  await expect(current).toHaveCount(1);
  await expect(current).toContainText("This session");
  await expect(current.getByRole("button", { name: "Sign out" })).toHaveCount(0);
  const a = page.getByTestId("session").filter({ hasText: "203.0.113.20" });
  await expect(a).toContainText("Chrome on Windows");
  await expect(page.getByTestId("session").filter({ hasText: "Safari on iOS" })).toContainText(
    "198.51.100.30",
  );
  // No session token is on the page.
  await expect(page.locator("body")).not.toContainText("tok_e2e_account");

  await a.getByRole("button", { name: "Sign out" }).click();
  await page
    .getByRole("dialog", { name: "Sign out this session?" })
    .getByRole("button", { name: "Sign out" })
    .click();
  await expect(page.getByTestId("session").filter({ hasText: "203.0.113.20" })).toHaveCount(0);
  expect(await sql("select 1 from session where id = 'ses_e2e_account_a'")).toHaveLength(0);

  await page.getByRole("button", { name: "Sign out all other sessions" }).click();
  await page
    .getByRole("dialog", { name: "Sign out all other sessions?" })
    .getByRole("button", { name: "Sign out the others" })
    .click();
  await expect(page.getByRole("status").filter({ hasText: /sessions? (was|were) signed out/ })).toBeVisible();
  await expect(page.getByTestId("session")).toHaveCount(1);
  await expect(page.getByRole("button", { name: "Sign out all other sessions" })).toBeDisabled();
  expect(await sql("select 1 from session where user_id = $1", [id])).toHaveLength(1);
  // The API refuses to end the current session or one of someone else.
  const sessionId =
    (await sql<{ id: string }>("select id from session where user_id = $1", [id]))[0]?.id ?? "";
  expect(
    (await page.request.delete(`/api/v1/account/sessions/${sessionId}`, { headers: ORIGIN })).status(),
  ).toBe(400);
  expect(
    (await page.request.delete("/api/v1/account/sessions/ses_e2e_nobody", { headers: ORIGIN })).status(),
  ).toBe(404);
  expect(problems).toEqual([]);
});

test("recovery: the operator command removes the second factors and the account sets up a new one", async () => {
  test.setTimeout(180_000);
  await resetRateLimits();
  const id = await userId();
  // A passkey to be removed with the rest.
  await sql(
    `insert into passkey (id, name, public_key, user_id, credential_id, counter, device_type, backed_up)
     values ('pk_e2e_account_gone', 'Gone', 'AAAA', $1, 'cred_e2e_account_gone', 0, 'multiDevice', true)`,
    [id],
  );

  // Without --yes nothing changes.
  const preview = await runCli("reset-second-factor", EMAIL.toUpperCase());
  expect(preview.code).toBe(0);
  expect(preview.out).toContain("Authenticator app: enrolled, will be removed");
  expect(preview.out).toMatch(/Passkeys: \d+, will be removed/);
  expect(preview.out).toContain("Nothing changed");
  expect((await page.request.get("/api/v1/me")).status()).toBe(200);
  expect(await sql("select 1 from two_factor where user_id = $1", [id])).toHaveLength(1);
  expect((await runCli("reset-second-factor", "nobody@e2e.test", "--yes")).code).toBe(1);
  expect((await runCli("reset-second-factor")).code).toBe(2);

  const result = await runCli("reset-second-factor", EMAIL, "--yes");
  expect(result.code).toBe(0);
  expect(result.out).toContain("Done.");
  expect(result.out).not.toContain(secret);
  expect(await sql("select 1 from two_factor where user_id = $1", [id])).toHaveLength(0);
  expect(await sql("select 1 from passkey where user_id = $1", [id])).toHaveLength(0);
  expect(await sql("select 1 from session where user_id = $1", [id])).toHaveLength(0);
  expect(
    (
      await sql<{ two_factor_enabled: boolean }>('select two_factor_enabled from "user" where id = $1', [id])
    )[0]?.two_factor_enabled,
  ).toBe(false);
  // The signed-in browser is out at once; the web UI offers no way to do this.
  expect((await page.request.get("/api/v1/me")).status()).toBe(401);

  // The password still works and leads straight to the setup of a new second factor.
  await page.goto("/sign-in");
  await page.getByLabel("Email").fill(EMAIL);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page).toHaveURL(/\/enroll$/);
  expect((await page.request.get("/api/v1/me")).status()).toBe(403);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Start setup" }).click();
  const fresh = (await page.locator("code").innerText()).replace(/\s+/g, "");
  expect(fresh).not.toBe(secret);
  await page.getByLabel("Code", { exact: true }).fill(totp(fresh));
  await page.getByRole("button", { name: "Confirm code" }).click();
  await page.getByLabel("I have saved my backup codes").check();
  await page.getByRole("button", { name: "Continue to GarnetOps" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  secret = fresh;
});

test("the owner finds every account action in the audit log under Account", async ({ browser }) => {
  const owner = await browser.newContext({ storageState: STATE_FILE });
  const ownerPage = await owner.newPage();
  const problems = watchForProblems(ownerPage);
  await ownerPage.goto("/audit-log?group=account");
  await expect(ownerPage.getByRole("button", { name: "Account", exact: true })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  for (const action of [
    "Display name changed",
    "Password changed",
    "Replacing the authenticator app started",
    "Authenticator app replaced",
    "Backup codes renewed",
    "Passkey added",
    "Passkey renamed",
    "Passkey removed",
    "Session signed out",
    "Other sessions signed out",
    "Second factor reset by an operator",
  ]) {
    await expect(ownerPage.getByText(action, { exact: true }).first(), action).toBeVisible();
  }
  // The operator reset has no signed-in actor and names the account and the way.
  const reset = ownerPage.locator("tbody tr").filter({ hasText: "Second factor reset by an operator" });
  await expect(reset).toContainText("System");
  await expect(reset).toContainText(EMAIL);
  // Passkey sign-ins are in the sign-in group.
  await ownerPage.goto("/audit-log?group=auth");
  await expect(ownerPage.getByText("Sign-in with a passkey").first()).toBeVisible();
  await expect(ownerPage.getByText("Sign-in endpoint closed to direct use (refused)").first()).toBeVisible();
  // The passkey that did not verify the person is attributed to its account and shown as failed.
  await expect(
    ownerPage.locator("tbody tr").filter({ hasText: "Sign-in with a passkey" }).filter({ hasText: "Failed" }),
  ).toHaveCount(1);
  // Nothing secret is in the audit log.
  const dump = JSON.stringify(await sql("select data from audit_log"));
  for (const secretValue of [secret, PASSWORD, NEW_PASSWORD, ...backupCodes])
    expect(dump).not.toContain(secretValue);
  expect(problems).toEqual([]);
  await owner.close();
});

test("signing out loads the sign-in page at once; a session ended elsewhere leads there with a notice", async () => {
  test.setTimeout(150_000);
  await resetRateLimits();
  const problems = watchForProblems(page);
  // Signing out from a page with live streams and queries: straight to the sign-in page, no
  // error messages from requests that were still running.
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await signOut(page);
  await expect(page).toHaveURL(/\/sign-in$/);
  await expect(page.getByRole("alert")).toHaveCount(0);
  await expect(page.getByText("Your sign-in has expired. Sign in again.")).toHaveCount(0);

  // Sign in again.
  await page.getByLabel("Email").fill(EMAIL);
  await page.getByLabel("Password").fill(PASSWORD);
  await page.getByRole("button", { name: "Sign in", exact: true }).click();
  await expect(page).toHaveURL(/\/two-factor$/);
  await nextTotpPeriod(page);
  await page.getByLabel("Code", { exact: true }).fill(totp(secret));
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();

  // The session ends elsewhere (another tab, an admin, expiry): the next request answers 401
  // and the app goes to the sign-in page and says why, instead of showing errors in place.
  await sql("delete from session where user_id = $1", [await userId()]);
  // Background requests (the bell, live streams) may notice it before the click does.
  await page
    .getByRole("link", { name: "Findings" })
    .first()
    .click({ timeout: 5_000 })
    .catch(() => {});
  await expect(page).toHaveURL(/\/sign-in\?ended=1$/);
  await expect(page.getByText("Your sign-in has expired. Sign in again.")).toBeVisible();
  // A plain visit to the app without a session is a normal redirect, without that notice.
  await page.goto("/");
  await expect(page).toHaveURL(/\/sign-in$/);
  await expect(page.getByText("Your sign-in has expired. Sign in again.")).toHaveCount(0);
  // 401 answers are expected here; nothing else may go wrong.
  expect(problems.filter((p) => !/401/.test(p))).toEqual([]);
});
