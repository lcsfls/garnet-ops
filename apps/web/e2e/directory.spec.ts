import { type Browser, type BrowserContext, expect, type Page, test } from "@playwright/test";
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
 * Signing in with LDAP or Active Directory (ADR 0020), against the worker's directory part and a fake
 * Active Directory (apps/worker/test/e2e-directory-worker.ts): the owner's settings with a test and
 * the pin of a certificate, sign-in of directory accounts with the mandatory second factor from
 * the first sign-in on, refusals that look alike, roles from groups (also for a session that
 * is already open), linking an existing account, and that the owner's local sign-in is untouched.
 * Owners' step-up is satisfied by marking the session as just signed in.
 */
test.describe.configure({ mode: "serial" });
test.setTimeout(180_000);

const ORIGIN = { origin: E2E.publicUrl };
const CONTROL = `http://127.0.0.1:${E2E.directoryControlPort}`;
const SERVICE_DN = "CN=svc-garnetops,OU=Service,DC=example,DC=lan";
const SERVICE_PASSWORD = "test-only-service-password";
const USER_PASSWORD = "test-only-user-password";
const BASE = "OU=Users,DC=example,DC=lan";
const GROUPS = {
  admins: "CN=GarnetOps-Admins,OU=Groups,DC=example,DC=lan",
  users: "CN=GarnetOps-Users,OU=Groups,DC=example,DC=lan",
  viewers: "CN=GarnetOps-Viewers,OU=Groups,DC=example,DC=lan",
};
const ANNA = { username: "asmith", email: "asmith@example.lan", name: "Anna Smith" };
const LOCAL = {
  email: "local.person@example.lan",
  name: "Local Person",
  password: "local-person-password-1",
  username: "lperson",
};

interface DirectoryState {
  url: string;
  ca: string;
  fingerprintA: string;
  fingerprintB: string;
  seen: { op: string; dn?: string; tls: boolean; passwordLength?: number }[];
}
const state = async (): Promise<DirectoryState> =>
  (await fetch(`${CONTROL}/state`)).json() as Promise<DirectoryState>;
const control = async (path: string, body?: unknown) => {
  const res = await fetch(`${CONTROL}${path}`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  expect(res.ok).toBe(true);
};
const resetRateLimits = () => sql("delete from rate_limit");
const roleOf = async (email: string) =>
  (
    await sql<{ role: string }>(
      'select m.role from membership m join "user" u on u.id = m.user_id where u.email = $1',
      [email],
    )
  )[0]?.role ?? null;
const auditOf = (action: string) =>
  sql<{ data: Record<string, unknown>; actor_user_id: string | null }>(
    "select data, actor_user_id from audit_log where action = $1 order by id",
    [action],
  );

/** An empty browser, as a person who is not signed in anywhere. */
async function visitor(browser: Browser): Promise<{ context: BrowserContext; page: Page }> {
  const context = await browser.newContext({ storageState: { cookies: [], origins: [] } });
  return { context, page: await context.newPage() };
}

async function directorySignIn(page: Page, username: string, password: string) {
  await page.goto("/sign-in");
  await page.getByRole("button", { name: "Directory account" }).click();
  await expect(page).toHaveURL(/via=directory/);
  await page.getByLabel("User name").fill(username);
  await page.getByLabel("Password").fill(password);
  await page.getByRole("button", { name: "Sign in with directory account" }).click();
}

/** The mandatory enrolment of a new directory account: no password is asked for. */
async function enrol(page: Page): Promise<{ secret: string }> {
  await expect(page).toHaveURL(/\/enroll$/);
  await expect(page.getByLabel("Password")).toHaveCount(0);
  await expect(page.getByText("there is no GarnetOps password to confirm")).toBeVisible();
  await page.getByRole("button", { name: "Start setup" }).click();
  const secret = (await page.locator("code").innerText()).replace(/\s+/g, "");
  await page.getByLabel("Code", { exact: true }).fill(totp(secret));
  await page.getByRole("button", { name: "Confirm code" }).click();
  await page.getByLabel("I have saved my backup codes").check();
  await page.getByRole("button", { name: "Continue to GarnetOps" }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  return { secret };
}

const form = (page: Page) => page.getByTestId("directory-form");
const REFUSAL = "User name or password is not correct, or this account may not sign in here.";

let anna: { context: BrowserContext; page: Page; secret: string } | null = null;

// The limits of the library (five a minute per address) count what the specs before this one did too.
test.beforeEach(async () => {
  await resetRateLimits();
});

test.afterAll(async () => {
  await anna?.context.close();
});

test.describe("the owner's settings", () => {
  test.use({ storageState: STATE_FILE });

  test("Sign-in settings are for owners: save, test with a person, switch on", async ({ page }) => {
    const problems = watchForProblems(page);
    await signedInAt("now");
    await page.goto("/settings");
    await expect(
      page.getByRole("navigation", { name: "Settings sections" }).getByRole("link", { name: "Sign-in" }),
    ).toBeVisible();
    await page
      .getByRole("navigation", { name: "Settings sections" })
      .getByRole("link", { name: "Sign-in" })
      .click();
    await expect(page).toHaveURL(/section=signin/);
    await expect(page.getByRole("heading", { name: "Directory sign-in", level: 2 })).toBeVisible();

    const directory = await state();
    await page.locator("#directory-servers").fill(directory.url);
    await page.getByLabel("Own certificate authority").check();
    await page.locator("#directory-ca").fill(directory.ca);
    await page.locator("#directory-bind-dn").fill(SERVICE_DN);
    await page.locator("#directory-bind-password").fill(SERVICE_PASSWORD);
    await page.locator("#directory-base").fill(BASE);
    // The Active Directory preset filled in the filter, attributes and the nested-groups mode.
    await expect(page.locator("#directory-filter")).toHaveValue(
      "(&(objectClass=user)(sAMAccountName={username}))",
    );
    await expect(page.locator("#directory-attr-id")).toHaveValue("objectGUID");
    await page.getByLabel("Group 1: distinguished name").fill(GROUPS.admins);
    await page.getByLabel("Group 1: role").selectOption("admin");
    await page.getByRole("button", { name: "Add a group" }).click();
    await page.getByLabel("Group 2: distinguished name").fill(GROUPS.users);
    await page.getByLabel("Group 2: role").selectOption("member");
    await page.getByRole("button", { name: "Add a group" }).click();
    await page.getByLabel("Group 3: distinguished name").fill(GROUPS.viewers);
    await page.getByLabel("Group 3: role").selectOption("viewer");

    // Not tested yet: it cannot be switched on.
    await expect(page.getByTestId("directory-enabled")).toBeDisabled();
    await form(page).getByRole("button", { name: "Save" }).click();
    await expect(page.getByRole("status").filter({ hasText: "Saved." })).toBeVisible();
    await expect(page.getByTestId("directory-enabled")).toBeDisabled();

    // The password is write-only.
    await expect(page.locator("#directory-bind-password")).toHaveValue("");
    await expect(page.getByText("A password is stored. Leave this empty to keep it.")).toBeVisible();
    const sealed = await sql<{ purpose: string; sealed: unknown }>(
      "select s.purpose, s.sealed from secret s join ldap_config c on c.bind_secret_id = s.id",
    );
    expect(sealed).toHaveLength(1);
    expect(sealed[0]?.purpose).toBe("ldap-bind-password");
    expect(JSON.stringify(sealed[0]?.sealed)).not.toContain(SERVICE_PASSWORD);
    const answer = await page.request.get("/api/v1/directory");
    expect(await answer.text()).not.toContain(SERVICE_PASSWORD);

    // The test shows the person, their groups and the role they would get, and never a password.
    await page.locator("#directory-test-user").fill("jdoe");
    await page.getByTestId("directory-test").click();
    const result = page.getByTestId("directory-test-result");
    await expect(result.getByText("Works", { exact: true })).toBeVisible();
    await expect(result).toContainText("CN=John Doe,OU=Users,DC=example,DC=lan");
    await expect(result).toContainText("jdoe@example.lan");
    await expect(result).toContainText("12345678-9abc-def0-0123-456789abcd01");
    await expect(result).toContainText(GROUPS.admins);
    await expect(result.getByText("Admin", { exact: true })).toBeVisible();
    await expect(result).toContainText("LDAPS");
    await expect(result).not.toContainText(SERVICE_PASSWORD);

    // Now it can be switched on.
    await expect(page.getByTestId("directory-enabled")).toBeEnabled();
    await page.getByTestId("directory-enabled").check();
    await form(page).getByRole("button", { name: "Save" }).click();
    await expect(page.getByRole("status").filter({ hasText: "Saved." }).first()).toBeVisible();
    await expect(page.getByText("On", { exact: true }).first()).toBeVisible();
    expect((await sql<{ enabled: boolean }>("select enabled from ldap_config"))[0]?.enabled).toBe(true);

    // The directory saw the service account bind and a search; every message was encrypted.
    const seen = (await state()).seen;
    expect(seen.some((s) => s.op === "bind" && s.dn === SERVICE_DN)).toBe(true);
    expect(seen.every((s) => s.tls)).toBe(true);
    expect(seen.filter((s) => s.op === "bind").every((s) => (s.passwordLength ?? 0) > 0)).toBe(true);

    const audit = await auditOf("directory.settings_created");
    expect(audit).toHaveLength(1);
    expect(JSON.stringify(audit)).not.toContain(SERVICE_PASSWORD);
    expect(await auditOf("directory.test_run")).not.toHaveLength(0);
    expect(await hasNoHorizontalScroll(page)).toBe(true);
    expect(problems).toEqual([]);
  });

  test("a wrong filter or a typo in a group is reported by the test, before anyone is locked out", async ({
    page,
  }) => {
    await page.goto("/settings?section=signin");
    await page.locator("#directory-test-user").fill("nobody");
    await page.getByTestId("directory-test").click();
    const result = page.getByTestId("directory-test-result");
    await expect(result.getByText("Does not work yet")).toBeVisible();
    await expect(result).toContainText("No user matched the filter.");
    // Settings that fail validation are not saved, and the field says why.
    await page.locator("#directory-filter").fill("(sAMAccountName=jdoe)");
    await form(page).getByRole("button", { name: "Save" }).click();
    await expect(page.getByText("Some settings are not valid.")).toBeVisible();
    await expect(
      page.getByText("The filter must contain the placeholder mentioned in the hint."),
    ).toBeVisible();
    await page.reload();
    await expect(page.locator("#directory-filter")).toHaveValue(
      "(&(objectClass=user)(sAMAccountName={username}))",
    );
  });
});

test("the sign-in page offers the directory next to the local sign-in", async ({ browser }) => {
  const { context, page } = await visitor(browser);
  const problems = watchForProblems(page);
  await page.goto("/sign-in");
  const choice = page.getByRole("group", { name: "How to sign in" });
  await expect(choice.getByRole("button", { name: "Local account" })).toHaveAttribute("aria-pressed", "true");
  await expect(page.getByLabel("Email")).toBeVisible();
  await choice.getByRole("button", { name: "Directory account" }).click();
  await expect(choice.getByRole("button", { name: "Directory account" })).toHaveAttribute(
    "aria-pressed",
    "true",
  );
  await expect(page.getByLabel("User name")).toBeVisible();
  await expect(page.getByLabel("Email")).toHaveCount(0);
  await expect(page.getByText("The name you use to sign in to your computer at work.")).toBeVisible();
  await expect(page.getByRole("button", { name: "Sign in with a passkey" })).toBeVisible();
  expect(await hasNoHorizontalScroll(page)).toBe(true);
  expect(problems).toEqual([]);
  await context.close();
});

test("a person in an allowed group signs in, sets up the second factor without a password, and gets the role of the groups", async ({
  browser,
}) => {
  const { context, page } = await visitor(browser);
  const problems = watchForProblems(page);
  await directorySignIn(page, ANNA.username, USER_PASSWORD);
  const { secret } = await enrol(page);
  anna = { context, page, secret };

  // Anna is in the users and the viewers group: the higher role, member, applies.
  expect(await roleOf(ANNA.email)).toBe("member");
  const [row] = await sql<{ email_verified: boolean; two_factor_enabled: boolean }>(
    'select email_verified, two_factor_enabled from "user" where email = $1',
    [ANNA.email],
  );
  expect(row).toMatchObject({ email_verified: false, two_factor_enabled: true });
  // No local password was ever made for the account.
  expect(
    await sql('select 1 from account a join "user" u on u.id = a.user_id where u.email = $1', [ANNA.email]),
  ).toHaveLength(0);
  expect(await auditOf("directory.account_created")).not.toHaveLength(0);
  expect((await auditOf("auth.directory_sign_in")).at(-1)?.data).toMatchObject({ outcome: "success" });

  // The directory is the source of the password and the name.
  await page.goto("/account?section=password");
  await expect(page.getByTestId("password-managed")).toContainText(
    "signs in with your organisation's directory",
  );
  await expect(page.getByLabel("Current password")).toHaveCount(0);
  await page.goto("/account");
  await expect(page.getByLabel("Display name")).toHaveAttribute("readonly", "");
  await expect(page.getByText("Your directory sets this name")).toBeVisible();
  expect(problems).toEqual([]);
});

test("the next sign-in asks for the code, and a confirmation uses the directory name", async () => {
  if (!anna) throw new Error("the first sign-in did not run");
  await signOut(anna.page);
  await expect(anna.page).toHaveURL(/\/sign-in$/);
  await nextTotpPeriod(anna.page);
  await directorySignIn(anna.page, ANNA.username, USER_PASSWORD);
  await expect(anna.page).toHaveURL(/\/two-factor$/);
  await anna.page.getByLabel("Code").fill(totp(anna.secret));
  await anna.page.getByRole("button", { name: "Verify" }).click();
  await expect(anna.page.getByRole("heading", { name: "Overview" })).toBeVisible();

  // "Confirm it is you" for a directory account asks for the directory name and password.
  await sql("update session set created_at = now() - interval '1 hour'");
  await anna.page.goto("/account?section=authenticator");
  await anna.page.getByRole("button", { name: "Replace authenticator app" }).click();
  const dialog = anna.page.getByRole("dialog", { name: "Replace the authenticator app" });
  await expect(dialog.getByLabel("Password")).toHaveCount(0);
  await dialog.getByRole("button", { name: "Continue" }).click();
  const confirm = anna.page.getByRole("dialog", { name: "Confirm it is you" });
  await expect(confirm.getByLabel("User name")).toHaveValue(ANNA.username);
  await confirm.getByLabel("Password").fill(USER_PASSWORD);
  await nextTotpPeriod(anna.page);
  await confirm.getByLabel("Code").fill(totp(anna.secret));
  await confirm.getByRole("button", { name: "Confirm" }).click();
  // The replacement went on after the confirmation, without a password: the new code is shown.
  const replacing = anna.page.getByRole("dialog", { name: "Replace the authenticator app" });
  await expect(replacing.getByText("Scan the code with the new authenticator app")).toBeVisible();
  await anna.page.keyboard.press("Escape");
  await expect(replacing).toBeHidden();
});

test("every refusal gives the same answer and leaves no account", async ({ browser }) => {
  await resetRateLimits();
  const { context, page } = await visitor(browser);
  const problems = watchForProblems(page);
  const alert = page.getByRole("alert");
  const attempts: [string, string][] = [
    ["cnoone", USER_PASSWORD], // right password, in no allowed group
    [ANNA.username, "wrong-password-typed"], // known name, wrong password
    ["nobody-here", USER_PASSWORD], // unknown name
  ];
  const timings: number[] = [];
  for (const [name, password] of attempts) {
    const started = Date.now();
    await directorySignIn(page, name, password);
    await expect(alert).toHaveText(REFUSAL);
    timings.push(Date.now() - started);
  }
  // A refusal takes about a second, whatever the reason.
  for (const ms of timings) expect(ms).toBeGreaterThan(900);
  expect(await sql('select 1 from "user" where email like $1', ["cnoone%"])).toHaveLength(0);
  const failed = (await auditOf("auth.directory_sign_in")).filter((e) => e.data.outcome === "failure");
  expect(failed.map((e) => e.data.reason)).toEqual([
    "not-allowed",
    "invalid-credentials",
    "invalid-credentials",
  ]);
  // The audit log names the directory entry of a known name and never the typed text.
  expect(failed[1]?.data.dn).toBe("CN=Anna Smith,OU=Users,DC=example,DC=lan");
  expect(JSON.stringify(failed)).not.toContain("wrong-password-typed");
  expect(JSON.stringify(failed)).not.toContain("nobody-here");
  // Anna's failed attempt is attributed to her account, so the admins see it.
  expect(failed[1]?.actor_user_id).not.toBeNull();
  expect(problems).toEqual([]);
  await context.close();
});

test("after three wrong passwords for a name nothing more reaches the directory", async ({ browser }) => {
  await resetRateLimits();
  await control("/reset");
  const { context, page } = await visitor(browser);
  for (let i = 0; i < 3; i++) {
    await directorySignIn(page, "ghost", `guess-${i}-long`);
    await expect(page.getByRole("alert")).toHaveText(REFUSAL);
  }
  const before = (await state()).seen.length;
  await directorySignIn(page, "ghost", USER_PASSWORD);
  await expect(page.getByRole("alert")).toHaveText("Too many attempts. Wait a minute and try again.");
  expect((await state()).seen.length).toBe(before);
  // Nobody else is affected.
  expect(await sql("select 1 from rate_limit where key like 'ldap:user:%'")).toHaveLength(1);
  await resetRateLimits();
  await context.close();
});

test.describe("the team page", () => {
  test.use({ storageState: STATE_FILE });

  test("shows where each account comes from, and the role of a directory account is read-only", async ({
    page,
  }) => {
    const problems = watchForProblems(page);
    await page.goto("/team");
    const table = page.getByRole("table");
    await expect(table.getByRole("columnheader", { name: "Source" })).toBeVisible();
    const row = table.getByRole("row").filter({ hasText: ANNA.email });
    await expect(row.getByText("Directory", { exact: true }).locator("visible=true")).toBeVisible();
    await expect(row.getByTestId("role-from-groups")).toHaveText("Set by the directory groups");
    // The role is shown in a select that cannot be changed, and there is no remove button: the directory decides.
    const role = row.getByRole("combobox", { name: `Role of ${ANNA.name}` });
    await expect(role).toBeDisabled();
    await expect(role).toHaveValue("member");
    await expect(row.getByRole("button", { name: /^Remove / })).toHaveCount(0);
    const owner = table.getByRole("row").filter({ hasText: "owner@e2e.test" });
    await expect(owner.getByText("Local", { exact: true }).locator("visible=true")).toBeVisible();

    // The API says the same, whatever a client sends.
    const id = (await sql<{ id: string }>('select id from "user" where email = $1', [ANNA.email]))[0]?.id;
    await signedInAt("now");
    const change = await page.request.patch(`/api/v1/team/members/${id}`, {
      headers: ORIGIN,
      data: { role: "admin" },
    });
    expect(change.status()).toBe(409);
    expect((await change.json()).type).toContain("managed-by-directory");
    const remove = await page.request.delete(`/api/v1/team/members/${id}`, { headers: ORIGIN });
    expect(remove.status()).toBe(409);
    expect(await roleOf(ANNA.email)).toBe("member");
    expect(await hasNoHorizontalScroll(page)).toBe(true);
    expect(problems).toEqual([]);
  });
});

test("a role change in the directory applies at the next sign-in, and the periodic check ends an open session", async () => {
  if (!anna) throw new Error("the first sign-in did not run");
  // Anna becomes an admin in the directory.
  await control("/groups", { user: "asmith", groups: ["admins"] });
  await signOut(anna.page);
  await nextTotpPeriod(anna.page);
  await directorySignIn(anna.page, ANNA.username, USER_PASSWORD);
  await anna.page.getByLabel("Code").fill(totp(anna.secret));
  await anna.page.getByRole("button", { name: "Verify" }).click();
  await expect(anna.page.getByRole("heading", { name: "Overview" })).toBeVisible();
  expect(await roleOf(ANNA.email)).toBe("admin");
  // As an admin she sees the Team page.
  await anna.page.goto("/team");
  await expect(anna.page.getByRole("heading", { name: "Team", level: 1 })).toBeVisible();
  expect((await auditOf("directory.role_changed")).at(-1)?.data).toMatchObject({
    before: "member",
    after: "admin",
    via: "sign-in",
  });

  // She leaves every allowed group while her session is open: the periodic check ends her access.
  await control("/groups", { user: "asmith", groups: [] });
  await control("/reconcile");
  expect(await roleOf(ANNA.email)).toBeNull();
  expect(
    await sql('select 1 from session s join "user" u on u.id = s.user_id where u.email = $1', [ANNA.email]),
  ).toHaveLength(0);
  const removed = (await auditOf("directory.access_removed")).at(-1);
  expect(removed?.data).toMatchObject({ before: "admin", via: "check" });
  await anna.page.reload();
  await expect(anna.page).toHaveURL(/\/sign-in$/);

  // Signing in is refused too, like for anyone in no allowed group.
  await directorySignIn(anna.page, ANNA.username, USER_PASSWORD);
  await expect(anna.page.getByRole("alert")).toHaveText(REFUSAL);

  // Back in a group: the same account comes back, with its second factor.
  await resetRateLimits();
  await control("/groups", { user: "asmith", groups: ["users"] });
  await nextTotpPeriod(anna.page);
  await directorySignIn(anna.page, ANNA.username, USER_PASSWORD);
  await anna.page.getByLabel("Code").fill(totp(anna.secret));
  await anna.page.getByRole("button", { name: "Verify" }).click();
  await expect(anna.page.getByRole("heading", { name: "Overview" })).toBeVisible();
  expect(await roleOf(ANNA.email)).toBe("member");
  expect(await auditOf("directory.access_restored")).not.toHaveLength(0);
});

test.describe("linking an existing account", () => {
  test.use({ storageState: STATE_FILE });

  test("an account with the same address is refused with an entry for the admins, until an owner links it", async ({
    page,
    browser,
  }) => {
    await resetRateLimits();
    // A local member whose address is the directory's address for Local Person.
    await signedInAt("now");
    const invite = await page.request.post("/api/v1/team/invitations", {
      headers: ORIGIN,
      data: { email: LOCAL.email, role: "viewer" },
    });
    expect(invite.status()).toBe(201);
    const link = ((await invite.json()) as { link: string }).link;
    const joiner = await visitor(browser);
    await joiner.page.goto(new URL(link).pathname + new URL(link).hash);
    await joiner.page.getByLabel("Your name").fill(LOCAL.name);
    await joiner.page.getByLabel("Choose a password").fill(LOCAL.password);
    await joiner.page.getByRole("button", { name: "Join" }).click();
    await expect(joiner.page.getByRole("link", { name: "Sign in" })).toBeVisible();
    await joiner.context.close();

    // The person signs in with the directory: refused, nothing linked, and the audit log says why.
    const { context, page: person } = await visitor(browser);
    await directorySignIn(person, LOCAL.username, USER_PASSWORD);
    await expect(person.getByRole("alert")).toHaveText(REFUSAL);
    expect(
      await sql('select 1 from directory_identity di join "user" u on u.id = di.user_id where u.email = $1', [
        LOCAL.email,
      ]),
    ).toHaveLength(0);
    const entry = (await auditOf("auth.directory_sign_in")).at(-1);
    expect(entry?.data).toMatchObject({ outcome: "failure", reason: "email-collision", email: LOCAL.email });
    expect(String(entry?.data.hint)).toContain("Link the account");

    // The owner looks the person up, sees that the address matches, and links the account.
    await page.goto("/team");
    const row = page.getByRole("table").getByRole("row").filter({ hasText: LOCAL.email });
    await expect(row.getByText("Local", { exact: true }).locator("visible=true")).toBeVisible();
    await row.getByRole("button", { name: `Link ${LOCAL.name} to the directory` }).click();
    const dialog = page.getByRole("dialog", { name: `Link ${LOCAL.name} to the directory` });
    await dialog.getByLabel("Directory user name").fill(LOCAL.username);
    await dialog.getByRole("button", { name: "Look up" }).click();
    const found = dialog.getByTestId("link-result");
    await expect(found).toContainText("CN=Local Person,OU=Users,DC=example,DC=lan");
    await expect(found.getByText("Same address")).toBeVisible();
    await expect(found).toContainText("After linking: the account signs in with the directory");
    await signedInAt("now");
    await dialog.getByRole("button", { name: "Link account" }).click();
    await expect(
      page.getByRole("status").filter({ hasText: `${LOCAL.name} now signs in with the directory.` }),
    ).toBeVisible();
    await expect(row.getByText("Directory", { exact: true }).locator("visible=true")).toBeVisible();
    // Viewers cannot be raised by the link: the role is the one of the groups (member).
    expect(await roleOf(LOCAL.email)).toBe("member");
    expect(
      await sql('select 1 from account a join "user" u on u.id = a.user_id where u.email = $1', [
        LOCAL.email,
      ]),
    ).toHaveLength(0);
    expect((await auditOf("directory.account_linked")).at(-1)?.data).toMatchObject({
      email: LOCAL.email,
      before: "viewer",
      after: "member",
    });

    // The local password no longer works; the directory does.
    await resetRateLimits();
    await person.goto("/sign-in");
    await person.getByLabel("Email").fill(LOCAL.email);
    await person.getByLabel("Password").fill(LOCAL.password);
    await person.getByRole("button", { name: "Sign in", exact: true }).click();
    await expect(person.getByRole("alert")).toHaveText("Email or password is not correct.");
    await directorySignIn(person, LOCAL.username, USER_PASSWORD);
    await expect(person).toHaveURL(/\/enroll$/);
    await context.close();
  });

  test("an owner cannot be linked", async ({ page }) => {
    await signedInAt("now");
    const ownerId = (
      await sql<{ id: string }>('select id from "user" where email = $1', ["owner@e2e.test"])
    )[0]?.id;
    const answer = await page.request.post("/api/v1/directory/link", {
      headers: ORIGIN,
      data: { userId: ownerId, username: "jdoe" },
    });
    expect(answer.status()).toBe(409);
    expect((await answer.json()).type).toContain("owner");
  });
});

test.describe("pinning a server certificate", () => {
  test.use({ storageState: STATE_FILE });

  test("the certificate is confirmed on first contact, a different one is refused, the old one works again", async ({
    page,
    browser,
  }) => {
    const problems = watchForProblems(page);
    await resetRateLimits();
    const directory = await state();
    await page.goto("/settings?section=signin");
    await page.getByLabel("Pin the server certificate").check();
    await signedInAt("now");
    await form(page).getByRole("button", { name: "Save" }).click();
    await expect(page.getByRole("status").filter({ hasText: "Saved." }).first()).toBeVisible();

    // The certificate was read without sending anything; the owner compares the fingerprint and confirms it.
    const card = page
      .locator("section")
      .filter({ has: page.getByRole("heading", { name: "Certificates", level: 2 }) });
    await expect(card.getByText("Not confirmed")).toBeVisible();
    await card.getByRole("button", { name: "Confirm certificate" }).click();
    const dialog = page.getByRole("dialog", { name: "Confirm the server's certificate" });
    await expect(dialog.getByTestId("fingerprint")).toHaveText(directory.fingerprintA);
    await signedInAt("now");
    await dialog.getByRole("button", { name: "Confirm this certificate" }).click();
    await expect(card.getByText("Pinned", { exact: true })).toBeVisible();
    await expect(card).toContainText(directory.fingerprintA);
    expect((await auditOf("directory.certificate_confirmed")).at(-1)?.data).toMatchObject({
      fingerprint: directory.fingerprintA,
    });
    // Changing how the server is trusted switched the sign-in off: untested settings never go live.
    expect((await sql<{ enabled: boolean }>("select enabled from ldap_config"))[0]?.enabled).toBe(false);

    await page.locator("#directory-test-user").fill("jdoe");
    await page.getByTestId("directory-test").click();
    await expect(page.getByTestId("directory-test-result").getByText("Works", { exact: true })).toBeVisible();
    await page.getByTestId("directory-enabled").check();
    await signedInAt("now");
    await form(page).getByRole("button", { name: "Save" }).click();
    await expect(page.getByRole("status").filter({ hasText: "Saved." }).first()).toBeVisible();
    expect((await sql<{ enabled: boolean }>("select enabled from ldap_config"))[0]?.enabled).toBe(true);

    // The server now presents another certificate: refused before anything is sent, and shown to the owner.
    await control("/certificate", { which: "B" });
    await control("/reset");
    await page.getByTestId("directory-test").click();
    const result = page.getByTestId("directory-test-result");
    await expect(result.getByText("Does not work yet")).toBeVisible();
    await expect(result).toContainText("The server shows another certificate than the pinned one.");
    expect((await state()).seen.filter((s) => s.op === "bind")).toHaveLength(0);
    await page.reload();
    await expect(page.getByText("Changed", { exact: true })).toBeVisible();
    await expect(page.getByRole("button", { name: "Review change" })).toBeVisible();
    expect(await auditOf("directory.certificate_changed")).toHaveLength(1);

    // Signing in through it is refused; the person is told the directory is not available.
    const visitorBrowser = await visitor(browser);
    await directorySignIn(visitorBrowser.page, "bwilson", USER_PASSWORD);
    await expect(visitorBrowser.page.getByRole("alert")).toContainText(
      "The directory cannot be reached right now.",
    );

    // The old certificate is back: the alarm clears itself.
    await control("/certificate", { which: "A" });
    await page.getByTestId("directory-test").click();
    await expect(page.getByTestId("directory-test-result").getByText("Works", { exact: true })).toBeVisible();
    await page.reload();
    await expect(page.getByText("Pinned", { exact: true })).toBeVisible();
    await resetRateLimits();
    await directorySignIn(visitorBrowser.page, "bwilson", USER_PASSWORD);
    await expect(visitorBrowser.page).toHaveURL(/\/enroll$/);
    await visitorBrowser.context.close();
    expect(problems).toEqual([]);
  });
});
