/**
 * Scan on push (ADR 0045) against a throw-away PostgreSQL database on the development server: who may switch the webhook on,
 * that address and secret are shown once and the secret is stored encrypted, that a delivery is read only after its HMAC
 * matches, which pushes queue a scan, and what the forge and the repository page are told. Sessions are replaced by a
 * header-driven actor; the job queue by a stand-in. Skipped without the development PostgreSQL.
 */
import { createHmac } from "node:crypto";
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();
const shared = vi.hoisted(() => ({ db: null as unknown, sent: [] as unknown[], privateKeyPem: "" }));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  const boss = { send: async (...args: unknown[]) => shared.sent.push(args) };
  const QUEUES = {
    scanRepository: "scan-repository",
    webhookRegister: "repository-webhook.register",
    webhookUnregister: "repository-webhook.unregister",
  };
  if (!target) return { db: null, pool: null, boss, QUEUES };
  const t = await create(target, "api_webhooks");
  shared.db = t;
  return { db: t.db, pool: t.pool, boss, QUEUES };
});
vi.mock("../env.ts", async () => {
  const { generateVaultKeyPair: gen, loadVaultPublicKey: load } = await import("@garnetops/core/vault");
  const pair = gen();
  // Only the test opens what the API sealed, to check it; the API itself never gets the private key.
  shared.privateKeyPem = pair.privateKeyPem;
  return {
    env: { BETTER_AUTH_SECRET: "b".repeat(48), PUBLIC_URL: "https://garnetops.example.com" },
    isProduction: false,
    vaultPublicKey: load(pair.publicKeyPem),
  };
});
vi.mock("../auth.ts", () => ({ auth: { api: {} } }));

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
type Role = "owner" | "admin" | "member" | "viewer";
const ORG = "org_hook";
const REPO = "repo_hook";
const PRIVATE = "repo_hook_private";
const STALE = 11 * 60;

describe.skipIf(!adminUrl)("Scan on push", () => {
  let t: TestDatabase;
  let app: Hono;

  async function call(
    method: string,
    path: string,
    opts: { role?: Role; user?: string; age?: number; body?: unknown } = {},
  ) {
    const res = await app.request(`/api/v1${path}`, {
      method,
      headers: {
        "x-role": opts.role ?? "admin",
        "x-user": opts.user ?? "user_hook_a",
        "x-age": String(opts.age ?? 0),
        ...(opts.body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    });
    const text = await res.text();
    return { status: res.status, json: (text ? JSON.parse(text) : null) as Json | null };
  }

  async function deliver(
    pathId: string,
    body: unknown,
    opts: { secret?: string; event?: string; forge?: "github" | "gitea"; raw?: string } = {},
  ) {
    const text = opts.raw ?? JSON.stringify(body);
    const sig = createHmac("sha256", opts.secret ?? "")
      .update(text)
      .digest("hex");
    const headers: Record<string, string> =
      opts.forge === "gitea"
        ? { "x-gitea-event": opts.event ?? "push", "x-gitea-signature": sig }
        : { "x-github-event": opts.event ?? "push", "x-hub-signature-256": `sha256=${sig}` };
    const res = await app.request(`/api/v1/hooks/${pathId}`, {
      method: "POST",
      headers: { ...headers, "content-type": "application/json", "x-real-ip": "198.51.100.9" },
      body: text,
    });
    return { status: res.status, json: (await res.json()) as Json };
  }

  const pathOf = (url: string) => url.split("/").pop() as string;
  const push = (ref: string) => ({ ref, repository: { default_branch: "main" } });

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { webhookRoutes, webhookDeliveryRoutes } = await import("./webhooks.ts");
    t = shared.db as TestDatabase;
    await t.db.insert(schema.organization).values({ id: ORG, name: "A" });
    await t.db.insert(schema.user).values([
      { id: "user_hook_a", name: "Erika", email: "erika@example.test" },
      { id: "user_hook_b", name: "Max", email: "max@example.test" },
    ]);
    await t.db.insert(schema.repository).values([
      {
        id: REPO,
        organizationId: ORG,
        name: "app",
        url: "https://git.example.com/team/app.git",
        authKind: "none",
      },
      {
        id: PRIVATE,
        organizationId: ORG,
        name: "mine",
        url: "https://git.example.com/max/mine.git",
        authKind: "none",
        visibility: "private",
        ownerUserId: "user_hook_b",
        branch: "release",
      },
    ]);
    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        {
          userId: c.req.header("x-user"),
          email: "someone@example.test",
          name: "Someone",
          organizationId: ORG,
          role: c.req.header("x-role"),
          ip: "198.51.100.7",
          strongAuthAt: new Date(Date.now() - Number(c.req.header("x-age") ?? 0) * 1000),
        } as never,
      );
      await next();
    });
    v1.route("/repositories/:id/webhook", webhookRoutes as never);
    app = new Hono()
      .onError(handleError)
      .route("/api/v1/hooks", webhookDeliveryRoutes)
      .route("/api/v1", v1) as unknown as Hono;
  }, 60_000);
  afterAll(async () => {
    await t?.drop();
  });
  beforeEach(async () => {
    await t.db.delete(schema.repositoryWebhook);
    await t.db.delete(schema.forgeConnection);
    await t.db.delete(schema.secret);
    await t.db.delete(schema.auditLog);
    await t.db.delete(schema.scan);
    await t.db.delete(schema.rateLimit);
    await t.db.update(schema.repository).set({ inactiveAt: null });
    shared.sent.length = 0;
  });

  it("is switched on by admins or the owner of a private repository, with a recent sign-in", async () => {
    expect((await call("POST", `/repositories/${REPO}/webhook`, { role: "member" })).status).toBe(403);
    const stale = await call("POST", `/repositories/${REPO}/webhook`, { age: STALE });
    expect(stale.status).toBe(403);
    expect(stale.json?.type).toMatch(/step-up-required/);
    // A member may switch it on for their own private repository.
    const own = await call("POST", `/repositories/${PRIVATE}/webhook`, {
      role: "member",
      user: "user_hook_b",
    });
    expect(own.status).toBe(201);
    expect(own.json?.url).toMatch(/^https:\/\/garnetops\.example\.com\/api\/v1\/hooks\/[A-Za-z0-9_-]{43}$/);
    expect(own.json?.secret).toMatch(/^[A-Za-z0-9_-]{43}$/);
  });

  it("stores the secret encrypted, shows it once, and replaces address and secret together", async () => {
    const first = await call("POST", `/repositories/${REPO}/webhook`);
    const [row] = await t.db.select().from(schema.repositoryWebhook);
    expect(row?.secretSealed).not.toContain(first.json?.secret);
    expect(row?.pathId).not.toBe(REPO);
    const view = await call("GET", `/repositories/${REPO}/webhook`);
    expect(view.json).toMatchObject({ enabled: true, canManage: true, url: first.json?.url });
    expect(JSON.stringify(view.json)).not.toContain(first.json?.secret);
    // Members see that it is on, not where it is.
    expect((await call("GET", `/repositories/${REPO}/webhook`, { role: "member" })).json).toMatchObject({
      enabled: true,
      canManage: false,
      url: null,
    });
    const second = await call("POST", `/repositories/${REPO}/webhook`);
    expect(second.json?.url).not.toBe(first.json?.url);
    expect(
      (await deliver(pathOf(first.json?.url), push("refs/heads/main"), { secret: first.json?.secret }))
        .status,
    ).toBe(404);
    const actions = (await t.db.select().from(schema.auditLog)).map((a) => a.action);
    expect(actions).toEqual(
      expect.arrayContaining(["repository.webhook_created", "repository.webhook_replaced"]),
    );
  });

  it("queues a scan for a signed push to the scanned branch, once, and says why it did nothing otherwise", async () => {
    const { json } = await call("POST", `/repositories/${REPO}/webhook`);
    const path = pathOf(json?.url);
    const secret = json?.secret as string;

    expect(await deliver(path, push("refs/heads/main"), { secret })).toEqual({
      status: 202,
      json: { result: "scan-queued" },
    });
    expect(shared.sent).toHaveLength(1);
    const [scan] = await t.db.select().from(schema.scan);
    expect(scan).toMatchObject({
      repositoryId: REPO,
      trigger: "webhook",
      state: "queued",
      requestedBy: null,
    });
    // A second push while it waits does not queue another.
    expect((await deliver(path, push("refs/heads/main"), { secret, forge: "gitea" })).json.result).toBe(
      "already-queued",
    );
    expect((await deliver(path, push("refs/heads/feature"), { secret })).json.result).toBe("ignored-branch");
    expect((await deliver(path, {}, { secret, event: "issues" })).json.result).toBe("ignored-event");
    expect((await deliver(path, { zen: "Keep it simple" }, { secret, event: "ping" })).json.result).toBe(
      "ping",
    );
    expect((await deliver(path, { ...push("refs/heads/main"), deleted: true }, { secret })).json.result).toBe(
      "ignored-delete",
    );
    expect(shared.sent).toHaveLength(1);

    const view = await call("GET", `/repositories/${REPO}/webhook`);
    expect(view.json?.deliveries.map((d: Json) => d.result)).toEqual([
      "ignored-delete",
      "ping",
      "ignored-event",
      "ignored-branch",
      "already-queued",
      "scan-queued",
    ]);
  });

  it("reads nothing before the signature matches", async () => {
    const { json } = await call("POST", `/repositories/${REPO}/webhook`);
    const path = pathOf(json?.url);
    expect(await deliver(path, push("refs/heads/main"), { secret: "x".repeat(43) })).toEqual({
      status: 401,
      json: { result: "bad-signature" },
    });
    // The signature covers the exact body.
    const res = await app.request(`/api/v1/hooks/${path}`, {
      method: "POST",
      headers: { "x-github-event": "push", "x-hub-signature-256": "sha256=00" },
      body: "{}",
    });
    expect(res.status).toBe(401);
    expect(shared.sent).toHaveLength(0);
    expect((await deliver("a".repeat(43), push("refs/heads/main"), { secret: json?.secret })).status).toBe(
      404,
    );
    // A path outside the pattern never reaches the database (and "../" never leaves the route).
    expect((await app.request("/api/v1/hooks/not-a-hook", { method: "POST", body: "{}" })).status).toBe(404);
  });

  it("follows the repository's own branch, and an inactive repository is not scanned", async () => {
    const { json } = await call("POST", `/repositories/${PRIVATE}/webhook`, {
      role: "member",
      user: "user_hook_b",
    });
    const path = pathOf(json?.url);
    const secret = json?.secret as string;
    expect((await deliver(path, push("refs/heads/main"), { secret })).json.result).toBe("ignored-branch");
    await t.db
      .update(schema.repository)
      .set({ inactiveAt: new Date() })
      .where(eq(schema.repository.id, PRIVATE));
    expect((await deliver(path, push("refs/heads/release"), { secret })).json.result).toBe("inactive");
    expect(shared.sent).toHaveLength(0);
  });

  it("is limited per webhook", async () => {
    const { json } = await call("POST", `/repositories/${REPO}/webhook`);
    const path = pathOf(json?.url);
    let last = 0;
    for (let i = 0; i < 61; i++)
      last = (await deliver(path, {}, { secret: json?.secret, event: "ping" })).status;
    expect(last).toBe(429);
  });

  it("is switched off by deleting it; the old address answers nobody", async () => {
    const { json } = await call("POST", `/repositories/${REPO}/webhook`);
    expect((await call("DELETE", `/repositories/${REPO}/webhook`, { role: "member" })).status).toBe(403);
    expect((await call("DELETE", `/repositories/${REPO}/webhook`)).status).toBe(204);
    expect((await deliver(pathOf(json?.url), push("refs/heads/main"), { secret: json?.secret })).status).toBe(
      404,
    );
    expect((await call("GET", `/repositories/${REPO}/webhook`)).json).toMatchObject({ enabled: false });
  });

  describe("registering through a connected account", () => {
    let counter = 0;
    const problemCode = (r: { json: Json | null }) =>
      String(r.json?.type ?? "")
        .split("/")
        .pop();

    /** A connection as the worker leaves it after a successful check. */
    async function connect(
      userId: string,
      overrides: Partial<typeof schema.forgeConnection.$inferInsert> = {},
    ): Promise<string> {
      const n = ++counter;
      const secretId = `sec_hookconn${n}`;
      await t.db.insert(schema.secret).values({
        id: secretId,
        organizationId: ORG,
        purpose: "forge-connection-token",
        sealed: {},
        vaultKeyId: "k",
      });
      const id = `fcn_hook${n}`;
      await t.db.insert(schema.forgeConnection).values({
        id,
        organizationId: ORG,
        userId,
        forgeKind: "gitea",
        webBaseUrl: "https://git.example.com",
        apiBaseUrl: "https://git.example.com/api/v1",
        secretId,
        accountLogin: userId === "user_hook_a" ? "erika" : "max",
        state: "ok",
        ...overrides,
      });
      return id;
    }
    const register = (opts: { role?: Role; user?: string; age?: number } = {}, repo = REPO) =>
      call("POST", `/repositories/${repo}/webhook`, { ...opts, body: { register: true } });
    const hookRow = async () => (await t.db.select().from(schema.repositoryWebhook))[0];
    const sentTo = (queue: string) =>
      (shared.sent as unknown[][]).filter((args) => args[0] === queue).map((args) => args[1] as Json);

    it("needs the caller's own connected account on the repository's forge", async () => {
      // Somebody else's connection never counts, for admins neither; nor one on another forge.
      await connect("user_hook_b");
      await connect("user_hook_a", {
        webBaseUrl: "https://git.example.org",
        apiBaseUrl: "https://git.example.org/api/v1",
      });
      const none = await register();
      expect(none.status).toBe(409);
      expect(problemCode(none)).toBe("no-connection");
      expect(await hookRow()).toBeUndefined();
      expect(shared.sent).toHaveLength(0);
      // The other checks come first: who may manage it, and a recent sign-in.
      expect((await register({ role: "member" })).status).toBe(403);
      expect(problemCode(await register({ age: STALE }))).toBe("step-up-required");
    });

    it("a Gitea or Forgejo sign-in needs its write scope", async () => {
      await connect("user_hook_a", { authMethod: "sign-in", writeScope: false });
      const res = await register();
      expect(res.status).toBe(409);
      expect(problemCode(res)).toBe("connection-write-scope-missing");
      expect(await hookRow()).toBeUndefined();
      expect((await call("GET", `/repositories/${REPO}/webhook`)).json?.canRegister).toEqual({
        login: "erika",
        kind: "gitea",
        problem: "write-scope-missing",
      });
    });

    it("seals a copy of the secret for the worker and queues a job with ids only", async () => {
      const connectionId = await connect("user_hook_a", { authMethod: "sign-in", writeScope: true });
      const res = await register();
      expect(res.status).toBe(201);
      expect(res.json).toMatchObject({ registering: true });
      const secret = res.json?.secret as string;
      expect(secret).toMatch(/^[A-Za-z0-9_-]{43}$/);
      const row = await hookRow();
      expect(row).toMatchObject({
        connectionId,
        registerState: "pending",
        forgeHookId: null,
        createdBy: "user_hook_a",
      });
      const [handover] = await t.db
        .select()
        .from(schema.secret)
        .where(eq(schema.secret.id, row?.handoverSecretId as string));
      expect(handover).toMatchObject({ organizationId: ORG, purpose: "webhook-secret" });
      const { loadVaultPrivateKey, open } = await import("@garnetops/core/vault");
      const key = loadVaultPrivateKey(shared.privateKeyPem);
      const binding = {
        organizationId: ORG,
        recordId: handover?.id as string,
        purpose: "webhook-secret" as const,
      };
      expect(open(handover?.sealed as never, binding, key).toString("utf8")).toBe(secret);
      // Bound to its purpose: it does not open as anything else.
      expect(() =>
        open(handover?.sealed as never, { ...binding, purpose: "forge-connection-token" }, key),
      ).toThrow();
      const jobs = sentTo("repository-webhook.register");
      expect(jobs).toEqual([{ webhookId: row?.id, organizationId: ORG, secretId: row?.handoverSecretId }]);
      expect(JSON.stringify(shared.sent)).not.toContain(secret);
      const [audit] = await t.db
        .select()
        .from(schema.auditLog)
        .where(eq(schema.auditLog.action, "repository.webhook_created"));
      expect(audit?.data).toMatchObject({ via: "connection", connection: connectionId });
      expect(JSON.stringify(audit)).not.toContain(secret);
    });

    it("shows how it was registered to those who may manage it, and nothing of it to others", async () => {
      await connect("user_hook_a");
      await register();
      const view = await call("GET", `/repositories/${REPO}/webhook`);
      expect(view.json).toMatchObject({
        enabled: true,
        registration: { state: "pending", reason: null, connection: { login: "erika", kind: "gitea" } },
        canRegister: { login: "erika", kind: "gitea", problem: null },
      });
      await t.db
        .update(schema.repositoryWebhook)
        .set({ registerState: "failed", registerReason: "forbidden" });
      expect((await call("GET", `/repositories/${REPO}/webhook`)).json?.registration).toMatchObject({
        state: "failed",
        reason: "forbidden",
      });
      expect((await call("GET", `/repositories/${REPO}/webhook`, { role: "member" })).json).toMatchObject({
        registration: null,
        canRegister: null,
      });
      // Entered by hand: no registration to show.
      await call("POST", `/repositories/${REPO}/webhook`);
      expect((await call("GET", `/repositories/${REPO}/webhook`)).json?.registration).toBeNull();
    });

    it("the owner of a private repository registers it with their own account", async () => {
      await connect("user_hook_b");
      const res = await register({ role: "member", user: "user_hook_b" }, PRIVATE);
      expect(res.status).toBe(201);
      expect(sentTo("repository-webhook.register")).toHaveLength(1);
    });

    it("switching off or replacing removes the webhook it registered in the forge, with ids only", async () => {
      const connectionId = await connect("user_hook_a");
      await register();
      await t.db
        .update(schema.repositoryWebhook)
        .set({ registerState: "ok", forgeHookId: "42", handoverSecretId: null });
      // An admin switches it off; the job names whose connection registered it, and who asked.
      await connect("user_hook_b");
      expect((await call("DELETE", `/repositories/${REPO}/webhook`, { user: "user_hook_b" })).status).toBe(
        204,
      );
      expect(sentTo("repository-webhook.unregister")).toEqual([
        {
          organizationId: ORG,
          repositoryId: REPO,
          connectionId,
          forgeHookId: "42",
          ownerUserId: "user_hook_a",
          requestedBy: "user_hook_b",
        },
      ]);
      expect(await hookRow()).toBeUndefined();

      shared.sent.length = 0;
      await register();
      await t.db.update(schema.repositoryWebhook).set({ registerState: "ok", forgeHookId: "43" });
      const replaced = await call("POST", `/repositories/${REPO}/webhook`);
      expect(replaced.status).toBe(201);
      expect(replaced.json).toMatchObject({ registering: false });
      expect(sentTo("repository-webhook.unregister").map((j) => j.forgeHookId)).toEqual(["43"]);
      expect(await hookRow()).toMatchObject({ registerState: null, connectionId: null, forgeHookId: null });
    });

    it("replacing a registration that is still pending deletes its handed-over secret", async () => {
      await connect("user_hook_a");
      await register();
      const first = (await hookRow())?.handoverSecretId as string;
      await register();
      const second = (await hookRow())?.handoverSecretId as string;
      expect(second).not.toBe(first);
      const left = await t.db.select().from(schema.secret).where(eq(schema.secret.purpose, "webhook-secret"));
      expect(left.map((x) => x.id)).toEqual([second]);
      // Nothing was registered yet, so nothing is to be removed in the forge.
      expect(sentTo("repository-webhook.unregister")).toHaveLength(0);
      await call("DELETE", `/repositories/${REPO}/webhook`);
      expect(
        await t.db.select().from(schema.secret).where(eq(schema.secret.purpose, "webhook-secret")),
      ).toEqual([]);
    });
  });
});
