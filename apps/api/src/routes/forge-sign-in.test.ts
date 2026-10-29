/**
 * Signing in to forges (ADR 0031) against a throw-away PostgreSQL database on the development server: who may register
 * sign-in applications, that client secrets are only sealed, the authorization URL with state and PKCE, and that a
 * callback only finishes the caller's own, unused, fresh sign-in, once. Sessions are replaced by a header-driven actor;
 * the queue is a recorder. Skipped without the development PostgreSQL.
 */
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();

const holder = vi.hoisted(() => ({
  db: null as unknown,
  sent: [] as { name: string; data: Record<string, unknown> }[],
}));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null, boss: null, QUEUES: {} };
  const t = await create(target, "api_sign_in");
  holder.db = t;
  return {
    db: t.db,
    pool: t.pool,
    boss: {
      send: async (name: string, data: Record<string, unknown>) => {
        holder.sent.push({ name, data });
        return "job";
      },
    },
    QUEUES: {
      scanRepository: "scan.repository",
      fixPrCreate: "fix-pr.create",
      fixPrCheck: "fix-pr.check",
      fixPrRefresh: "fix-pr.refresh",
      forgeConnectionRefresh: "forge-connection.refresh",
      forgeSignIn: "forge-sign-in.run",
    },
  };
});
vi.mock("../env.ts", async () => {
  const { generateVaultKeyPair: gen, loadVaultPublicKey: load } = await import("@garnetops/core/vault");
  return {
    env: { PUBLIC_URL: "https://garnetops.example.test/" },
    isProduction: false,
    vaultPublicKey: load(gen().publicKeyPem),
  };
});
vi.mock("../auth.ts", () => ({ auth: { api: {} } }));

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
type Role = "owner" | "admin" | "member" | "viewer";
const ORG = "org_vis";
/** Alex owns the private repository; Sam is another member; Kim is an admin. */
const ALEX = { user: "user_alex", role: "member" as Role };
const SAM = { user: "user_sam", role: "member" as Role };
const KIM = { user: "user_kim", role: "admin" as Role };
const CLIENT_SECRET = ["gto_", "NotARealClientSecret0123"].join("");

describe.skipIf(!adminUrl)("signing in to forges", () => {
  let t: TestDatabase;
  let app: Hono;

  async function call(method: string, path: string, who: { user: string; role: Role }, body?: unknown) {
    const res = await app.request(path, {
      method,
      headers: {
        "x-user": who.user,
        "x-role": who.role,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    let json: Json | null = null;
    try {
      json = text ? (JSON.parse(text) as Json) : null;
    } catch {
      json = null;
    }
    return { status: res.status, json, text };
  }

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { forgeAppRoutes, forgeSignInRoutes } = await import("./forge-sign-in.ts");
    t = holder.db as TestDatabase;
    await t.db.insert(schema.organization).values({ id: ORG, name: "Example" });
    await t.db.insert(schema.user).values([
      { id: ALEX.user, name: "Alex Example", email: "alex@example.test" },
      { id: SAM.user, name: "Sam Example", email: "sam@example.test" },
      { id: KIM.user, name: "Kim Example", email: "kim@example.test" },
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
          ip: null,
          strongAuthAt: new Date(),
        } as never,
      );
      await next();
    });
    v1.route("/forge-apps", forgeAppRoutes as never);
    v1.route("/forge-sign-in", forgeSignInRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  }, 60_000);

  beforeEach(async () => {
    holder.sent.length = 0;
    await t.db.delete(schema.rateLimit);
  });

  let giteaApp = "";
  let githubApp = "";

  it("lets owners and admins register sign-in applications, and seals the client secret", async () => {
    const body = {
      forgeKind: "gitea",
      webBaseUrl: "https://git.example.lan/",
      clientId: "client-0123",
      clientSecret: CLIENT_SECRET,
    };
    expect((await call("POST", "/api/v1/forge-apps", ALEX, body)).status).toBe(403);
    const created = await call("POST", "/api/v1/forge-apps", KIM, body);
    expect(created.status).toBe(201);
    expect(created.json).toMatchObject({
      forgeKind: "gitea",
      webBaseUrl: "https://git.example.lan",
      apiBaseUrl: "https://git.example.lan/api/v1",
      hasSecret: true,
      flow: "code",
    });
    giteaApp = created.json?.id as string;
    const github = await call("POST", "/api/v1/forge-apps", KIM, {
      forgeKind: "github",
      webBaseUrl: "https://github.com",
      clientId: "Iv23liExampleClient",
    });
    expect(github.json).toMatchObject({
      apiBaseUrl: "https://api.github.com",
      hasSecret: false,
      flow: "device",
    });
    githubApp = github.json?.id as string;
    expect((await call("POST", "/api/v1/forge-apps", KIM, body)).status).toBe(409);
    for (const webBaseUrl of ["http://git.example.lan", "https://169.254.169.254"]) {
      expect((await call("POST", "/api/v1/forge-apps", KIM, { ...body, webBaseUrl })).status).toBe(422);
    }

    const list = await call("GET", "/api/v1/forge-apps", KIM);
    expect(list.json?.redirectUri).toBe("https://garnetops.example.test/settings/accounts/callback");
    expect(list.text).not.toContain(CLIENT_SECRET);
    const [secret] = await t.db
      .select()
      .from(schema.secret)
      .where(eq(schema.secret.purpose, "forge-app-secret"));
    expect(JSON.stringify(secret?.sealed)).not.toContain(CLIENT_SECRET);
    expect((await call("GET", "/api/v1/forge-apps", ALEX)).status).toBe(403);
    // Members see what they can sign in with, nothing about the client.
    const available = await call("GET", "/api/v1/forge-apps/available", ALEX);
    expect(available.json).toEqual([
      { id: giteaApp, forgeKind: "gitea", webBaseUrl: "https://git.example.lan", flow: "code" },
      { id: githubApp, forgeKind: "github", webBaseUrl: "https://github.com", flow: "device" },
    ]);
  });

  it("starts a code flow with state and PKCE, and finishes it only for the caller, once", async () => {
    expect(
      (await call("POST", "/api/v1/forge-sign-in", { user: "user_v", role: "viewer" }, { appId: giteaApp }))
        .status,
    ).toBe(403);
    const started = await call("POST", "/api/v1/forge-sign-in", ALEX, { appId: giteaApp });
    expect(started.status).toBe(201);
    const url = new URL(started.json?.authorizeUrl as string);
    expect(url.origin + url.pathname).toBe("https://git.example.lan/login/oauth/authorize");
    const params = Object.fromEntries(url.searchParams);
    expect(params).toMatchObject({
      client_id: "client-0123",
      redirect_uri: "https://garnetops.example.test/settings/accounts/callback",
      code_challenge_method: "S256",
      scope: "read:repository read:user",
    });
    expect(params.state).toMatch(/^[A-Za-z0-9_-]{43}$/);
    // Only a hash of the state is stored.
    expect(JSON.stringify(await t.db.select().from(schema.forgeSignIn))).not.toContain(params.state);
    expect(holder.sent).toEqual([]);

    const callback = (who: { user: string; role: Role }, state: string) =>
      call("POST", "/api/v1/forge-sign-in/callback", who, { state, code: "code-from-forge" });
    expect((await callback(ALEX, "x".repeat(43))).status).toBe(409);
    expect((await callback(SAM, params.state as string)).status).toBe(409);
    const done = await callback(ALEX, params.state as string);
    expect(done.status).toBe(202);
    expect(holder.sent).toEqual([{ name: "forge-sign-in.run", data: { signInId: started.json?.id } }]);
    expect((await callback(ALEX, params.state as string)).status).toBe(409);
    const [row] = await t.db
      .select()
      .from(schema.forgeSignIn)
      .where(eq(schema.forgeSignIn.id, started.json?.id));
    expect(row).toMatchObject({ state: "exchanging", stateHash: null });
    expect(JSON.stringify(await t.db.select().from(schema.secret))).not.toContain("code-from-forge");

    // Someone else's sign-in is not found.
    expect((await call("GET", `/api/v1/forge-sign-in/${started.json?.id}`, SAM)).status).toBe(404);
    expect((await call("GET", `/api/v1/forge-sign-in/${started.json?.id}`, ALEX)).json).toMatchObject({
      flow: "code",
      state: "exchanging",
    });
  });

  it("records a declined sign-in and drops its verifier", async () => {
    const started = await call("POST", "/api/v1/forge-sign-in", ALEX, { appId: giteaApp });
    const state = new URL(started.json?.authorizeUrl as string).searchParams.get("state") as string;
    const r = await call("POST", "/api/v1/forge-sign-in/callback", ALEX, { state, error: "access_denied" });
    expect(r.status).toBe(200);
    const [row] = await t.db
      .select()
      .from(schema.forgeSignIn)
      .where(eq(schema.forgeSignIn.id, started.json?.id));
    expect(row).toMatchObject({ state: "failed", problem: "denied", verifierSecretId: null });
  });

  it("starts a device flow in the worker, and lets the caller cancel it", async () => {
    const started = await call("POST", "/api/v1/forge-sign-in", ALEX, { appId: githubApp });
    expect(started.json).toEqual({ id: expect.any(String), flow: "device" });
    expect(holder.sent).toEqual([{ name: "forge-sign-in.run", data: { signInId: started.json?.id } }]);
    expect((await call("DELETE", `/api/v1/forge-sign-in/${started.json?.id}`, SAM)).status).toBe(404);
    expect((await call("DELETE", `/api/v1/forge-sign-in/${started.json?.id}`, ALEX)).status).toBe(204);
    expect((await call("GET", `/api/v1/forge-sign-in/${started.json?.id}`, ALEX)).status).toBe(404);
  });

  it("removes an application and its sealed secret", async () => {
    expect((await call("DELETE", `/api/v1/forge-apps/${giteaApp}`, KIM)).status).toBe(204);
    expect(
      await t.db.select().from(schema.secret).where(eq(schema.secret.purpose, "forge-app-secret")),
    ).toEqual([]);
    const audit = await t.db.select().from(schema.auditLog);
    expect(audit.map((a) => a.action)).toEqual(
      expect.arrayContaining(["forge_app.added", "forge_app.removed"]),
    );
    expect(JSON.stringify(audit)).not.toContain(CLIENT_SECRET);
  });
});
