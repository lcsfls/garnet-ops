/**
 * Fix pull requests through a personal forge connection (ADR 0039), the switch on the connection, against a throw-away
 * PostgreSQL database on the development server: only the connection's owner can switch it, switching on needs a recent
 * sign-in, the acknowledgement and (for a Gitea/Forgejo sign-in) the write scope, switching off needs neither, both are
 * audited, and a new token turns it off again. Sessions are replaced by a header-driven actor; the queue is a recorder.
 * Skipped without the development PostgreSQL.
 */
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { and, eq } from "drizzle-orm";
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
  const t = await create(target, "api_forge_conn");
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
      forgeConnectionRefresh: "forge-connection.refresh",
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
const ORG = "org_conn";
/** Alex owns the connections; Kim is an owner of the organisation, and still not allowed to touch them. */
const ALEX = { user: "user_alex", role: "member" as Role };
const KIM = { user: "user_kim", role: "owner" as Role };
const STALE = 11 * 60;
const TOKEN = ["glpat-", "NotARealTokenJustFixture0123"].join("");

describe.skipIf(!adminUrl)("pull requests through a connected account", () => {
  let t: TestDatabase;
  let app: Hono;
  let counter = 0;

  async function call(
    method: string,
    path: string,
    who: { user: string; role: Role },
    body?: unknown,
    age = 0,
  ) {
    const res = await app.request(path, {
      method,
      headers: {
        "x-user": who.user,
        "x-role": who.role,
        "x-age": String(age),
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
  const problemCode = (r: { json: Json | null }) =>
    String(r.json?.type ?? "")
      .split("/")
      .pop();

  /** A connection as the worker leaves it after a successful check. */
  async function addConnection(
    userId: string,
    overrides: Partial<typeof schema.forgeConnection.$inferInsert> = {},
  ): Promise<string> {
    const n = ++counter;
    const secretId = `sec_conn${n}`;
    await t.db.insert(schema.secret).values({
      id: secretId,
      organizationId: ORG,
      purpose: "forge-connection-token",
      sealed: {},
      vaultKeyId: "k",
    });
    const id = `fcn_conn${n}`;
    await t.db.insert(schema.forgeConnection).values({
      id,
      organizationId: ORG,
      userId,
      forgeKind: "gitea",
      webBaseUrl: `https://git${n}.example.lan`,
      apiBaseUrl: `https://git${n}.example.lan/api/v1`,
      secretId,
      accountLogin: "alex",
      state: "ok",
      ...overrides,
    });
    return id;
  }
  const connection = async (id: string) =>
    (await t.db.select().from(schema.forgeConnection).where(eq(schema.forgeConnection.id, id)))[0];
  const auditOf = async (id: string) =>
    t.db
      .select()
      .from(schema.auditLog)
      .where(and(eq(schema.auditLog.targetType, "forge_connection"), eq(schema.auditLog.targetId, id)))
      .orderBy(schema.auditLog.createdAt);
  const toggle = (id: string, who: { user: string; role: Role }, body: unknown, age = 0) =>
    call("PUT", `/api/v1/forge-connections/${id}/pull-requests`, who, body, age);

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { forgeConnectionRoutes } = await import("./forge-connections.ts");
    t = holder.db as TestDatabase;
    await t.db.insert(schema.organization).values({ id: ORG, name: "Example" });
    await t.db.insert(schema.user).values([
      { id: ALEX.user, name: "Alex Example", email: "alex@example.test" },
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
          strongAuthAt: new Date(Date.now() - Number(c.req.header("x-age") ?? 0) * 1000),
        } as never,
      );
      await next();
    });
    v1.route("/forge-connections", forgeConnectionRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  }, 60_000);

  beforeEach(async () => {
    holder.sent.length = 0;
    await t.db.delete(schema.rateLimit);
  });

  it("is off for every connection until its owner switches it on", async () => {
    const id = await addConnection(ALEX.user);
    const list = await call("GET", "/api/v1/forge-connections", ALEX);
    expect(list.json?.find((c: Json) => c.id === id)).toMatchObject({
      pullRequests: false,
      pullRequestsAt: null,
      writeScope: false,
      needsWriteSignIn: false,
    });
  });

  it("only the owner can switch it, for owners and admins of the organisation too", async () => {
    const id = await addConnection(ALEX.user);
    for (const body of [{ enabled: true, acknowledged: true }, { enabled: false }]) {
      const r = await toggle(id, KIM, body);
      expect([r.status, problemCode(r)]).toEqual([404, "not-found"]);
    }
    expect(await connection(id)).toMatchObject({ pullRequests: false });
    expect(await auditOf(id)).toEqual([]);
    const r = await toggle(id, ALEX, { enabled: true, acknowledged: true });
    expect(r.status).toBe(200);
    expect(r.json).toMatchObject({ id, pullRequests: true });
    expect((await connection(id))?.pullRequestsAt).toBeInstanceOf(Date);
  });

  it("switching on needs a recent sign-in and the acknowledgement; viewers cannot", async () => {
    const id = await addConnection(ALEX.user);
    const stale = await toggle(id, ALEX, { enabled: true, acknowledged: true }, STALE);
    expect([stale.status, problemCode(stale)]).toEqual([403, "step-up-required"]);
    for (const body of [{ enabled: true }, { enabled: true, acknowledged: false }]) {
      const r = await toggle(id, ALEX, body);
      expect([r.status, problemCode(r)]).toEqual([422, "acknowledgement-required"]);
    }
    const viewer = await toggle(
      id,
      { user: ALEX.user, role: "viewer" },
      { enabled: true, acknowledged: true },
    );
    expect(viewer.status).toBe(403);
    for (const bad of [{}, { enabled: "yes" }, { enabled: 1, acknowledged: true }]) {
      expect((await toggle(id, ALEX, bad)).status, JSON.stringify(bad)).toBe(422);
    }
    expect(await connection(id)).toMatchObject({ pullRequests: false, pullRequestsAt: null });
    expect(await auditOf(id)).toEqual([]);
  });

  it("is audited both ways; switching off needs neither a recent sign-in nor the acknowledgement", async () => {
    const id = await addConnection(ALEX.user);
    expect((await toggle(id, ALEX, { enabled: true, acknowledged: true })).status).toBe(200);
    // The same state again changes nothing and writes no second entry.
    expect((await toggle(id, ALEX, { enabled: true, acknowledged: true })).status).toBe(200);
    const off = await toggle(id, { user: ALEX.user, role: "viewer" }, { enabled: false }, STALE);
    expect(off.status).toBe(200);
    expect(off.json).toMatchObject({ pullRequests: false, pullRequestsAt: null });
    const audit = await auditOf(id);
    expect(audit.map((a) => a.action)).toEqual([
      "forge_connection.pull_requests_enabled",
      "forge_connection.pull_requests_disabled",
    ]);
    expect(audit[0]).toMatchObject({ organizationId: ORG, actorUserId: ALEX.user });
    expect(audit[0]?.data).toMatchObject({ forge: "gitea", auth: "token", account: "alex" });
  });

  it("a Gitea or Forgejo sign-in needs the write scope first; a GitHub App and a pasted token do not", async () => {
    const signedIn = await addConnection(ALEX.user, { authMethod: "sign-in" });
    const list = await call("GET", "/api/v1/forge-connections", ALEX);
    expect(list.json?.find((c: Json) => c.id === signedIn)?.needsWriteSignIn).toBe(true);
    const r = await toggle(signedIn, ALEX, { enabled: true, acknowledged: true });
    expect([r.status, problemCode(r)]).toEqual([409, "write-sign-in-required"]);
    expect(await connection(signedIn)).toMatchObject({ pullRequests: false });

    const withWrite = await addConnection(ALEX.user, {
      authMethod: "sign-in",
      forgeKind: "forgejo",
      writeScope: true,
    });
    expect((await toggle(withWrite, ALEX, { enabled: true, acknowledged: true })).json).toMatchObject({
      pullRequests: true,
      writeScope: true,
      needsWriteSignIn: false,
    });
    const github = await addConnection(ALEX.user, {
      authMethod: "sign-in",
      forgeKind: "github",
      webBaseUrl: "https://github.com",
      apiBaseUrl: "https://api.github.com",
    });
    expect((await toggle(github, ALEX, { enabled: true, acknowledged: true })).status).toBe(200);
  });

  it("a new token turns it off again, audited", async () => {
    const id = await addConnection(ALEX.user, { authMethod: "sign-in", writeScope: true });
    expect((await toggle(id, ALEX, { enabled: true, acknowledged: true })).status).toBe(200);
    const replaced = await call("PUT", `/api/v1/forge-connections/${id}/token`, ALEX, { token: TOKEN });
    expect(replaced.status).toBe(204);
    expect(await connection(id)).toMatchObject({
      authMethod: "token",
      pullRequests: false,
      pullRequestsAt: null,
      writeScope: false,
    });
    const audit = await auditOf(id);
    expect(audit.map((a) => a.action)).toEqual([
      "forge_connection.pull_requests_enabled",
      "forge_connection.replaced",
      "forge_connection.pull_requests_disabled",
    ]);
    expect(audit[2]?.data).toMatchObject({ reason: "token-replaced" });
    expect(JSON.stringify(audit)).not.toContain(TOKEN);
  });
});
