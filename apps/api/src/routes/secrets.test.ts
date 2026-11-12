/**
 * The secrets API (ADR 0049) against a throw-away database on the development server: lists and counts by state and severity,
 * private repositories (ADR 0030), closing and reopening with a reason and an audit entry, the history setting and the
 * once-an-hour history check. Sessions are replaced by a header-driven actor. Skipped without the development PostgreSQL.
 */
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { and, desc, eq } from "drizzle-orm";
import { Hono } from "hono";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();
const holder = vi.hoisted(() => ({ db: null as unknown, sent: [] as unknown[] }));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null, boss: null, QUEUES: {} };
  const t = await create(target, "api_secrets");
  holder.db = t;
  return {
    db: t.db,
    pool: t.pool,
    QUEUES: { scanRepository: "scan.repository" },
    boss: { send: async (...args: unknown[]) => holder.sent.push(args) },
  };
});

// The context helpers read the installation's settings when they are imported.
vi.mock("../env.ts", () => ({ env: { PUBLIC_URL: "https://garnetops.example.test/" }, isProduction: false }));
vi.mock("../auth.ts", () => ({ auth: { api: {} } }));

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
const ORG = "org_sec_a";
const OTHER = "org_sec_b";

describe.skipIf(!adminUrl)("secrets API", () => {
  let t: TestDatabase;
  let app: Hono;
  let counter = 0;
  let shared: string;
  let mine: string;
  let theirs: string;

  async function call(
    method: string,
    path: string,
    opts: { role?: string; user?: string; org?: string; body?: unknown; stale?: boolean } = {},
  ) {
    const res = await app.request(path, {
      method,
      headers: {
        "x-org": opts.org ?? ORG,
        "x-role": opts.role ?? "member",
        "x-user": opts.user ?? "usr_member",
        "content-type": "application/json",
        ...(opts.stale ? { "x-stale": "1" } : {}),
      },
      body: opts.body === undefined ? undefined : JSON.stringify(opts.body),
    });
    const text = await res.text();
    return { status: res.status, json: (text ? JSON.parse(text) : null) as Json | null };
  }

  async function repo(name: string, options: { owner?: string; org?: string } = {}) {
    const id = `repo_sec${++counter}`;
    await t.db.insert(schema.repository).values({
      id,
      organizationId: options.org ?? ORG,
      name,
      url: `https://git.example.lan/${name}.git`,
      authKind: "none",
      visibility: options.owner ? "private" : "organization",
      ownerUserId: options.owner ?? null,
    });
    return id;
  }

  async function secret(
    repositoryId: string,
    severity: "critical" | "high" | "medium" | "low",
    options: { state?: "open" | "revoked" | "dismissed"; org?: string; inTree?: boolean } = {},
  ) {
    const id = `sec_t${++counter}`;
    const rank = { critical: 5, high: 4, medium: 3, low: 2 }[severity];
    await t.db.insert(schema.secretFinding).values({
      id,
      organizationId: options.org ?? ORG,
      repositoryId,
      ruleId: severity === "critical" ? "github-pat" : "garnetops-env-file",
      severity,
      severityRank: rank,
      fingerprint: `fp-${counter}`,
      state: options.state ?? "open",
      inTree: options.inTree ?? true,
      treeLocations: options.inTree === false ? [] : [{ path: "src/config.js", line: 3 }],
      treeLocationCount: options.inTree === false ? 0 : 1,
      historyLocations: [],
      historyLocationCount: 0,
      firstSeenScanId: "scan_x",
      lastSeenScanId: "scan_x",
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
    });
    return id;
  }

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { secretRoutes, repositorySecretRoutes } = await import("./secrets.ts");
    t = holder.db as TestDatabase;
    await t.db.insert(schema.organization).values([
      { id: ORG, name: "A" },
      { id: OTHER, name: "B" },
    ]);
    await t.db.insert(schema.user).values([
      { id: "usr_member", name: "Member", email: "member@example.com" },
      { id: "usr_other", name: "Other", email: "other@example.com" },
      { id: "usr_admin", name: "Admin", email: "admin@example.com" },
    ]);
    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        {
          userId: c.req.header("x-user"),
          organizationId: c.req.header("x-org"),
          role: c.req.header("x-role"),
          ip: null,
          // "x-stale": signed in long ago, for the step-up of ignore rules.
          strongAuthAt: c.req.header("x-stale") ? new Date(0) : new Date(),
        } as never,
      );
      await next();
    });
    v1.route("/secrets", secretRoutes as never);
    v1.route("/repositories/:id/secrets", repositorySecretRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;

    shared = await repo("shared");
    mine = await repo("mine", { owner: "usr_member" });
    theirs = await repo("theirs", { owner: "usr_other" });
    await secret(shared, "critical");
    await secret(shared, "medium", { inTree: false });
    await secret(shared, "high", { state: "dismissed" });
    await secret(mine, "high");
    await secret(theirs, "critical");
    await secret(await repo("elsewhere", { org: OTHER }), "critical", { org: OTHER });
  });

  afterAll(async () => {
    await t?.drop();
  });

  it("lists open secrets worst first, of the repositories the person sees, without any value", async () => {
    const list = await call("GET", "/api/v1/secrets");
    expect(list.status).toBe(200);
    expect(list.json?.items.map((i: Json) => [i.repositoryName, i.severity])).toEqual([
      ["shared", "critical"],
      ["mine", "high"],
      ["shared", "medium"],
    ]);
    expect(list.json?.items[0]).toMatchObject({
      ruleId: "github-pat",
      place: { path: "src/config.js", line: 3 },
    });
    expect(list.json?.items[2]).toMatchObject({ inTree: false, place: null });
    expect(JSON.stringify(list.json)).not.toMatch(/fingerprint|fp-\d/);
    // The owner of "theirs" sees its secret; nobody else does.
    const other = await call("GET", "/api/v1/secrets", { user: "usr_other" });
    // Two critical ones: the one seen last comes first.
    expect(other.json?.items.map((i: Json) => i.repositoryName)).toEqual(["theirs", "shared", "shared"]);
    const filtered = await call("GET", "/api/v1/secrets?state=all&severity=high");
    expect(filtered.json?.items.map((i: Json) => i.state).sort()).toEqual(["dismissed", "open"]);
    expect((await call("GET", "/api/v1/secrets?severity=bad")).status).toBe(422);
  });

  it("counts per state, and open ones per severity", async () => {
    const counts = await call("GET", "/api/v1/secrets/counts");
    expect(counts.json).toEqual({
      states: { open: 3, ignored: 0, revoked: 0, dismissed: 1 },
      open: { critical: 1, high: 1, medium: 1 },
    });
  });

  it("exports the list as filtered, of the repositories the person sees, without any value, and audits it", async () => {
    const download = (query: string, user = "usr_member") =>
      app.request(`/api/v1/secrets/export?${query}`, {
        headers: { "x-org": ORG, "x-role": "member", "x-user": user },
      });
    const txt = await download("format=txt&lang=en&tz=Europe/Berlin");
    expect(txt.status).toBe(200);
    expect(txt.headers.get("content-type")).toContain("text/plain");
    expect(txt.headers.get("cache-control")).toBe("no-store");
    expect(txt.headers.get("content-disposition")).toMatch(
      /filename="garnetops-secrets-\d{4}-\d{2}-\d{2}\.txt"/,
    );
    const text = await txt.text();
    const lines = text.split("\n");
    expect(lines[0]).toBe("Secrets");
    expect(text).toContain("Filters: state Open");
    expect(text).toContain("Secrets: 3");
    expect(text).toContain("No values: GarnetOps never stores them");
    // Worst first; the rule's name for GarnetOps' own file rules; "theirs" is not in it.
    const body = lines.slice(lines.findIndex((l) => l.startsWith("---")) + 1).filter(Boolean);
    expect(body.map((l) => l.split(/\s{2,}/).slice(0, 2))).toEqual([
      ["Critical", "github-pat"],
      ["High", "Environment file with values"],
      ["Medium", "Environment file with values"],
    ]);
    expect(text).toContain("src/config.js:3");
    expect(text).not.toMatch(/theirs|fp-\d/);

    // One repository and every state, in German, as a spreadsheet.
    const xlsx = await download(`format=xlsx&lang=de&state=all&repositoryId=${shared}`);
    expect(xlsx.status).toBe(200);
    expect(xlsx.headers.get("content-disposition")).toContain("garnetops-secrets-shared-");
    expect(
      Buffer.from(await xlsx.arrayBuffer())
        .subarray(0, 2)
        .toString(),
    ).toBe("PK");
    // A repository the person does not see is not found, and a bad format is refused.
    expect((await download(`format=csv&repositoryId=${theirs}`)).status).toBe(404);
    expect((await download("format=doc")).status).toBe(422);

    const [entry] = await t.db
      .select()
      .from(schema.auditLog)
      .where(eq(schema.auditLog.action, "secret.exported"))
      .orderBy(desc(schema.auditLog.createdAt))
      .limit(1);
    expect(entry?.data).toMatchObject({ format: "xlsx", count: 3 });
  });

  it("closes a secret with a reason, audits it, keeps it closed, and reopens it", async () => {
    const [target] = (await call("GET", "/api/v1/secrets")).json?.items ?? [];
    const id = target.id as string;
    expect(
      (
        await call("POST", `/api/v1/secrets/${id}/revoke`, {
          role: "viewer",
          body: { reason: "rotated today" },
        })
      ).status,
    ).toBe(403);
    expect((await call("POST", `/api/v1/secrets/${id}/revoke`, { body: { reason: "short" } })).status).toBe(
      422,
    );
    expect(
      (
        await call("POST", `/api/v1/secrets/${id}/revoke`, {
          body: { reason: "Rotated the token on GitHub" },
        })
      ).status,
    ).toBe(200);
    expect(
      (
        await call("POST", `/api/v1/secrets/${id}/dismiss`, {
          body: { reason: "Rotated the token on GitHub" },
        })
      ).status,
    ).toBe(409);
    const detail = await call("GET", `/api/v1/secrets/${id}`);
    expect(detail.json).toMatchObject({
      state: "revoked",
      stateReason: "Rotated the token on GitHub",
      stateByName: "Member",
      treeLocations: [{ path: "src/config.js", line: 3 }],
    });
    const [entry] = await t.db
      .select()
      .from(schema.auditLog)
      .where(and(eq(schema.auditLog.action, "secret.revoked"), eq(schema.auditLog.targetId, id)));
    expect(entry).toMatchObject({ actorUserId: "usr_member", organizationId: ORG });
    expect((await call("POST", `/api/v1/secrets/${id}/reopen`)).status).toBe(200);
    expect((await call("GET", `/api/v1/secrets/${id}`)).json).toMatchObject({
      state: "open",
      stateReason: null,
    });
    // Another organisation, or a private repository of someone else: not found.
    expect((await call("GET", `/api/v1/secrets/${id}`, { org: OTHER })).status).toBe(404);
  });

  it("switches history checks on for admins, or a member's own private repository, and audits it", async () => {
    expect(
      (await call("PUT", `/api/v1/repositories/${shared}/secrets/history`, { body: { enabled: true } }))
        .status,
    ).toBe(403);
    const own = await call("PUT", `/api/v1/repositories/${mine}/secrets/history`, {
      body: { enabled: true },
    });
    expect(own.status).toBe(200);
    expect(own.json).toMatchObject({ open: { high: 1 }, history: { enabled: true } });
    const admin = await call("PUT", `/api/v1/repositories/${shared}/secrets/history`, {
      role: "admin",
      user: "usr_admin",
      body: { enabled: true },
    });
    expect(admin.json?.history.enabled).toBe(true);
    const actions = (await t.db.select().from(schema.auditLog)).map((a) => a.action);
    expect(actions.filter((a) => a === "repository.secret_history_enabled")).toHaveLength(2);
    expect((await call("GET", `/api/v1/repositories/${theirs}/secrets`)).status).toBe(404);
  });

  it("checks the history once on request, not twice within an hour, and not while a scan runs", async () => {
    const first = await call("POST", `/api/v1/repositories/${shared}/secrets/history-check`);
    expect(first.status).toBe(202);
    const [scan] = await t.db.select().from(schema.scan).where(eq(schema.scan.id, first.json?.scanId));
    expect(scan).toMatchObject({ secretHistory: true, state: "queued", repositoryId: shared });
    expect(holder.sent).toHaveLength(1);
    expect((await call("POST", `/api/v1/repositories/${shared}/secrets/history-check`)).status).toBe(409);
    await t.db.update(schema.scan).set({ state: "succeeded" }).where(eq(schema.scan.id, first.json?.scanId));
    expect((await call("POST", `/api/v1/repositories/${shared}/secrets/history-check`)).status).toBe(429);
    expect(
      (await call("POST", `/api/v1/repositories/${shared}/secrets/history-check`, { role: "viewer" })).status,
    ).toBe(403);
  });

  it("ignore rules: admins with a recent sign-in, set aside only what they cover, counted apart, and undone on delete", async () => {
    const before = (await call("GET", "/api/v1/secrets/counts")).json;
    const body = { pathPattern: "src/**", reason: "Example configuration in the docs" };
    expect((await call("POST", "/api/v1/secrets/ignore-rules", { body })).status).toBe(403);
    const stale = await call("POST", "/api/v1/secrets/ignore-rules", {
      role: "admin",
      user: "usr_admin",
      stale: true,
      body,
    });
    expect(stale.json?.type ?? stale.json?.code).toMatch(/step-up-required/);
    for (const bad of [
      { reason: "no pattern and no rule" },
      { pathPattern: "**", reason: "everything at once" },
    ]) {
      expect(
        (await call("POST", "/api/v1/secrets/ignore-rules", { role: "admin", user: "usr_admin", body: bad }))
          .status,
      ).toBe(422);
    }
    const made = await call("POST", "/api/v1/secrets/ignore-rules", {
      role: "admin",
      user: "usr_admin",
      body: { ...body, repositoryId: shared },
    });
    expect(made.status).toBe(201);
    // The open secrets of "shared" sit in src/config.js; the one without places (only in history, none known) stays.
    expect(made.json?.ignored).toBeGreaterThanOrEqual(1);
    const counts = (await call("GET", "/api/v1/secrets/counts")).json;
    expect(counts?.states.ignored).toBe(made.json?.ignored);
    expect(counts?.states.open).toBe((before?.states.open ?? 0) - (made.json?.ignored ?? 0));
    const ignored = await call("GET", "/api/v1/secrets?state=ignored");
    expect(ignored.json?.items.every((i: Json) => i.ignoredBy === made.json?.id)).toBe(true);
    const detail = await call("GET", `/api/v1/secrets/${ignored.json?.items[0].id}`);
    expect(detail.json?.ignoredBy).toMatchObject({
      pathPattern: "src/**",
      reason: "Example configuration in the docs",
    });
    const rules = await call("GET", "/api/v1/secrets/ignore-rules", { role: "viewer" });
    expect(rules.json?.items).toEqual([
      expect.objectContaining({
        id: made.json?.id,
        repositoryName: "shared",
        ignored: made.json?.ignored,
        createdByName: "Admin",
      }),
    ]);
    // Removing it brings them back at once, and both changes are audited.
    expect(
      (
        await call("DELETE", `/api/v1/secrets/ignore-rules/${made.json?.id}`, {
          role: "admin",
          user: "usr_admin",
        })
      ).status,
    ).toBe(204);
    expect((await call("GET", "/api/v1/secrets/counts")).json).toEqual(before);
    const actions = (await t.db.select().from(schema.auditLog)).map((a) => a.action);
    expect(actions).toEqual(
      expect.arrayContaining(["secret.ignore_rule_created", "secret.ignore_rule_deleted"]),
    );
  });
});
