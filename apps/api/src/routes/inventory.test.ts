/**
 * The inventory (ADR 0053) against a throw-away database on the development server: systems added by hand, the tokens scripts
 * use, what each scope may do, the software search across the inventory, hosts, containers and repositories, and the export.
 * Sessions are replaced by a header-driven actor. Skipped without the development PostgreSQL.
 */
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { and, eq } from "drizzle-orm";
import { Hono } from "hono";
import { beforeAll, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();
const holder = vi.hoisted(() => ({ db: null as unknown }));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null, boss: null, QUEUES: {} };
  const t = await create(target, "api_inventory");
  holder.db = t;
  return { db: t.db, pool: t.pool, QUEUES: {}, boss: null };
});
vi.mock("../env.ts", () => ({ env: { PUBLIC_URL: "https://garnetops.example.test/" }, isProduction: false }));
vi.mock("../auth.ts", () => ({ auth: { api: {} } }));

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
const ORG = "org_inv";
const OTHER = "org_inv_other";

describe.skipIf(!adminUrl)("inventory", () => {
  let t: TestDatabase;
  let app: Hono;

  type Who = { org?: string; user?: string; role?: string; stale?: boolean };
  async function call(method: string, path: string, body?: unknown, who: Who = {}) {
    // The list and "add" live at the root: no trailing slash.
    const res = await app.request(`/api/v1/inventory${path.replace(/^\/(?=$|\?)/, "")}`, {
      method,
      headers: {
        "x-org": who.org ?? ORG,
        "x-user": who.user ?? "usr_sam",
        "x-role": who.role ?? "admin",
        ...(who.stale ? { "x-stale": "1" } : {}),
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    const json = (text.startsWith("{") || text.startsWith("[") ? JSON.parse(text) : null) as Json | null;
    return { status: res.status, json, text, headers: res.headers };
  }
  /** A request of a script: a bearer token, nothing else. */
  async function feed(method: string, path: string, token: string | null, body?: unknown) {
    const res = await app.request(`/api/v1/inventory-feed${path}`, {
      method,
      headers: {
        ...(token ? { authorization: `Bearer ${token}` } : {}),
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: body === undefined ? undefined : typeof body === "string" ? body : JSON.stringify(body),
    });
    const text = await res.text();
    return { status: res.status, json: (text.startsWith("{") ? JSON.parse(text) : null) as Json | null };
  }
  const items = (body: Json | null, key = "items") => (body?.[key] ?? []) as Json[];
  /** The code of a problem answer: the last part of its type. */
  const code = (body: Json | null) =>
    String(body?.type ?? "")
      .split("/")
      .pop();
  async function token(scope: "read" | "write", who: Who = {}) {
    const res = await call("POST", "/tokens", { label: `${scope} for tests`, scope }, who);
    expect(res.status).toBe(201);
    return res.json as Json;
  }
  const audits = (action: string, org = ORG) =>
    t.db
      .select()
      .from(schema.auditLog)
      .where(and(eq(schema.auditLog.organizationId, org), eq(schema.auditLog.action, action)));

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { inventoryRoutes } = await import("./inventory.ts");
    const { inventoryFeedRoutes } = await import("./inventory-feed.ts");
    t = holder.db as TestDatabase;
    await t.db.insert(schema.organization).values([
      { id: ORG, name: "A" },
      { id: OTHER, name: "B" },
    ]);
    await t.db.insert(schema.user).values([
      { id: "usr_sam", name: "Sam", email: "sam@example.com" },
      { id: "usr_alex", name: "Alex", email: "alex@example.com" },
    ]);
    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        {
          userId: c.req.header("x-user"),
          organizationId: c.req.header("x-org"),
          role: c.req.header("x-role"),
          ip: null,
          strongAuthAt: c.req.header("x-stale") ? new Date(Date.now() - 3_600_000) : new Date(),
        } as never,
      );
      await next();
    });
    v1.route("/inventory", inventoryRoutes as never);
    app = new Hono()
      .onError(handleError)
      .route("/api/v1/inventory-feed", inventoryFeedRoutes as never)
      .route("/api/v1", v1) as unknown as Hono;
  });

  it("keeps systems added by hand: cleaned, one key each, changed and removed with an audit entry", async () => {
    const created = await call("POST", "/", {
      key: "web-1.example.lan",
      name: "  Web‮ server\u0007 1 ",
      kind: "vm",
      environment: "production",
      notes: "Rack 4\nasks for a reboot window",
      tags: ["web", "web", " customer-a "],
      software: [
        { name: "nginx", version: "1.26.0" },
        { name: "nginx", version: "1.26.0" },
        { name: "php", version: "8.3.12" },
        { name: "exim" },
      ],
    });
    expect(created.status).toBe(201);
    const id = created.json?.id as string;

    const one = await call("GET", `/${id}`);
    expect(one.json).toMatchObject({
      key: "web-1.example.lan",
      name: "Web server 1",
      kind: "vm",
      environment: "production",
      notes: "Rack 4\nasks for a reboot window",
      tags: ["web", "customer-a"],
      source: "manual",
      reportedAt: null,
    });
    // Each name and version once, sorted; a missing version is an empty one.
    expect(one.json?.software).toEqual([
      { name: "exim", version: "" },
      { name: "nginx", version: "1.26.0" },
      { name: "php", version: "8.3.12" },
    ]);

    // The key is one system's: a second system cannot take it, by creating or by renaming.
    const twice = await call("POST", "/", { key: "web-1.example.lan", name: "Copy" });
    expect(twice.status).toBe(409);
    expect(code(twice.json)).toBe("inventory-key-taken");
    const other = await call("POST", "/", {
      key: "db-1",
      name: "Database",
      software: [{ name: "postgresql" }],
    });
    const renamed = await call("PUT", `/${other.json?.id}`, { key: "web-1.example.lan", name: "Database" });
    expect(renamed.status).toBe(409);
    expect((await call("POST", "/", { key: "../etc", name: "Bad key" })).status).toBe(422);
    expect((await call("POST", "/", { key: "ok", name: "Bad kind", kind: "mainframe" })).status).toBe(422);

    const changed = await call("PUT", `/${id}`, {
      key: "web-1.example.lan",
      name: "Web server 1",
      kind: "server",
      software: [{ name: "nginx", version: "1.27.1" }],
    });
    expect(changed.status).toBe(200);
    const after = await call("GET", `/${id}`);
    expect(after.json).toMatchObject({ kind: "server", environment: null, notes: null, tags: [] });
    expect(after.json?.software).toEqual([{ name: "nginx", version: "1.27.1" }]);

    // The list: by name, with how much software and the first entries; filtered by software, tag, key and kind.
    const all = await call("GET", "/");
    expect(items(all.json).map((x) => x.name)).toEqual(["Database", "Web server 1"]);
    expect(all.json).toMatchObject({ total: 2, next: null, prev: null });
    expect(items(all.json)[1]).toMatchObject({
      softwareCount: 1,
      software: [{ name: "nginx", version: "1.27.1" }],
    });
    expect(items((await call("GET", "/?q=postgres")).json).map((x) => x.key)).toEqual(["db-1"]);
    expect(items((await call("GET", "/?q=EXAMPLE.lan")).json).map((x) => x.key)).toEqual([
      "web-1.example.lan",
    ]);
    expect(items((await call("GET", "/?kind=vm")).json)).toEqual([]);
    expect(items((await call("GET", "/?q=%25")).json)).toEqual([]);
    const paged = await call("GET", "/?pageSize=25&cursor=25");
    expect(paged.json).toMatchObject({ total: 2, next: null, prev: "0" });
    expect(items(paged.json)).toEqual([]);

    // Viewers read; they do not write.
    expect((await call("GET", "/", undefined, { role: "viewer" })).status).toBe(200);
    expect((await call("POST", "/", { key: "v", name: "V" }, { role: "viewer" })).status).toBe(403);
    expect((await call("PUT", `/${id}`, { key: "v", name: "V" }, { role: "viewer" })).status).toBe(403);
    expect((await call("DELETE", `/${id}`, undefined, { role: "viewer" })).status).toBe(403);

    // Another organisation sees and changes nothing of it.
    expect((await call("GET", `/${id}`, undefined, { org: OTHER })).status).toBe(404);
    expect((await call("PUT", `/${id}`, { key: "x", name: "X" }, { org: OTHER })).status).toBe(404);
    expect((await call("DELETE", `/${id}`, undefined, { org: OTHER })).status).toBe(404);
    expect(items((await call("GET", "/", undefined, { org: OTHER })).json)).toEqual([]);

    expect((await call("DELETE", `/${other.json?.id}`)).status).toBe(204);
    expect((await call("GET", `/${other.json?.id}`)).status).toBe(404);
    expect(
      await t.db
        .select()
        .from(schema.inventorySoftware)
        .where(eq(schema.inventorySoftware.systemId, other.json?.id)),
    ).toEqual([]);
    expect((await audits("inventory.system_created")).length).toBe(2);
    expect((await audits("inventory.system_updated")).length).toBe(1);
    const [removed] = await audits("inventory.system_deleted");
    expect(removed).toMatchObject({ actorUserId: "usr_sam", targetId: other.json?.id });
    expect(removed?.data).toMatchObject({ key: "db-1" });
  });

  it("gives tokens to admins with a recent sign-in, once, and keeps only a hash", async () => {
    expect((await call("POST", "/tokens", { label: "x", scope: "write" }, { role: "member" })).status).toBe(
      403,
    );
    expect((await call("GET", "/tokens", undefined, { role: "member" })).status).toBe(403);
    const stale = await call("POST", "/tokens", { label: "x", scope: "write" }, { stale: true });
    expect(stale.status).toBe(403);
    expect(code(stale.json)).toBe("step-up-required");
    expect((await call("POST", "/tokens", { label: "x", scope: "everything" })).status).toBe(422);
    expect((await call("POST", "/tokens", { label: " \u0007 ", scope: "read" })).status).toBe(422);

    const made = await token("write");
    expect(made.token).toMatch(/^goi_[A-Za-z0-9_-]{43}$/);
    expect(made.prefix).toBe(made.token.slice(0, 10));
    const [stored] = await t.db
      .select()
      .from(schema.inventoryToken)
      .where(eq(schema.inventoryToken.id, made.id));
    expect(stored?.tokenHash).toMatch(/^[0-9a-f]{64}$/);
    expect(JSON.stringify(stored)).not.toContain(made.token);

    const listed = await call("GET", "/tokens");
    expect(listed.text).not.toContain(made.token);
    expect(listed.text).not.toContain(stored?.tokenHash);
    expect((listed.json as unknown as Json[])[0]).toMatchObject({
      id: made.id,
      scope: "write",
      prefix: made.prefix,
      createdBy: "Sam",
      lastUsedAt: null,
    });
    const [created] = await audits("inventory.token_created");
    expect(created?.data).toEqual({ label: "write for tests", scope: "write", prefix: made.prefix });

    // Another organisation's admin cannot revoke it; revoking needs a recent sign-in; a revoked token is gone at once.
    expect((await call("DELETE", `/tokens/${made.id}`, undefined, { org: OTHER })).status).toBe(404);
    expect((await call("DELETE", `/tokens/${made.id}`, undefined, { stale: true })).status).toBe(403);
    expect((await feed("PUT", "/systems/gone-soon", made.token, { software: [] })).status).toBe(201);
    expect((await call("DELETE", `/tokens/${made.id}`)).status).toBe(204);
    expect((await feed("PUT", "/systems/gone-soon", made.token, { software: [] })).status).toBe(401);
    expect((await call("DELETE", `/tokens/${made.id}`)).status).toBe(404);
    expect(
      items(await call("GET", "/tokens").then((r) => ({ items: r.json }))).map((x) => x.id),
    ).not.toContain(made.id);
    expect((await audits("inventory.token_revoked")).length).toBe(1);
  });

  it("lets a script report, read and remove systems, each scope doing only its own", async () => {
    const write = (await token("write")).token as string;
    const read = (await token("read")).token as string;

    // No token, a malformed one, an unknown one and a session cookie get the same answer.
    const unknown = `goi_${"A".repeat(43)}`;
    for (const bad of [null, "goi_short", unknown, write.slice(0, -1)]) {
      const res = await feed("GET", "/systems", bad);
      expect(res.status).toBe(401);
      expect(code(res.json)).toBe("invalid-inventory-token");
    }
    // A write token reads nothing; a read token changes nothing.
    expect((await feed("GET", "/systems", write)).status).toBe(403);
    expect((await feed("PUT", "/systems/app-1", read, { software: [] })).status).toBe(403);
    expect((await feed("DELETE", "/systems/web-1.example.lan", read)).status).toBe(403);

    const first = await feed("PUT", "/systems/app-1", write, {
      name: "App server",
      kind: "container",
      environment: "staging",
      tags: ["django"],
      software: [
        { name: "Django", version: "5.0.14" },
        { name: "gunicorn", version: "23.0.0" },
      ],
    });
    expect(first.status).toBe(201);
    expect(first.json).toEqual({ key: "app-1", created: true, software: 2 });
    const [created] = (await audits("inventory.system_created")).filter(
      (a) => (a.data as Json | null)?.key === "app-1",
    );
    expect(created).toMatchObject({ actorUserId: null });
    expect(JSON.stringify(created?.data)).not.toContain(write);

    // A person adds notes and tags in the app (which makes the entry theirs until the next report).
    const [row] = await t.db
      .select()
      .from(schema.inventorySystem)
      .where(and(eq(schema.inventorySystem.organizationId, ORG), eq(schema.inventorySystem.key, "app-1")));
    await t.db
      .update(schema.inventorySystem)
      .set({ notes: "Owned by the web team", tags: ["django", "customer-a"] })
      .where(eq(schema.inventorySystem.id, row?.id ?? ""));

    // The next report replaces the software and sets only what it sends: notes, tags and the name stay.
    const second = await feed("PUT", "/systems/app-1", write, {
      software: [{ name: "Django", version: "5.2.8" }],
    });
    expect(second.status).toBe(200);
    expect(second.json).toEqual({ key: "app-1", created: false, software: 1 });
    const app1 = await call("GET", `/${row?.id}`);
    expect(app1.json).toMatchObject({
      name: "App server",
      kind: "container",
      environment: "staging",
      notes: "Owned by the web team",
      tags: ["django", "customer-a"],
      source: "script",
    });
    expect(app1.json?.reportedAt).not.toBeNull();
    expect(app1.json?.software).toEqual([{ name: "Django", version: "5.2.8" }]);
    // A routine report is not an audit entry; only the first one was.
    expect(
      (await audits("inventory.system_created")).filter((a) => (a.data as Json | null)?.key === "app-1")
        .length,
    ).toBe(1);

    // A system reported with nothing but software is named after its key.
    expect((await feed("PUT", "/systems/SW-CORE:1", write, { software: [] })).status).toBe(201);
    // What does not fit is refused, never half-stored.
    expect((await feed("PUT", "/systems/app-1", write, {})).status).toBe(422);
    expect((await feed("PUT", "/systems/app-1", write, "not json")).status).toBe(422);
    expect((await feed("PUT", "/systems/app-1", write, { software: [{ name: "" }] })).status).toBe(422);
    expect((await feed("PUT", `/systems/${"a".repeat(121)}`, write, { software: [] })).status).toBe(404);
    expect((await feed("PUT", "/systems/bad%20key", write, { software: [] })).status).toBe(404);
    const many = Array.from({ length: 5001 }, (_, i) => ({ name: `pkg-${i}`, version: "1" }));
    expect((await feed("PUT", "/systems/app-1", write, { software: many })).status).toBe(422);
    expect((await call("GET", `/${row?.id}`)).json?.software).toEqual([{ name: "Django", version: "5.2.8" }]);

    // The read token gets the whole inventory of its organisation, by key, and never an internal id.
    const whole = await feed("GET", "/systems", read);
    expect(whole.status).toBe(200);
    const systems = items(whole.json, "systems");
    expect(systems.map((x) => x.key)).toEqual(["SW-CORE:1", "app-1", "gone-soon", "web-1.example.lan"]);
    expect(systems[1]).toMatchObject({
      name: "App server",
      source: "script",
      software: [{ name: "Django", version: "5.2.8" }],
    });
    expect(systems[0]).toMatchObject({ name: "SW-CORE:1", kind: "server" });
    expect(Object.keys(systems[0] ?? {})).not.toContain("id");

    // Tokens stay in their organisation.
    const foreign = (await token("write", { org: OTHER })).token as string;
    const foreignRead = (await token("read", { org: OTHER })).token as string;
    expect((await feed("DELETE", "/systems/app-1", foreign)).status).toBe(404);
    expect((await feed("PUT", "/systems/app-1", foreign, { software: [{ name: "theirs" }] })).status).toBe(
      201,
    );
    expect(items((await feed("GET", "/systems", foreignRead)).json, "systems").map((x) => x.key)).toEqual([
      "app-1",
    ]);
    expect((await call("GET", `/${row?.id}`)).json?.software).toEqual([{ name: "Django", version: "5.2.8" }]);

    expect((await feed("DELETE", "/systems/SW-CORE:1", write)).status).toBe(204);
    expect((await feed("DELETE", "/systems/SW-CORE:1", write)).status).toBe(404);
    const removed = (await audits("inventory.system_deleted")).find(
      (a) => (a.data as Json | null)?.key === "SW-CORE:1",
    );
    expect(removed).toMatchObject({ actorUserId: null });

    const [used] = await t.db
      .select({ lastUsedAt: schema.inventoryToken.lastUsedAt })
      .from(schema.inventoryToken)
      .where(eq(schema.inventoryToken.organizationId, OTHER))
      .limit(1);
    expect(used?.lastUsedAt).not.toBeNull();
  });

  it("limits a token to 120 requests a minute", async () => {
    const read = await token("read");
    await t.db.execute(
      `insert into rate_limit (id, key, count, last_request) values ('rl_inv', 'inventory:${read.id}', 120, ${Date.now()})
       on conflict (key) do update set count = 120, last_request = excluded.last_request`,
    );
    const res = await feed("GET", "/systems", read.token);
    expect(res.status).toBe(429);
    expect(code(res.json)).toBe("rate-limited");
  });

  it("finds where software runs across inventory, hosts, containers and repositories, as far as the person may see", async () => {
    await t.db.insert(schema.hostSettings).values({ organizationId: ORG, enabled: true });
    await t.db.insert(schema.agentHost).values({
      id: "hst_inv",
      organizationId: ORG,
      name: "edge-1",
      hostname: "edge-1.example.lan",
      publicKey: "k".repeat(43),
      enrolledAt: new Date(),
      lastSeenAt: new Date(),
      hostPackages: [
        { name: "nginx", version: "1.22.1-9", type: "deb", purl: "pkg:deb/debian/nginx@1.22.1-9" },
        { name: "openssl", version: "3.0.15", type: "deb", purl: "pkg:deb/debian/openssl@3.0.15" },
      ],
    });
    await t.db.insert(schema.hostContainer).values({
      hostId: "hst_inv",
      containerId: "c1",
      organizationId: ORG,
      name: "proxy",
      imageRef: "registry.example.test/proxy:1",
      imageId: "sha256:inv1",
      state: "running",
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
    });
    await t.db.insert(schema.containerImage).values({
      organizationId: ORG,
      imageId: "sha256:inv1",
      packages: [{ name: "nginx", version: "1.27.0", type: "binary", purl: "pkg:generic/nginx@1.27.0" }],
      packagesAt: new Date(),
      firstSeenAt: new Date(),
      lastSeenAt: new Date(),
    });
    const repo = (id: string, name: string, patch: Partial<typeof schema.repository.$inferInsert> = {}) =>
      t.db.insert(schema.repository).values({
        id,
        organizationId: ORG,
        name,
        url: `https://git.example.test/team/${name}.git`,
        authKind: "none",
        ...patch,
      });
    await repo("repo_inv", "shop");
    await repo("repo_inv_private", "alex-tool", { visibility: "private", ownerUserId: "usr_alex" });
    const pkg = (repositoryId: string, name: string) =>
      t.db.insert(schema.repositoryPackage).values({
        organizationId: ORG,
        repositoryId,
        id: `pkg_inv_${name}`,
        scanId: "scan_inv",
        purl: `pkg:npm/${name}@1.0.0`,
        name,
        version: "1.0.0",
        type: "npm",
      });
    await pkg("repo_inv", "nginx-conf");
    await pkg("repo_inv_private", "nginx-private");

    const found = await call("GET", "/software?q=NGINX", undefined, { role: "member" });
    expect(found.status).toBe(200);
    expect(found.json).toMatchObject({ limited: false, hostsOn: true });
    const rows = items(found.json);
    expect(rows.map((x) => [x.source, x.system, x.name, x.version, x.checked])).toEqual([
      ["inventory", "Web server 1", "nginx", "1.27.1", false],
      ["host", "edge-1", "nginx", "1.22.1-9", true],
      ["container", "proxy", "nginx", "1.27.0", true],
      ["repository", "shop", "nginx-conf", "1.0.0", true],
    ]);
    expect(rows[2]?.detail).toBe("edge-1: registry.example.test/proxy:1");
    // Alex sees their private repository too; Sam did not.
    const alex = await call("GET", "/software?q=nginx", undefined, { user: "usr_alex", role: "member" });
    expect(items(alex.json).map((x) => x.name)).toContain("nginx-private");
    // A wildcard is a character, not a pattern; one character is not a search.
    expect(items((await call("GET", "/software?q=n%25x")).json)).toEqual([]);
    expect((await call("GET", "/software?q=n")).status).toBe(422);
    // Another organisation finds nothing of this one.
    expect(items((await call("GET", "/software?q=nginx", undefined, { org: OTHER })).json)).toEqual([]);

    // With the hosts module off, hosts and containers are left out and the answer says so.
    await t.db
      .update(schema.hostSettings)
      .set({ enabled: false })
      .where(eq(schema.hostSettings.organizationId, ORG));
    const off = await call("GET", "/software?q=nginx");
    expect(off.json?.hostsOn).toBe(false);
    expect(items(off.json).map((x) => x.source)).toEqual(["inventory", "repository"]);
  });

  it("exports the inventory as filtered, one row per system and software, and notes it in the audit log", async () => {
    const csv = await call("GET", "/export?format=csv&q=web-1");
    expect(csv.status).toBe(200);
    expect(csv.headers.get("content-type")).toContain("text/csv");
    expect(csv.headers.get("content-disposition")).toMatch(
      /attachment; filename="garnetops-inventory-.*\.csv"/,
    );
    expect(csv.text).toContain("Web server 1");
    expect(csv.text).toContain("nginx");
    expect(csv.text).toContain("1.27.1");
    expect(csv.text).not.toContain("App server");
    const german = await call("GET", "/export?format=txt&lang=de");
    expect(german.text).toContain("Inventar");
    expect(german.text).toContain("App server");
    // A system without software still has its row.
    expect(german.text).toContain("gone-soon");
    expect((await call("GET", "/export?format=docx")).status).toBe(422);
    const pdf = await call("GET", "/export?format=pdf", undefined, { role: "viewer" });
    expect(pdf.headers.get("content-type")).toBe("application/pdf");
    const logged = await audits("inventory.exported");
    expect(logged.length).toBe(3);
    expect(logged[0]?.data).toMatchObject({ format: "csv", systems: 1 });
  });
});
