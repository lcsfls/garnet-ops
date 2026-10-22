/**
 * The live attack feed over the API (ADR 0021) against a throw-away PostgreSQL database on the development server:
 * the latest events (order, limit, enrichment from the local tables, the cached abuse score only while OSINT is on),
 * the status of the feed, the event stream (ready, new events after NOTIFY, resuming with the last id, too much to
 * replay, one organisation never sees another's events, the connection limit), and the settings it adds: the home
 * location and the live feed (roles, validation, audit). Sessions are replaced by a header-driven actor. Only
 * documentation address ranges and example names appear. Skipped without the development PostgreSQL.
 */
import { liveChannel } from "@garnetops/core/attack-live";
import { type GeoipRow, newParseStats } from "@garnetops/core/geoip";
import { importDataset, schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();
const holder = vi.hoisted(() => ({ db: null as unknown }));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null, boss: null, QUEUES: {} };
  const t = await create(target, "api_attacks_live");
  holder.db = t;
  return { db: t.db, pool: t.pool, boss: null, QUEUES: {} };
});
vi.mock("../env.ts", async () => {
  const { generateVaultKeyPair: generate, loadVaultPublicKey } = await import("@garnetops/core/vault");
  return {
    env: { PUBLIC_URL: "https://garnetops.example.test/" },
    isProduction: false,
    vaultPublicKey: loadVaultPublicKey(generate().publicKeyPem),
  };
});
vi.mock("../auth.ts", () => ({ auth: { api: {} } }));

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
type Role = "owner" | "admin" | "member" | "viewer";
const ORG = "org_live_a";
const OTHER = "org_live_b";
const STALE = 11 * 60;

async function* rowsOf(rows: GeoipRow[]) {
  for (const row of rows) yield row;
}

describe.skipIf(!adminUrl)("live attack feed API", () => {
  let t: TestDatabase;
  let app: Hono;
  let counter = 0;
  let connectionId = "";

  const as = (user: string, role: Role = "member", org = ORG, age = 0) => ({
    "x-user": user,
    "x-role": role,
    "x-org": org,
    "x-age": String(age),
  });

  async function call(
    method: string,
    path: string,
    options: { user?: string; role?: Role; org?: string; age?: number; body?: unknown } = {},
  ) {
    const headers: Record<string, string> = as(
      options.user ?? "u_member",
      options.role ?? "member",
      options.org ?? ORG,
      options.age ?? 0,
    );
    if (options.body !== undefined) headers["content-type"] = "application/json";
    const res = await app.request(path, {
      method,
      headers,
      body: options.body === undefined ? undefined : JSON.stringify(options.body),
    });
    const text = await res.text();
    let json: unknown = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      // not JSON
    }
    return { status: res.status, json: json as Json | null, text };
  }
  const itemsOf = (r: { json: Json | null }): Json[] => (r.json?.items ?? []) as Json[];
  const errorsOf = (r: { json: Json | null }): Json[] => (r.json?.errors ?? []) as Json[];
  const problemCode = (r: { json: Json | null }) =>
    String(r.json?.type ?? "")
      .split("/")
      .pop();
  const audits = async (action: string) =>
    (await t.db.select().from(schema.auditLog)).filter((a) => a.action === action);

  async function seedConnection(org = ORG, over: Partial<typeof schema.wazuhConnection.$inferInsert> = {}) {
    const id = `wzc_live${String(++counter).padStart(10, "0")}`;
    await t.db.insert(schema.wazuhConnection).values({
      id,
      organizationId: org,
      name: "Seeded lab",
      adapter: "wazuh4",
      lastSyncAt: new Date(),
      ...over,
    });
    for (const kind of ["manager", "indexer"] as const) {
      await t.db.insert(schema.wazuhEndpoint).values({
        id: `wze_live${kind[0]}${String(counter).padStart(8, "0")}`,
        organizationId: org,
        connectionId: id,
        kind,
        apiUrl: "https://wazuh.example.test:9200",
        host: "wazuh.example.test",
        port: 9200,
        username: "reader",
        trustMode: "pin",
        certStatus: "confirmed",
        certFingerprint: "AA:BB",
      });
    }
    return id;
  }

  let docs = 0;
  /** Stores an event as the worker does (without the NOTIFY). */
  async function store(
    over: Partial<typeof schema.wazuhAttackEvent.$inferInsert> = {},
    org = ORG,
    connection = connectionId,
  ) {
    const [row] = await t.db
      .insert(schema.wazuhAttackEvent)
      .values({
        organizationId: org,
        connectionId: connection,
        docId: `doc-${++docs}`,
        at: new Date(),
        ip: "198.51.100.77",
        ruleId: "5710",
        ruleLevel: 10,
        description: "sshd: login failed",
        groups: ["authentication_failed"],
        agentId: "001",
        agentName: "web-01",
        ...over,
      })
      .returning();
    return row as typeof schema.wazuhAttackEvent.$inferSelect;
  }
  const notify = (org: string, seq: number) =>
    t.pool.query("select pg_notify($1, $2)", [liveChannel(org), JSON.stringify({ s: seq })]);

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { attackRoutes } = await import("./attacks.ts");
    t = holder.db as TestDatabase;
    await t.db.insert(schema.organization).values([
      { id: ORG, name: "A" },
      { id: OTHER, name: "B" },
    ]);
    for (const [id, org] of [
      ["u_owner", ORG],
      ["u_admin", ORG],
      ["u_member", ORG],
      ["u_viewer", ORG],
      ["u_other", OTHER],
    ] as const) {
      await t.db.insert(schema.user).values({ id, name: id, email: `${id}@example.test` });
      await t.db.insert(schema.membership).values({
        organizationId: org,
        userId: id,
        role: id === "u_owner" || id === "u_other" ? "owner" : id.slice(2) === "admin" ? "admin" : "member",
      });
    }
    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        {
          userId: c.req.header("x-user"),
          email: `${c.req.header("x-user")}@example.test`,
          name: "Test",
          organizationId: c.req.header("x-org"),
          role: c.req.header("x-role"),
          ip: "198.51.100.7",
          strongAuthAt: new Date(Date.now() - Number(c.req.header("x-age") ?? 0) * 1000),
        } as never,
      );
      await next();
    });
    v1.route("/attacks", attackRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
  }, 60_000);

  afterAll(async () => {
    const { listenBus } = await import("../lib/listen-bus.ts");
    await listenBus.close();
    await t?.drop();
  });

  beforeEach(async () => {
    await t.pool.query(
      "truncate wazuh_connection, attack_settings, attack_osint_result, geoip_dataset, audit_log, rate_limit restart identity cascade",
    );
    connectionId = await seedConnection();
  });

  /* ------------------------------------------------------------------------ */

  describe("latest events", () => {
    it("lets every member read, newest first, and nothing of another organisation", async () => {
      await store({ docId: "old", at: new Date("2026-10-21T08:00:00Z"), description: "first" });
      await store({ docId: "new", at: new Date("2026-10-21T08:05:00Z"), description: "second" });
      const otherConnection = await seedConnection(OTHER);
      await store({ description: "not for A" }, OTHER, otherConnection);
      for (const role of ["viewer", "member", "admin", "owner"] as Role[]) {
        const r = await call("GET", "/api/v1/attacks/events", { role });
        expect(r.status, role).toBe(200);
        expect(itemsOf(r).map((e) => e.description)).toEqual(["second", "first"]);
      }
      const theirs = await call("GET", "/api/v1/attacks/events", {
        user: "u_other",
        role: "owner",
        org: OTHER,
      });
      expect(itemsOf(theirs).map((e) => e.description)).toEqual(["not for A"]);
    });

    it("limits the answer to 50 and refuses more", async () => {
      for (let i = 0; i < 60; i++) await store({ description: `event ${i}` });
      expect(itemsOf(await call("GET", "/api/v1/attacks/events")).length).toBe(50);
      expect(itemsOf(await call("GET", "/api/v1/attacks/events?limit=5")).length).toBe(5);
      for (const bad of ["0", "51", "abc", "-1"]) {
        expect((await call("GET", `/api/v1/attacks/events?limit=${bad}`)).status, bad).toBe(422);
      }
    });

    it("shows country and network from the local tables; internal addresses are labelled and never looked up", async () => {
      await importDataset(t.db, {
        kind: "country",
        source: "import",
        month: "2026-10",
        importedBy: null,
        rows: rowsOf([{ start: "198.51.100.0", end: "198.51.100.255", country: "DE" }]),
        stats: newParseStats(),
      });
      await importDataset(t.db, {
        kind: "asn",
        source: "import",
        month: "2026-10",
        importedBy: null,
        rows: rowsOf([{ start: "198.51.100.0", end: "198.51.100.255", asn: 64500, org: "Example Hosting" }]),
        stats: newParseStats(),
      });
      await store({ ip: "198.51.100.77" });
      await store({ ip: "10.20.30.40" });
      await store({ ip: "203.0.113.9" });
      const items = itemsOf(await call("GET", "/api/v1/attacks/events"));
      const by = (ip: string) => items.find((e) => e.ip === ip) as Json;
      expect(by("198.51.100.77")).toMatchObject({ scope: "public", country: "DE", asn: 64500, score: null });
      expect(by("10.20.30.40")).toMatchObject({ scope: "internal", country: null, asn: null });
      expect(by("203.0.113.9")).toMatchObject({ scope: "public", country: null });
      // No organisation name of the network table in the event, only its number.
      expect(JSON.stringify(items)).not.toContain("Example Hosting");
    });

    it("returns the cached abuse score only while OSINT is on, and only for public addresses", async () => {
      await store({ ip: "198.51.100.77" });
      await store({ ip: "10.20.30.40" });
      await t.db.insert(schema.attackOsintResult).values({
        id: "osr_live1",
        organizationId: ORG,
        provider: "abuseipdb",
        ip: "198.51.100.77",
        score: 93,
        reports: 12,
        checkedAt: new Date(),
      });
      const scoreOf = async (ip: string) =>
        itemsOf(await call("GET", "/api/v1/attacks/events")).find((e) => e.ip === ip)?.score;
      // OSINT is off: a cached result is not shown.
      expect(await scoreOf("198.51.100.77")).toBeNull();
      await t.db
        .insert(schema.attackSettings)
        .values({ organizationId: ORG, osintEnabled: true, osintProvider: "abuseipdb" });
      expect(await scoreOf("198.51.100.77")).toBe(93);
      expect(await scoreOf("10.20.30.40")).toBeNull();
      // Another organisation's result for the same address is not ours.
      await t.db.delete(schema.attackOsintResult);
      expect(await scoreOf("198.51.100.77")).toBeNull();
    });

    it("hands text on as plain strings, as stored, with no log line field", async () => {
      await store({ description: `<img src=x onerror="document.title='pwned'">`, agentName: "<b>x</b>" });
      const r = await call("GET", "/api/v1/attacks/events");
      expect(r.json?.items[0].description).toBe(`<img src=x onerror="document.title='pwned'">`);
      expect(r.text).not.toContain("full_log");
      expect(r.text).not.toContain("raw");
    });

    it("reports the status of the feed honestly", async () => {
      const live = async () => (await call("GET", "/api/v1/attacks/events")).json?.live as Json;
      // Not polled yet.
      expect(await live()).toMatchObject({
        state: "waiting",
        enabled: true,
        intervalSeconds: 30,
        minLevel: 7,
      });
      await t.db.insert(schema.wazuhLiveState).values({
        connectionId,
        organizationId: ORG,
        lastPollAt: new Date(),
        lastEventAt: new Date("2026-10-21T08:00:00Z"),
      });
      expect(await live()).toMatchObject({ state: "live", lastEventAt: "2026-10-21T08:00:00.000Z" });
      await t.db.update(schema.wazuhLiveState).set({ lastError: "unreachable" });
      expect(await live()).toMatchObject({ state: "waiting", error: "unreachable" });
      await t.db.update(schema.wazuhLiveState).set({ lastError: null, enabled: false });
      expect((await live()).state).toBe("off");
      await t.db.update(schema.wazuhLiveState).set({ enabled: true });
      await t.db
        .update(schema.wazuhEndpoint)
        .set({ certStatus: "changed" })
        .where(eq(schema.wazuhEndpoint.kind, "indexer"));
      expect(await live()).toMatchObject({ state: "paused", reason: "certificate" });
      await t.db.update(schema.wazuhEndpoint).set({ certStatus: "confirmed" });
      await t.db
        .update(schema.wazuhConnection)
        .set({ extraPrivileges: ["agent:restart"], acknowledgedPrivileges: [] });
      expect(await live()).toMatchObject({ state: "paused", reason: "privileges" });
      await t.db.update(schema.wazuhConnection).set({ extraPrivileges: [], enabled: false });
      expect(await live()).toMatchObject({ state: "paused", reason: "disabled" });
      await t.db.delete(schema.wazuhConnection);
      expect((await call("GET", "/api/v1/attacks/events")).json?.live).toBeNull();
    });
  });

  /* ------------------------------------------------------------------------ */

  describe("event stream", () => {
    /** Reads server-sent events from a response as they come. */
    function reader(res: Response) {
      const decoder = new TextDecoder();
      const body = (res.body as ReadableStream<Uint8Array>).getReader();
      let buffer = "";
      let pending: ReturnType<typeof body.read> | null = null;
      return {
        async next(timeout = 3000): Promise<{ event: string; id?: string; data: Json } | null> {
          const deadline = Date.now() + timeout;
          for (;;) {
            const end = buffer.indexOf("\n\n");
            if (end >= 0) {
              const block = buffer.slice(0, end);
              buffer = buffer.slice(end + 2);
              if (block.startsWith(":")) continue;
              const event = /^event: (.*)$/m.exec(block)?.[1] ?? "message";
              const id = /^id: (.*)$/m.exec(block)?.[1];
              const data = /^data: (.*)$/m.exec(block)?.[1];
              return { event, ...(id ? { id } : {}), data: data ? JSON.parse(data) : {} };
            }
            const left = deadline - Date.now();
            if (left <= 0) return null;
            pending ??= body.read();
            const chunk = await Promise.race([
              pending,
              new Promise<null>((r) => setTimeout(() => r(null), left)),
            ]);
            if (chunk === null) return null;
            pending = null;
            if (chunk.done) return null;
            buffer += decoder.decode(chunk.value, { stream: true });
          }
        },
        cancel: () => body.cancel().catch(() => {}),
      };
    }
    const open = (
      options: { user?: string; role?: Role; org?: string; lastEventId?: number; after?: number } = {},
    ) =>
      app.request(`/api/v1/attacks/live${options.after !== undefined ? `?after=${options.after}` : ""}`, {
        headers: {
          ...as(options.user ?? "u_member", options.role ?? "member", options.org ?? ORG),
          ...(options.lastEventId !== undefined ? { "last-event-id": String(options.lastEventId) } : {}),
        },
      });

    it("says ready with the newest number and the status, then delivers a new event after NOTIFY", async () => {
      const before = await store({ description: "before" });
      const res = await open();
      expect(res.status).toBe(200);
      expect(res.headers.get("content-type")).toContain("text/event-stream");
      expect(res.headers.get("cache-control")).toContain("no-store");
      const stream = reader(res);
      const ready = await stream.next();
      expect(ready).toMatchObject({ event: "ready", data: { latestSeq: before.seq } });
      expect(ready?.data.live).toMatchObject({ enabled: true });
      // Nothing is replayed for a stream that starts now.
      expect(await stream.next(300)).toBeNull();
      const row = await store({ description: "fresh", ip: "198.51.100.5" });
      await notify(ORG, row.seq);
      const event = await stream.next();
      expect(event?.event).toBe("event");
      expect(event?.id).toBe(String(row.seq));
      expect(event?.data).toMatchObject({
        seq: row.seq,
        description: "fresh",
        ip: "198.51.100.5",
        level: 10,
      });
      expect((await stream.next())?.event).toBe("status");
      await stream.cancel();
    });

    it("resumes from the last event id (header or ?after=) and sends what was missed, in order", async () => {
      const first = await store({ description: "one" });
      await store({ description: "two" });
      await store({ description: "three" });
      for (const options of [{ lastEventId: first.seq }, { after: first.seq }]) {
        const stream = reader(await open(options));
        expect((await stream.next())?.event).toBe("ready");
        const two = await stream.next();
        const three = await stream.next();
        expect([two?.data.description, three?.data.description]).toEqual(["two", "three"]);
        await stream.cancel();
      }
    });

    it("asks the browser to reload the list when too much was missed", async () => {
      for (let i = 0; i < 60; i++) await store({ description: `bulk ${i}` });
      const stream = reader(await open({ lastEventId: 1 }));
      expect((await stream.next())?.event).toBe("ready");
      expect((await stream.next())?.event).toBe("resync");
      expect(await stream.next(300)).toBeNull();
      await stream.cancel();
    });

    it("never delivers another organisation's events, even if that organisation's channel is told", async () => {
      const otherConnection = await seedConnection(OTHER);
      const mine = reader(await open());
      const theirs = reader(await open({ user: "u_other", role: "owner", org: OTHER }));
      expect((await mine.next())?.event).toBe("ready");
      expect((await theirs.next())?.event).toBe("ready");
      const foreign = await store({ description: "only for B" }, OTHER, otherConnection);
      await notify(OTHER, foreign.seq);
      expect((await theirs.next())?.data.description).toBe("only for B");
      expect(await mine.next(500)).toBeNull();
      // A notice on A's channel that names B's number reveals nothing: the rows are read with A's organisation.
      await notify(ORG, foreign.seq);
      expect(await mine.next(500)).toBeNull();
      await Promise.all([mine.cancel(), theirs.cancel()]);
    });

    it("limits open streams per person to four, and frees the slots when they close", async () => {
      const opened = [];
      for (let i = 0; i < 4; i++) {
        const res = await open({ user: "u_owner", role: "owner" });
        expect(res.status).toBe(200);
        opened.push(res);
      }
      const refused = await open({ user: "u_owner", role: "owner" });
      expect(refused.status).toBe(429);
      expect(((await refused.json()) as Json).type).toContain("too-many-streams");
      const other = await open({ user: "u_admin", role: "admin" });
      expect(other.status).toBe(200);
      for (const r of [...opened, other]) await reader(r).cancel();
      await new Promise((resolve) => setTimeout(resolve, 300));
      const again = await open({ user: "u_owner", role: "owner" });
      expect(again.status).toBe(200);
      await reader(again).cancel();
    });
  });

  /* ------------------------------------------------------------------------ */

  describe("home location", () => {
    const patch = (body: unknown, options: Parameters<typeof call>[2] = {}) =>
      call("PATCH", "/api/v1/attacks/settings", { role: "admin", user: "u_admin", ...options, body });

    it("is empty by default: no coordinates are invented", async () => {
      expect((await call("GET", "/api/v1/attacks/settings", { role: "admin" })).json?.home).toBeNull();
      expect((await call("GET", "/api/v1/attacks/overview")).json?.home).toBeNull();
    });

    it("lets owners and admins set it, rounds to two decimals, audits it, and lets everyone read it", async () => {
      for (const role of ["member", "viewer"] as Role[]) {
        expect((await patch({ home: { country: "DE" } }, { role })).status, role).toBe(403);
      }
      const r = await patch({ home: { country: "de", lat: 50.9375, lon: 6.9603 } });
      expect(r.status).toBe(204);
      const expected = { country: "DE", lat: 50.94, lon: 6.96 };
      expect((await call("GET", "/api/v1/attacks/overview", { role: "viewer" })).json?.home).toEqual(
        expected,
      );
      expect((await call("GET", "/api/v1/attacks/settings", { role: "owner" })).json?.home).toEqual(expected);
      const [entry] = await audits("attacks.home_changed");
      expect(entry?.data).toMatchObject({ country: "DE", lat: 50.94, lon: 6.96, previousCountry: null });
      expect(entry?.actorUserId).toBe("u_admin");
      // The same value again is not a change.
      await patch({ home: expected });
      expect(await audits("attacks.home_changed")).toHaveLength(1);
    });

    it("accepts a country alone (the globe then uses its capital) and removes it again", async () => {
      expect((await patch({ home: { country: "AT" } })).status).toBe(204);
      expect((await call("GET", "/api/v1/attacks/settings", { role: "admin" })).json?.home).toEqual({
        country: "AT",
        lat: null,
        lon: null,
      });
      expect((await patch({ home: null })).status).toBe(204);
      expect((await call("GET", "/api/v1/attacks/settings", { role: "admin" })).json?.home).toBeNull();
      expect(await audits("attacks.home_removed")).toHaveLength(1);
      // Removing what is not there changes and audits nothing.
      await patch({ home: null });
      expect(await audits("attacks.home_removed")).toHaveLength(1);
    });

    it("refuses an unknown country, a point out of range, half a point and anything that is not a number", async () => {
      const bad: [unknown, string][] = [
        [{ country: "ZZ" }, "home.country"],
        [{ country: "Germany" }, "home.country"],
        [{ country: "DE", lat: 91, lon: 0 }, "home.lat"],
        [{ country: "DE", lat: 0, lon: 181 }, "home.lon"],
        [{ country: "DE", lat: 10 }, "home.lat"],
      ];
      for (const [home, field] of bad) {
        const r = await patch({ home });
        expect(r.status, JSON.stringify(home)).toBe(422);
        expect(errorsOf(r).map((e) => e.path)).toContain(field);
      }
      for (const home of [{ country: "DE", lat: "50", lon: "6" }, { country: "DE", extra: 1 }, "DE", 5]) {
        expect((await patch({ home })).status, JSON.stringify(home)).toBe(422);
      }
      expect((await call("GET", "/api/v1/attacks/settings", { role: "admin" })).json?.home).toBeNull();
    });

    it("needs no recent sign-in (nothing leaves the network), but is rate-safe and audited", async () => {
      expect((await patch({ home: { country: "FR" } }, { age: STALE })).status).toBe(204);
    });
  });

  /* ------------------------------------------------------------------------ */

  describe("live feed settings", () => {
    const patch = (liveFeed: unknown, options: Parameters<typeof call>[2] = {}) =>
      call("PATCH", "/api/v1/attacks/settings", { role: "admin", ...options, body: { liveFeed } });
    const read = async () =>
      (await call("GET", "/api/v1/attacks/settings", { role: "admin" })).json?.liveFeed as Json;

    it("shows the defaults and the limits", async () => {
      expect(await read()).toMatchObject({
        enabled: true,
        intervalSeconds: 30,
        minLevel: 7,
        limits: {
          intervalSeconds: { min: 15, max: 300, default: 30 },
          minLevel: { min: 3, max: 15, default: 7 },
        },
      });
    });

    it("lets owners and admins change interval, level and the switch, and audits it", async () => {
      for (const role of ["member", "viewer"] as Role[]) {
        expect((await patch({ intervalSeconds: 60 }, { role })).status, role).toBe(403);
      }
      expect((await patch({ intervalSeconds: 60, minLevel: 10 })).status).toBe(204);
      expect(await read()).toMatchObject({ enabled: true, intervalSeconds: 60, minLevel: 10 });
      const [stored] = await t.db.select().from(schema.wazuhLiveState);
      expect(stored).toMatchObject({ connectionId, organizationId: ORG, intervalSeconds: 60, minLevel: 10 });
      expect((await audits("attacks.live_feed_changed"))[0]?.data).toMatchObject({
        enabled: true,
        intervalSeconds: 60,
        minLevel: 10,
      });
      expect((await patch({ enabled: false }, { role: "owner" })).status).toBe(204);
      expect((await read()).state).toBe("off");
      // Switching on starts polling at once and forgets earlier trouble.
      await t.db.update(schema.wazuhLiveState).set({ failures: 4, lastError: "unreachable" });
      expect((await patch({ enabled: true })).status).toBe(204);
      const [again] = await t.db.select().from(schema.wazuhLiveState);
      expect(again).toMatchObject({ enabled: true, failures: 0, lastError: null });
      expect(again?.nextPollAt.getTime()).toBeLessThanOrEqual(Date.now() + 1000);
      // The same values again change and audit nothing.
      const count = (await audits("attacks.live_feed_changed")).length;
      await patch({ intervalSeconds: 60, minLevel: 10, enabled: true });
      expect((await audits("attacks.live_feed_changed")).length).toBe(count);
    });

    it("refuses an interval outside 15 to 300 seconds and a level outside 3 to 15", async () => {
      for (const [body, field] of [
        [{ intervalSeconds: 14 }, "liveFeed.intervalSeconds"],
        [{ intervalSeconds: 301 }, "liveFeed.intervalSeconds"],
        [{ intervalSeconds: 30.5 }, "liveFeed.intervalSeconds"],
        [{ minLevel: 2 }, "liveFeed.minLevel"],
        [{ minLevel: 16 }, "liveFeed.minLevel"],
      ] as const) {
        const r = await patch(body);
        expect(r.status, JSON.stringify(body)).toBe(422);
        expect(errorsOf(r).map((e) => e.path)).toContain(field);
      }
      for (const body of [{ intervalSeconds: "30" }, { enabled: "yes" }, { other: 1 }]) {
        expect((await patch(body)).status, JSON.stringify(body)).toBe(422);
      }
      expect(await t.db.select().from(schema.wazuhLiveState)).toHaveLength(0);
    });

    it("needs a Wazuh connection", async () => {
      await t.db.delete(schema.wazuhConnection);
      const r = await patch({ intervalSeconds: 60 });
      expect(r.status).toBe(409);
      expect(problemCode(r)).toBe("no-connection");
      expect((await call("GET", "/api/v1/attacks/settings", { role: "admin" })).json?.liveFeed).toBeNull();
    });
  });

  describe("erasure", () => {
    it("deletes the stored events with the other stored addresses, and says how many", async () => {
      await store();
      await store();
      const otherConnection = await seedConnection(OTHER);
      await store({}, OTHER, otherConnection);
      const r = await call("DELETE", "/api/v1/attacks/data", { role: "admin" });
      expect(r.status).toBe(200);
      expect(r.json).toMatchObject({ attackEvents: 2 });
      expect(await t.db.select().from(schema.wazuhAttackEvent)).toHaveLength(1);
      expect((await audits("attacks.data_purged"))[0]?.data).toMatchObject({ attackEvents: 2 });
    });
  });
});
