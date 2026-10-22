/**
 * The attack overview with UniFi threat events (ADR 0022) against a throw-away PostgreSQL database on the development
 * server: the latest events of both origins in one list and one stream (the shared sequence number, resuming, one
 * organisation never sees another's), the aggregates that join the Wazuh numbers (per country, per address, blocked
 * versus observed), the page working with UniFi alone, the navigation flag, and the erasure that includes the events.
 * Sessions are replaced by a header-driven actor. Only documentation address ranges and example names appear. Skipped
 * without the development PostgreSQL.
 */
import { liveChannel } from "@garnetops/core/attack-live";
import { type GeoipRow, newParseStats } from "@garnetops/core/geoip";
import { importDataset, schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { Hono } from "hono";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();
const holder = vi.hoisted(() => ({ db: null as unknown, sent: [] as { name: string; data: unknown }[] }));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null, boss: null, QUEUES: {} };
  const t = await create(target, "api_attacks_unifi");
  holder.db = t;
  return {
    db: t.db,
    pool: t.pool,
    boss: {
      send: async (name: string, data: unknown) => {
        holder.sent.push({ name, data });
        return "job";
      },
    },
    QUEUES: { attackSummary: "attacks.summary" },
  };
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
const ORG = "org_ufa_a";
const OTHER = "org_ufa_b";

async function* rowsOf(rows: GeoipRow[]) {
  for (const row of rows) yield row;
}

describe.skipIf(!adminUrl)("attack overview with UniFi threat events", () => {
  let t: TestDatabase;
  let app: Hono;
  let counter = 0;

  async function call(
    method: string,
    path: string,
    options: { role?: Role; org?: string; age?: number; body?: unknown } = {},
  ) {
    const headers: Record<string, string> = {
      "x-user": "u_member",
      "x-role": options.role ?? "member",
      "x-org": options.org ?? ORG,
      "x-age": String(options.age ?? 0),
    };
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
  const windowOf = (r: { json: Json | null }): Json => (r.json?.window ?? {}) as Json;

  async function seedUnifi(org = ORG, over: Partial<typeof schema.unifiConnection.$inferInsert> = {}) {
    const id = `ufc_ufa${String(++counter).padStart(10, "0")}`;
    await t.db.insert(schema.unifiConnection).values({
      id,
      organizationId: org,
      name: `Console ${counter}`,
      apiUrl: `https://udm${counter}.example.lan:443`,
      host: `udm${counter}.example.lan`,
      port: 443,
      certStatus: "confirmed",
      certFingerprint: "AA:BB",
      apiBase: "unifi-os",
      lastSyncAt: new Date(),
      ...over,
    });
    return id;
  }
  async function seedWazuh(org = ORG) {
    const id = `wzc_ufa${String(++counter).padStart(10, "0")}`;
    await t.db.insert(schema.wazuhConnection).values({
      id,
      organizationId: org,
      name: "Seeded lab",
      adapter: "wazuh4",
      lastSyncAt: new Date(),
    });
    return id;
  }

  let docs = 0;
  async function unifiEvent(
    connectionId: string,
    over: Partial<typeof schema.unifiThreatEvent.$inferInsert> = {},
    org = ORG,
  ) {
    const [row] = await t.db
      .insert(schema.unifiThreatEvent)
      .values({
        organizationId: org,
        connectionId,
        docId: `uf-${++docs}`,
        at: new Date(),
        ip: "198.51.100.77",
        action: "blocked",
        signature: "ET SCAN Example SSH brute force",
        category: "Attempted Administrator Privilege Gain",
        destPort: 22,
        proto: "tcp",
        siteName: "Main office",
        ...over,
      })
      .returning();
    return row as typeof schema.unifiThreatEvent.$inferSelect;
  }
  async function wazuhEvent(
    connectionId: string,
    over: Partial<typeof schema.wazuhAttackEvent.$inferInsert> = {},
  ) {
    const [row] = await t.db
      .insert(schema.wazuhAttackEvent)
      .values({
        organizationId: ORG,
        connectionId,
        docId: `wz-${++docs}`,
        at: new Date(),
        ip: "198.51.100.88",
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
    const { xdrRoutes } = await import("./xdr.ts");
    t = holder.db as TestDatabase;
    await t.db.insert(schema.organization).values([
      { id: ORG, name: "A" },
      { id: OTHER, name: "B" },
    ]);
    await t.db.insert(schema.user).values({ id: "u_member", name: "Member", email: "u_member@example.test" });
    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        {
          userId: "u_member",
          email: "u_member@example.test",
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
    v1.route("/xdr", xdrRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
    await importDataset(t.db, {
      kind: "country",
      source: "import",
      month: "2026-10",
      importedBy: null,
      rows: rowsOf([
        { start: "198.51.100.0", end: "198.51.100.255", country: "DE" },
        { start: "203.0.113.0", end: "203.0.113.255", country: "NL" },
      ]),
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
  }, 60_000);

  afterAll(async () => {
    const { listenBus } = await import("../lib/listen-bus.ts");
    await listenBus.close();
    await t?.drop();
  });

  beforeEach(async () => {
    await t.pool.query(
      "truncate wazuh_connection, unifi_connection, wazuh_source_ip, wazuh_attack_window, attack_settings, audit_log, rate_limit restart identity cascade",
    );
  });

  describe("the latest events", () => {
    it("lists Wazuh alerts and UniFi events together in the order of their shared number", async () => {
      const wazuh = await seedWazuh();
      const unifi = await seedUnifi(ORG, { ipsEnabled: true, ipsUsername: "garnetops-view" });
      const a = await wazuhEvent(wazuh, { description: "first, from Wazuh" });
      const b = await unifiEvent(unifi, { signature: "second, from UniFi" });
      const c = await wazuhEvent(wazuh, { description: "third, from Wazuh" });
      const d = await unifiEvent(unifi, { signature: "fourth, from UniFi", action: "alerted" });
      expect([a.seq, b.seq, c.seq, d.seq]).toEqual([...[a.seq, b.seq, c.seq, d.seq]].sort((x, y) => x - y));
      expect(new Set([a.seq, b.seq, c.seq, d.seq]).size).toBe(4);

      const r = await call("GET", "/api/v1/attacks/events");
      expect(r.status).toBe(200);
      expect(itemsOf(r).map((e) => e.seq)).toEqual([d.seq, c.seq, b.seq, a.seq]);
      expect(r.json?.latestSeq).toBe(d.seq);
      const items = itemsOf(r);
      expect(items[3]).toMatchObject({
        source: "wazuh",
        action: null,
        destPort: null,
        level: 10,
        agentName: "web-01",
      });
      expect(items[2]).toMatchObject({
        source: "unifi",
        action: "blocked",
        description: "second, from UniFi",
        groups: ["Attempted Administrator Privilege Gain"],
        destPort: 22,
        agentName: "Main office",
        level: 0,
        ruleId: "",
      });
      expect(items[0]).toMatchObject({ source: "unifi", action: "alerted" });
      // The preview's own state travels with the list.
      expect(r.json?.unifi).toMatchObject({ enabled: true, connections: 1 });
      expect(r.json?.live).not.toBeNull();
    });

    it("works with UniFi alone, and says nothing of the preview while it is off", async () => {
      const unifi = await seedUnifi();
      await unifiEvent(unifi);
      const r = await call("GET", "/api/v1/attacks/events");
      expect(itemsOf(r)).toHaveLength(1);
      expect(r.json?.live).toBeNull();
      expect(r.json?.unifi).toBeNull();
    });

    it("never shows another organisation's events", async () => {
      const mine = await seedUnifi();
      const theirs = await seedUnifi(OTHER);
      await unifiEvent(mine, { signature: "mine" });
      await unifiEvent(theirs, { signature: "not for A" }, OTHER);
      expect(itemsOf(await call("GET", "/api/v1/attacks/events")).map((e) => e.description)).toEqual([
        "mine",
      ]);
      expect(
        itemsOf(await call("GET", "/api/v1/attacks/events", { org: OTHER })).map((e) => e.description),
      ).toEqual(["not for A"]);
    });

    it("shows country and network of a UniFi event from the local tables; internal addresses are labelled", async () => {
      const unifi = await seedUnifi();
      await unifiEvent(unifi, { ip: "198.51.100.77" });
      await unifiEvent(unifi, { ip: "10.20.30.40" });
      const items = itemsOf(await call("GET", "/api/v1/attacks/events"));
      expect(items.find((e) => e.ip === "198.51.100.77")).toMatchObject({
        scope: "public",
        country: "DE",
        asn: 64500,
      });
      expect(items.find((e) => e.ip === "10.20.30.40")).toMatchObject({ scope: "internal", country: null });
    });

    it("reports the state of the preview honestly", async () => {
      const id = await seedUnifi(ORG, {
        ipsEnabled: true,
        ipsUsername: "garnetops-view",
        certStatus: "pending",
        certFingerprint: null,
      });
      const state = async () => (await call("GET", "/api/v1/attacks/events")).json?.unifi;
      expect(await state()).toMatchObject({ state: "paused", reason: "certificate" });
      await t.db.update(schema.unifiConnection).set({ certStatus: "confirmed", certFingerprint: "AA:BB" });
      expect(await state()).toMatchObject({ state: "paused", reason: "credentials" });
      await t.pool.query(
        "insert into secret (id, organization_id, purpose, sealed, vault_key_id) values ('sec_x', $1, 'unifi-ips-password', '{}', 'k')",
        [ORG],
      );
      await t.db.update(schema.unifiConnection).set({ ipsSecretId: "sec_x" });
      expect(await state()).toMatchObject({ state: "waiting" });
      await t.db
        .update(schema.unifiConnection)
        .set({ ipsLastPollAt: new Date(), ipsLastEventAt: new Date() });
      expect(await state()).toMatchObject({ state: "live" });
      await t.db
        .update(schema.unifiConnection)
        .set({ ipsLastError: "The console reported an error. Check the console." });
      expect(await state()).toMatchObject({
        state: "waiting",
        error: "The console reported an error. Check the console.",
      });
      // Rights beyond viewing that nobody acknowledged pause the preview, also on the Attacks page.
      await t.db.update(schema.unifiConnection).set({ ipsRights: ["owner"] });
      expect(await state()).toMatchObject({ state: "paused", reason: "rights" });
      void id;
    });
  });

  describe("event stream", () => {
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
    const open = (options: { org?: string; lastEventId?: number } = {}) =>
      app.request("/api/v1/attacks/live", {
        headers: {
          "x-user": "u_member",
          "x-role": "member",
          "x-org": options.org ?? ORG,
          "x-age": "0",
          ...(options.lastEventId !== undefined ? { "last-event-id": String(options.lastEventId) } : {}),
        },
      });

    it("delivers a UniFi event after NOTIFY with its action, and says ready with the shared newest number", async () => {
      const wazuh = await seedWazuh();
      const unifi = await seedUnifi(ORG, { ipsEnabled: true, ipsUsername: "garnetops-view" });
      const before = await wazuhEvent(wazuh);
      const stream = reader(await open());
      const ready = await stream.next();
      expect(ready).toMatchObject({ event: "ready", data: { latestSeq: before.seq } });
      expect(ready?.data.unifi).toMatchObject({ enabled: true });
      const row = await unifiEvent(unifi, { signature: "fresh block", ip: "203.0.113.5" });
      await notify(ORG, row.seq);
      const event = await stream.next();
      expect(event).toMatchObject({
        event: "event",
        id: String(row.seq),
        data: { seq: row.seq, source: "unifi", action: "blocked", description: "fresh block", country: "NL" },
      });
      expect((await stream.next())?.event).toBe("status");
      await stream.cancel();
    });

    it("resumes across both origins by the one number, in order", async () => {
      const wazuh = await seedWazuh();
      const unifi = await seedUnifi();
      const first = await wazuhEvent(wazuh, { description: "one" });
      await unifiEvent(unifi, { signature: "two" });
      await wazuhEvent(wazuh, { description: "three" });
      await unifiEvent(unifi, { signature: "four" });
      const stream = reader(await open({ lastEventId: first.seq }));
      expect((await stream.next())?.event).toBe("ready");
      const got = [await stream.next(), await stream.next(), await stream.next()];
      expect(got.map((g) => g?.data.description)).toEqual(["two", "three", "four"]);
      expect(got.map((g) => g?.data.source)).toEqual(["unifi", "wazuh", "unifi"]);
      await stream.cancel();
    });

    it("never delivers another organisation's UniFi events", async () => {
      const theirs = await seedUnifi(OTHER);
      const mine = reader(await open());
      expect((await mine.next())?.event).toBe("ready");
      const foreign = await unifiEvent(theirs, { signature: "only for B" }, OTHER);
      await notify(OTHER, foreign.seq);
      await notify(ORG, foreign.seq);
      expect(await mine.next(500)).toBeNull();
      await mine.cancel();
    });

    it("asks the browser to reload when too much was missed", async () => {
      const unifi = await seedUnifi();
      for (let i = 0; i < 60; i++) await unifiEvent(unifi, { signature: `bulk ${i}`, ip: "203.0.113.9" });
      const stream = reader(await open({ lastEventId: 1 }));
      expect((await stream.next())?.event).toBe("ready");
      expect((await stream.next())?.event).toBe("resync");
      await stream.cancel();
    });
  });

  describe("the overview", () => {
    it("shows nothing connected without Wazuh and without UniFi events", async () => {
      const r = await call("GET", "/api/v1/attacks/overview");
      expect(r.json).toMatchObject({ connected: false, window: null });
      await seedUnifi();
      // A console with the preview off and no events does not make the page appear.
      expect((await call("GET", "/api/v1/attacks/overview")).json).toMatchObject({ connected: false });
    });

    it("works with UniFi alone: numbers, countries, blocked versus observed, and the sources table", async () => {
      const unifi = await seedUnifi(ORG, { ipsEnabled: true, ipsUsername: "garnetops-view" });
      await unifiEvent(unifi, { ip: "198.51.100.1", action: "blocked" });
      await unifiEvent(unifi, { ip: "198.51.100.1", action: "blocked" });
      await unifiEvent(unifi, { ip: "198.51.100.1", action: "alerted" });
      await unifiEvent(unifi, { ip: "203.0.113.5", action: "blocked" });
      await unifiEvent(unifi, { ip: "10.1.2.3", action: "alerted" });
      await unifiEvent(unifi, { ip: "198.51.100.9", at: new Date(Date.now() - 30 * 3_600_000) });
      const r = await call("GET", "/api/v1/attacks/overview?period=24h");
      expect(r.json).toMatchObject({ connected: true, syncedAt: null, live: null, unifi: { enabled: true } });
      const w = windowOf(r);
      expect(w).toMatchObject({
        attackAlerts: 5,
        distinctSources: 3,
        previousAttackAlerts: 1,
        previousDistinctSources: 1,
        listedSources: 3,
        listedAlerts: 5,
        blockedAlerts: 3,
        agents: [],
        internal: { alerts: 1, sources: 1 },
      });
      expect(w.countries).toEqual([
        { country: "DE", alerts: 3, sources: 1, blocked: 2 },
        { country: "NL", alerts: 1, sources: 1, blocked: 1 },
      ]);
      // The week reaches the older event too.
      expect(windowOf(await call("GET", "/api/v1/attacks/overview?period=7d")).attackAlerts).toBe(6);

      const sources = await call("GET", "/api/v1/attacks/sources?period=24h");
      const rows = itemsOf(sources).map((s) => [s.ip, s.count, s.blocked]);
      // The busiest first; addresses with the same count may come in either order.
      expect(rows[0]).toEqual(["198.51.100.1", 3, 2]);
      expect(rows.slice(1).sort()).toEqual([
        ["10.1.2.3", 1, 0],
        ["203.0.113.5", 1, 1],
      ]);
      expect(itemsOf(await call("GET", "/api/v1/attacks/sources?country=NL"))).toHaveLength(1);
      expect(itemsOf(await call("GET", "/api/v1/attacks/sources?country=internal"))).toHaveLength(1);
    });

    it("joins the numbers of Wazuh and UniFi, and counts an address both saw once", async () => {
      const wazuh = await seedWazuh();
      const unifi = await seedUnifi(ORG, { ipsEnabled: true, ipsUsername: "garnetops-view" });
      const now = new Date();
      await t.db.insert(schema.wazuhAttackWindow).values({
        organizationId: ORG,
        connectionId: wazuh,
        window: "24h",
        attackAlerts: 100,
        distinctSources: 2,
        agents: [{ agentId: "001", name: "web-01", count: 100 }],
        previousAttackAlerts: 40,
        previousDistinctSources: 2,
        previousSources: [],
        readAt: now,
      });
      await t.db.insert(schema.wazuhSourceIp).values([
        {
          id: "wzs_1",
          organizationId: ORG,
          connectionId: wazuh,
          window: "24h",
          ip: "198.51.100.1",
          count: 90,
          groups: ["attack"],
          seenAt: now,
          agents: [{ agentId: "001", name: "web-01", count: 90 }],
        },
        {
          id: "wzs_2",
          organizationId: ORG,
          connectionId: wazuh,
          window: "24h",
          ip: "198.51.100.2",
          count: 10,
          groups: ["attack"],
          seenAt: now,
          agents: [],
        },
      ]);
      await unifiEvent(unifi, { ip: "198.51.100.1", action: "blocked" });
      await unifiEvent(unifi, { ip: "198.51.100.1", action: "blocked" });
      await unifiEvent(unifi, { ip: "203.0.113.5", action: "alerted" });
      const w = windowOf(await call("GET", "/api/v1/attacks/overview"));
      expect(w).toMatchObject({
        attackAlerts: 103,
        // Two Wazuh sources, and one of UniFi's two is already among them.
        distinctSources: 3,
        previousAttackAlerts: 40,
        listedSources: 3,
        listedAlerts: 103,
        blockedAlerts: 2,
      });
      expect(w.agents).toEqual([{ agentId: "001", name: "web-01", count: 100, hostId: null }]);
      const de = (w.countries as Json[]).find((c) => c.country === "DE") as Json;
      expect(de).toMatchObject({ alerts: 102, sources: 2, blocked: 2 });
      const rows = itemsOf(await call("GET", "/api/v1/attacks/sources"));
      expect(rows.find((r) => r.ip === "198.51.100.1")).toMatchObject({
        count: 92,
        blocked: 2,
        groups: ["attack"],
      });
    });

    it("keeps the page as it was for Wazuh alone (no blocked figures)", async () => {
      const wazuh = await seedWazuh();
      await t.db.insert(schema.wazuhAttackWindow).values({
        organizationId: ORG,
        connectionId: wazuh,
        window: "24h",
        attackAlerts: 10,
        distinctSources: 1,
        agents: [],
        previousAttackAlerts: null,
        previousDistinctSources: null,
        previousSources: [],
        readAt: new Date(),
      });
      await t.db.insert(schema.wazuhSourceIp).values({
        id: "wzs_9",
        organizationId: ORG,
        connectionId: wazuh,
        window: "24h",
        ip: "198.51.100.1",
        count: 10,
        groups: [],
        seenAt: new Date(),
        agents: [],
      });
      const r = await call("GET", "/api/v1/attacks/overview");
      expect(r.json?.unifi).toBeNull();
      const w = windowOf(r);
      expect(w).toMatchObject({ attackAlerts: 10, previousAttackAlerts: null, blockedAlerts: 0 });
      expect(w.countries).toEqual([{ country: "DE", alerts: 10, sources: 1 }]);
      expect(itemsOf(await call("GET", "/api/v1/attacks/sources"))[0]).toMatchObject({ blocked: 0 });
    });

    it("scopes everything to the organisation", async () => {
      const theirs = await seedUnifi(OTHER, { ipsEnabled: true, ipsUsername: "garnetops-view" });
      await unifiEvent(theirs, { ip: "198.51.100.1" }, OTHER);
      expect((await call("GET", "/api/v1/attacks/overview")).json).toMatchObject({ connected: false });
      expect(itemsOf(await call("GET", "/api/v1/attacks/sources"))).toEqual([]);
      expect(windowOf(await call("GET", "/api/v1/attacks/overview", { org: OTHER })).attackAlerts).toBe(1);
    });
  });

  describe("navigation and erasure", () => {
    it("lists the Attacks entry while a console has the preview on or events are stored, even without Wazuh", async () => {
      const status = async () => (await call("GET", "/api/v1/xdr/status")).json;
      expect(await status()).toEqual({ connected: false, attacks: false });
      const unifi = await seedUnifi();
      expect(await status()).toEqual({ connected: false, attacks: false });
      await t.db.update(schema.unifiConnection).set({ ipsEnabled: true, ipsUsername: "garnetops-view" });
      expect(await status()).toEqual({ connected: false, attacks: true });
      await t.db.update(schema.unifiConnection).set({ ipsEnabled: false });
      await unifiEvent(unifi);
      expect(await status()).toEqual({ connected: false, attacks: true });
      await seedWazuh();
      expect(await status()).toEqual({ connected: true, attacks: true });
    });

    it("deletes the stored UniFi events with the other addresses, counts them in the audit entry, and keeps the cursor", async () => {
      const unifi = await seedUnifi(ORG, { ipsCursorAt: new Date("2026-10-22T10:00:00Z") });
      const theirs = await seedUnifi(OTHER);
      await unifiEvent(unifi);
      await unifiEvent(unifi);
      await unifiEvent(theirs, {}, OTHER);
      expect((await call("DELETE", "/api/v1/attacks/data", { role: "member" })).status).toBe(403);
      expect((await call("DELETE", "/api/v1/attacks/data", { role: "admin", age: 11 * 60 })).status).toBe(
        403,
      );
      const r = await call("DELETE", "/api/v1/attacks/data", { role: "admin" });
      expect(r.status).toBe(200);
      const events = await t.db.select().from(schema.unifiThreatEvent);
      expect(events.map((e) => e.organizationId)).toEqual([OTHER]);
      const [row] = await t.db.select().from(schema.unifiConnection);
      expect(row?.ipsCursorAt?.toISOString()).toBe("2026-10-22T10:00:00.000Z");
      const audit = (await t.db.select().from(schema.auditLog)).filter(
        (a) => a.action === "attacks.data_purged",
      );
      expect(audit[0]?.data).toMatchObject({ attackEvents: 2 });
    });
  });

  describe("the AI summary", () => {
    const configureAi = () =>
      t.db
        .insert(schema.aiSettings)
        .values({
          organizationId: ORG,
          enabled: true,
          baseUrl: "https://llm.example.lan/v1",
          model: "example-model",
        } as never)
        .onConflictDoNothing();

    it("can be asked for with UniFi events alone, and not without any data", async () => {
      await configureAi();
      holder.sent.length = 0;
      // A console with the preview off and no events: no source of attack data at all.
      const unifi = await seedUnifi(ORG);
      expect((await call("POST", "/api/v1/attacks/summary", { body: {} })).status).toBe(404);
      expect(holder.sent).toEqual([]);

      // Preview on, nothing stored yet: nothing to summarise.
      await t.db.update(schema.unifiConnection).set({ ipsEnabled: true });
      const empty = await call("POST", "/api/v1/attacks/summary", { body: {} });
      expect(empty.status).toBe(409);
      expect(empty.text).toContain("no-data");
      expect(holder.sent).toEqual([]);

      await unifiEvent(unifi, { ip: "198.51.100.77", action: "blocked" });
      const ok = await call("POST", "/api/v1/attacks/summary", { body: { language: "de" } });
      expect(ok.status).toBe(202);
      expect(holder.sent[0]).toMatchObject({ name: "attacks.summary", data: { summaryId: ok.json?.id } });
      // No Wazuh connection: the summary belongs to the organisation, and the audit entry names the origin, not data.
      const [row] = await t.db.select().from(schema.attackSummary);
      expect(row).toMatchObject({
        organizationId: ORG,
        connectionId: null,
        status: "pending",
        language: "de",
      });
      const audit = (await t.db.select().from(schema.auditLog)).filter((a) => a.action === "ai.request");
      expect(audit[0]).toMatchObject({ targetType: "organization", targetId: ORG });
      expect(audit[0]?.data).toMatchObject({ kind: "attack-summary", sources: ["unifi"] });
      expect(JSON.stringify(audit[0]?.data)).not.toMatch(/198\.51\.100|SSH brute force/);
      const latest = await call("GET", "/api/v1/attacks/summary");
      expect(latest.json?.summary).toMatchObject({ status: "pending", language: "de" });
    });

    it("does not count another organisation's events", async () => {
      await configureAi();
      await seedUnifi(ORG, { ipsEnabled: true });
      const theirs = await seedUnifi(OTHER);
      await unifiEvent(theirs, {}, OTHER);
      expect((await call("POST", "/api/v1/attacks/summary", { body: {} })).status).toBe(409);
    });
  });
});
