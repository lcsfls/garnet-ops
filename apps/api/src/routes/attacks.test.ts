/**
 * The attack overview API (ADR 0016) against a throw-away PostgreSQL database on the development
 * server: who may read and change, step-up, the page data enriched from the local GeoIP tables,
 * the filtered, sorted and paged address table, the settings (retention, opt-in download, OSINT
 * with its key sealed in the vault), the streamed GeoIP upload with its limits and its refusal of
 * wrong, damaged and hostile files, erasure, and the AI summary request. Sessions are replaced by
 * a header-driven actor; the queue is a recorder. Only documentation address ranges and example
 * names appear. Skipped without the development PostgreSQL.
 */
import { gzipSync } from "node:zlib";
import type { GeoipRow } from "@garnetops/core/geoip";
import { newParseStats } from "@garnetops/core/geoip";
import { loadVaultPrivateKey, open } from "@garnetops/core/vault";
import { importDataset, schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();

const queue = vi.hoisted(() => ({
  sent: [] as { name: string; data: Record<string, unknown>; options: Record<string, unknown> }[],
  db: null as unknown,
  vault: null as null | { publicKeyPem: string; privateKeyPem: string },
}));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null, boss: null, QUEUES: {} };
  const t = await create(target, "api_attacks");
  queue.db = t;
  return {
    db: t.db,
    pool: t.pool,
    boss: {
      send: async (name: string, data: Record<string, unknown>, options: Record<string, unknown>) => {
        queue.sent.push({ name, data, options });
        return "job";
      },
    },
    QUEUES: { attackSummary: "attacks.summary" },
  };
});
vi.mock("../env.ts", async () => {
  const { generateVaultKeyPair: generate, loadVaultPublicKey } = await import("@garnetops/core/vault");
  queue.vault = generate();
  return {
    env: { PUBLIC_URL: "https://garnetops.example.test/" },
    isProduction: false,
    vaultPublicKey: loadVaultPublicKey(queue.vault.publicKeyPem),
  };
});
vi.mock("../auth.ts", () => ({ auth: { api: {} } }));

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
type Role = "owner" | "admin" | "member" | "viewer";
const ORG = "org_atk_a";
const OTHER = "org_atk_b";
const STALE = 11 * 60;
/** A made-up key. It must never appear in a row other than sealed, in an audit entry or in a response. */
const API_KEY = ["0123456789abcdef", "0123456789abcdef", "0123456789abcdef"].join("");

const COUNTRY_RANGES: GeoipRow[] = [
  { start: "198.51.100.0", end: "198.51.100.255", country: "DE" },
  { start: "203.0.113.0", end: "203.0.113.255", country: "FR" },
  { start: "192.0.2.0", end: "192.0.2.127", country: "NL" },
  { start: "2001:db8::", end: "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", country: "BR" },
];
const ASN_RANGES: GeoipRow[] = [
  { start: "198.51.100.0", end: "198.51.100.255", asn: 64500, org: "Example Hosting GmbH" },
  { start: "203.0.113.0", end: "203.0.113.255", asn: 64501, org: "Exemple Réseau" },
  { start: "2001:db8::", end: "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", asn: 64502, org: "Exemplo Telecom" },
];

async function* rowsOf(rows: GeoipRow[]) {
  for (const row of rows) yield row;
}
const csv = (lines: string[]) => gzipSync(Buffer.from(`${lines.join("\n")}\n`));

describe.skipIf(!adminUrl)("attack overview API", () => {
  let t: TestDatabase;
  let app: Hono;
  let counter = 0;

  async function call(
    method: string,
    path: string,
    options: { role?: Role; org?: string; age?: number; body?: unknown } = {},
  ) {
    const headers: Record<string, string> = {
      "x-role": options.role ?? "admin",
      "x-org": options.org ?? ORG,
      "x-age": String(options.age ?? 0),
      "x-ip": "198.51.100.7",
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
  async function upload(
    kind: string,
    body: Uint8Array | null,
    options: { role?: Role; age?: number; filename?: string; length?: number | null } = {},
  ) {
    const headers: Record<string, string> = {
      "x-role": options.role ?? "admin",
      "x-org": ORG,
      "x-age": String(options.age ?? 0),
      "content-type": "application/gzip",
    };
    if (options.length !== null) headers["content-length"] = String(options.length ?? body?.length ?? 0);
    const query = options.filename ? `?filename=${encodeURIComponent(options.filename)}` : "";
    const res = await app.request(`/api/v1/attacks/geoip/${kind}${query}`, {
      method: "PUT",
      headers,
      body: body as never,
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
  /** The `items` of a list answer, or an empty list. */
  const itemsOf = (r: { json: Json | null }): Json[] => (r.json?.items ?? []) as Json[];
  const problemCode = (r: { json: Json | null }) =>
    String(r.json?.type ?? "")
      .split("/")
      .pop();
  const audits = async (action: string) =>
    (await t.db.select().from(schema.auditLog)).filter((a) => a.action === action);

  async function seedConnection(org = ORG) {
    const id = `wzc_atk${String(++counter).padStart(10, "0")}`;
    await t.db.insert(schema.wazuhConnection).values({
      id,
      organizationId: org,
      name: "Seeded lab",
      adapter: "wazuh4",
      lastSyncAt: new Date(),
    });
    return id;
  }
  async function seedSources(
    connectionId: string,
    window: "24h" | "7d" | "30d",
    rows: {
      ip: string;
      count: number;
      groups?: string[];
      agents?: { agentId: string; name: string; count: number }[];
      first?: string | null;
      last?: string | null;
    }[],
    org = ORG,
  ) {
    await t.db.insert(schema.wazuhSourceIp).values(
      rows.map((r) => ({
        id: `wzs_atk${String(++counter).padStart(10, "0")}`,
        organizationId: org,
        connectionId,
        window,
        ip: r.ip,
        count: r.count,
        groups: r.groups ?? ["authentication_failed"],
        seenAt: new Date(),
        firstSeenAt: r.first ? new Date(r.first) : null,
        lastSeenAt: r.last ? new Date(r.last) : null,
        agents: r.agents ?? [],
      })),
    );
  }
  async function seedWindow(
    connectionId: string,
    window: "24h" | "7d" | "30d",
    over: Partial<typeof schema.wazuhAttackWindow.$inferInsert> = {},
    org = ORG,
  ) {
    await t.db.insert(schema.wazuhAttackWindow).values({
      organizationId: org,
      connectionId,
      window,
      attackAlerts: 500,
      distinctSources: 6,
      agents: [
        { agentId: "001", name: "web-01", count: 300 },
        { agentId: "002", name: "db-01", count: 100 },
      ],
      previousAttackAlerts: 400,
      previousDistinctSources: 4,
      previousSources: [
        { ip: "198.51.100.5", count: 100 },
        { ip: "203.0.113.5", count: 50 },
        { ip: "10.1.1.1", count: 5 },
      ],
      readAt: new Date(),
      ...over,
    });
  }
  async function loadGeo() {
    await importDataset(t.db, {
      kind: "country",
      source: "import",
      month: "2026-10",
      importedBy: null,
      rows: rowsOf(COUNTRY_RANGES),
      stats: newParseStats(),
    });
    await importDataset(t.db, {
      kind: "asn",
      source: "import",
      month: "2026-10",
      importedBy: null,
      rows: rowsOf(ASN_RANGES),
      stats: newParseStats(),
    });
  }
  /** A connection with six sources in the 24 h window, and the geo data loaded. */
  async function seedPage() {
    await loadGeo();
    const id = await seedConnection();
    await seedWindow(id, "24h");
    await seedSources(id, "24h", [
      {
        ip: "198.51.100.77",
        count: 200,
        groups: ["authentication_failed", "authentication_failures"],
        agents: [{ agentId: "001", name: "web-01", count: 200 }],
        first: "2026-10-21T08:00:00Z",
        last: "2026-10-22T07:00:00Z",
      },
      {
        ip: "198.51.100.78",
        count: 80,
        agents: [
          { agentId: "001", name: "web-01", count: 50 },
          { agentId: "002", name: "db-01", count: 30 },
        ],
      },
      {
        ip: "203.0.113.9",
        count: 120,
        groups: ["web_scan"],
        agents: [{ agentId: "001", name: "web-01", count: 120 }],
      },
      { ip: "2001:db8::bad", count: 30, groups: ["invalid_login"] },
      { ip: "10.9.8.7", count: 20 },
      { ip: "192.0.2.50", count: 10 },
      { ip: "100.64.1.1", count: 4 },
      { ip: "192.0.2.200", count: 1 },
    ]);
    return id;
  }

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { attackRoutes } = await import("./attacks.ts");
    t = queue.db as TestDatabase;
    await t.db.insert(schema.organization).values([
      { id: ORG, name: "A" },
      { id: OTHER, name: "B" },
    ]);
    await t.db.insert(schema.user).values({ id: "user_a", name: "Erika", email: "erika@example.test" });
    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        {
          userId: "user_a",
          email: "erika@example.test",
          name: "Erika",
          organizationId: c.req.header("x-org"),
          role: c.req.header("x-role"),
          ip: c.req.header("x-ip") ?? null,
          strongAuthAt: new Date(Date.now() - Number(c.req.header("x-age") ?? 0) * 1000),
        } as never,
      );
      await next();
    });
    v1.route("/attacks", attackRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  });
  beforeEach(async () => {
    queue.sent.length = 0;
    await t.db.delete(schema.wazuhConnection);
    await t.db.delete(schema.attackSettings);
    await t.db.delete(schema.attackOsintResult);
    await t.db.delete(schema.geoipDataset);
    await t.db.delete(schema.secret);
    await t.db.delete(schema.aiSettings);
    await t.db.delete(schema.auditLog);
  });

  describe("who may do what", () => {
    it("lets every member read the page and the table, but only admins open the settings", async () => {
      await seedPage();
      for (const role of ["viewer", "member", "admin", "owner"] as Role[]) {
        for (const path of ["overview", "sources", "summary"]) {
          expect((await call("GET", `/api/v1/attacks/${path}`, { role })).status, `${role} ${path}`).toBe(
            200,
          );
        }
        const settings = await call("GET", "/api/v1/attacks/settings", { role });
        expect(settings.status, role).toBe(role === "admin" || role === "owner" ? 200 : 403);
      }
    });

    it("lets only owners and admins change anything, and asks for a recent sign-in", async () => {
      const writes: [string, string, unknown][] = [
        ["PATCH", "/api/v1/attacks/settings", { retentionDays: 30 }],
        ["DELETE", "/api/v1/attacks/geoip/country", undefined],
        ["DELETE", "/api/v1/attacks/data", undefined],
      ];
      for (const role of ["viewer", "member"] as Role[]) {
        for (const [method, path, body] of writes) {
          expect((await call(method, path, { role, body })).status, `${role} ${method} ${path}`).toBe(403);
        }
        expect((await upload("country", csv(["198.51.100.0,198.51.100.255,DE"]), { role })).status).toBe(403);
      }
      for (const [method, path, body] of writes.slice(1)) {
        const r = await call(method, path, { age: STALE, body });
        expect(r.status, `${method} ${path}`).toBe(403);
        expect(problemCode(r)).toBe("step-up-required");
      }
      const stale = await upload("country", csv(["198.51.100.0,198.51.100.255,DE"]), { age: STALE });
      expect(problemCode(stale)).toBe("step-up-required");
      expect(await t.db.select().from(schema.geoipDataset)).toHaveLength(0);
    });
  });

  describe("the page", () => {
    it("has nothing to show without a Wazuh connection", async () => {
      const r = await call("GET", "/api/v1/attacks/overview");
      expect(r.json).toMatchObject({ connected: false, window: null });
      expect(r.json?.attribution.text).toBe("IP geolocation by DB-IP (db-ip.com), CC BY 4.0");
      const list = await call("GET", "/api/v1/attacks/sources");
      expect(list.json).toMatchObject({ items: [], total: 0 });
    });

    it("counts attacks, countries and sources from the local tables, with the change against the previous period", async () => {
      await seedPage();
      const r = await call("GET", "/api/v1/attacks/overview?period=24h");
      expect(r.status).toBe(200);
      const w = r.json?.window as Json;
      expect(w).toMatchObject({
        attackAlerts: 500,
        previousAttackAlerts: 400,
        distinctSources: 6,
        previousDistinctSources: 4,
        listedSources: 8,
        listedAlerts: 465,
        // DE, FR, NL, BR: four countries among the public sources the tables cover.
        countryCount: 4,
        // Previous period: 198.51.100.5 (DE) and 203.0.113.5 (FR); 10.1.1.1 is internal.
        previousCountryCount: 2,
        internal: { alerts: 24, sources: 2 },
      });
      expect(w.countries).toEqual([
        { country: "DE", alerts: 280, sources: 2 },
        { country: "FR", alerts: 120, sources: 1 },
        { country: "BR", alerts: 30, sources: 1 },
        { country: "NL", alerts: 10, sources: 1 },
      ]);
      // 192.0.2.200 is public and covered by no range.
      expect(w.unlocated).toEqual({ alerts: 1, sources: 1 });
      expect(w.asns[0]).toMatchObject({ asn: 64500, org: "Example Hosting GmbH", alerts: 280, sources: 2 });
      expect(w.agents).toEqual([
        { agentId: "001", name: "web-01", count: 300, hostId: null },
        { agentId: "002", name: "db-01", count: 100, hostId: null },
      ]);
      expect(r.json?.geoip.missing).toBe(false);
      expect(r.json?.osint).toEqual({ enabled: false });
    });

    it("links a targeted agent to its confirmed server", async () => {
      const id = await seedPage();
      await t.db
        .insert(schema.host)
        .values({ id: "host_atk1", organizationId: ORG, name: "web-01", address: "192.0.2.11" });
      await t.db.insert(schema.wazuhAgent).values({
        id: "wza_atk1",
        organizationId: ORG,
        connectionId: id,
        agentId: "001",
        name: "web-01",
        status: "active",
        hostId: "host_atk1",
        firstSeenAt: new Date(),
        lastSeenAt: new Date(),
      });
      const w = (await call("GET", "/api/v1/attacks/overview")).json?.window as Json;
      expect(w.agents[0]).toMatchObject({ agentId: "001", hostId: "host_atk1" });
      expect(w.agents[1]).toMatchObject({ agentId: "002", hostId: null });
    });

    it("says so when no GeoIP data is loaded and still lists the addresses, unlocated", async () => {
      const id = await seedConnection();
      await seedWindow(id, "24h");
      await seedSources(id, "24h", [
        { ip: "198.51.100.77", count: 5 },
        { ip: "10.0.0.5", count: 2 },
      ]);
      const r = await call("GET", "/api/v1/attacks/overview");
      expect(r.json?.geoip).toMatchObject({ missing: true, asnMissing: true });
      expect(r.json?.window.countries).toEqual([]);
      expect(r.json?.window.unlocated).toEqual({ alerts: 5, sources: 1 });
      const list = await call("GET", "/api/v1/attacks/sources");
      expect(list.json?.items.map((x: Json) => [x.ip, x.scope, x.country])).toEqual([
        ["198.51.100.77", "public", null],
        ["10.0.0.5", "internal", null],
      ]);
    });

    it("keeps organisations apart", async () => {
      await seedPage();
      const other = await seedConnection(OTHER);
      await seedWindow(other, "24h", { attackAlerts: 9999 }, OTHER);
      await seedSources(other, "24h", [{ ip: "198.51.100.200", count: 777 }], OTHER);
      const mine = await call("GET", "/api/v1/attacks/sources?pageSize=100");
      expect(mine.json?.items.map((x: Json) => x.ip)).not.toContain("198.51.100.200");
      const theirs = await call("GET", "/api/v1/attacks/sources", { org: OTHER });
      expect(theirs.json?.items.map((x: Json) => x.ip)).toEqual(["198.51.100.200"]);
      expect((await call("GET", "/api/v1/attacks/overview", { org: OTHER })).json?.window.attackAlerts).toBe(
        9999,
      );
    });
  });

  describe("the address table", () => {
    it("links the machines an address attacked to their confirmed servers", async () => {
      const id = await seedPage();
      await t.db
        .insert(schema.host)
        .values({ id: "host_atk2", organizationId: ORG, name: "db-01", address: "192.0.2.31" });
      await t.db.insert(schema.wazuhAgent).values({
        id: "wza_atk2",
        organizationId: ORG,
        connectionId: id,
        agentId: "002",
        name: "db-01",
        status: "active",
        hostId: "host_atk2",
        firstSeenAt: new Date(),
        lastSeenAt: new Date(),
      });
      const rows = itemsOf(await call("GET", "/api/v1/attacks/sources?agent=002"));
      expect(rows).toHaveLength(1);
      expect(rows[0]?.agents).toEqual([
        { agentId: "001", name: "web-01", count: 50, hostId: null },
        { agentId: "002", name: "db-01", count: 30, hostId: "host_atk2" },
      ]);
    });

    it("labels internal addresses and never looks them up", async () => {
      await seedPage();
      const r = await call("GET", "/api/v1/attacks/sources?pageSize=100");
      const byIp = new Map(itemsOf(r).map((x) => [x.ip, x]));
      expect(byIp.get("10.9.8.7")).toMatchObject({ scope: "internal", country: null, asn: null });
      expect(byIp.get("100.64.1.1")).toMatchObject({ scope: "internal", country: null });
      expect(byIp.get("198.51.100.77")).toMatchObject({
        scope: "public",
        country: "DE",
        asn: 64500,
        org: "Example Hosting GmbH",
        count: 200,
        firstSeen: "2026-10-21T08:00:00.000Z",
        lastSeen: "2026-10-22T07:00:00.000Z",
        osint: null,
      });
      expect(byIp.get("2001:db8::bad")).toMatchObject({ country: "BR", asn: 64502 });
      expect(byIp.get("192.0.2.200")).toMatchObject({ scope: "public", country: null });
    });

    it("sorts by every column and pages with cursors", async () => {
      const id = await seedPage();
      const extra = Array.from({ length: 30 }, (_, i) => ({ ip: `198.51.100.${100 + i}`, count: 1000 - i }));
      await seedSources(id, "24h", extra);
      const first = await call("GET", "/api/v1/attacks/sources?pageSize=25");
      expect(first.json).toMatchObject({ total: 38, pageSize: 25 });
      expect(first.json?.items[0]).toMatchObject({ ip: "198.51.100.100", count: 1000 });
      expect(first.json?.prev).toBeNull();
      const second = await call("GET", `/api/v1/attacks/sources?pageSize=25&cursor=${first.json?.next}`);
      expect(second.json?.items).toHaveLength(13);
      expect(second.json?.next).toBeNull();
      const back = await call("GET", `/api/v1/attacks/sources?pageSize=25&cursor=${second.json?.prev}`);
      expect(back.json?.items.map((x: Json) => x.ip)).toEqual(first.json?.items.map((x: Json) => x.ip));
      const seen = new Set([...itemsOf(first), ...itemsOf(second)].map((x) => x.ip));
      expect(seen.size).toBe(38);

      for (const sort of ["count", "ip", "country", "asn", "firstSeen", "lastSeen", "score"]) {
        for (const dir of ["asc", "desc"]) {
          const r = await call("GET", `/api/v1/attacks/sources?pageSize=100&sort=${sort}&dir=${dir}`);
          expect(r.status, `${sort} ${dir}`).toBe(200);
          expect(r.json?.items).toHaveLength(38);
        }
      }
      const byIp = await call("GET", "/api/v1/attacks/sources?pageSize=100&sort=ip&dir=asc");
      expect(byIp.json?.items[0].ip).toBe("10.9.8.7");
      expect(byIp.json?.items.at(-1).ip).toBe("2001:db8::bad");
      expect((await call("GET", "/api/v1/attacks/sources?cursor=garbage")).status).toBe(400);
      expect((await call("GET", "/api/v1/attacks/sources?sort=nope")).status).toBe(422);
    });

    it("filters by country (code, internal, unknown), AS, agent and rule group, and searches", async () => {
      await seedPage();
      const ips = async (query: string) =>
        itemsOf(await call("GET", `/api/v1/attacks/sources?pageSize=100&${query}`))
          .map((x) => x.ip)
          .sort();
      expect(await ips("country=DE")).toEqual(["198.51.100.77", "198.51.100.78"]);
      expect(await ips("country=internal")).toEqual(["10.9.8.7", "100.64.1.1"]);
      expect(await ips("country=unknown")).toEqual(["192.0.2.200"]);
      expect(await ips("asn=64501")).toEqual(["203.0.113.9"]);
      expect(await ips("agent=002")).toEqual(["198.51.100.78"]);
      expect(await ips("group=web_scan")).toEqual(["203.0.113.9"]);
      expect(await ips("q=198.51.100.7")).toEqual(["198.51.100.77", "198.51.100.78"]);
      expect(await ips("q=germany")).toEqual(["198.51.100.77", "198.51.100.78"]);
      expect(await ips("q=deutschland")).toEqual(["198.51.100.77", "198.51.100.78"]);
      expect(await ips("q=AS64501")).toEqual(["203.0.113.9"]);
      expect(await ips("q=exemple")).toEqual(["203.0.113.9"]);
      expect(await ips("q=db-01")).toEqual(["198.51.100.78"]);
      expect(await ips("q=internal")).toEqual(["10.9.8.7", "100.64.1.1"]);
      expect(await ips("country=DE&agent=002")).toEqual(["198.51.100.78"]);
      expect(await ips("q=zzzz-nothing")).toEqual([]);
      expect((await call("GET", "/api/v1/attacks/sources?country=Germany")).status).toBe(422);
      expect((await call("GET", "/api/v1/attacks/sources?group=%3Cscript%3E")).status).toBe(422);
    });

    it("shows OSINT scores only while OSINT is on, and links only to the provider's page", async () => {
      const id = await seedPage();
      await t.db
        .insert(schema.attackSettings)
        .values({ organizationId: ORG, osintEnabled: true, osintProvider: "abuseipdb" });
      await t.db.insert(schema.attackOsintResult).values([
        {
          id: "osr_1",
          organizationId: ORG,
          provider: "abuseipdb",
          ip: "198.51.100.77",
          score: 91,
          reports: 120,
          lastReportedAt: new Date("2026-10-22T06:00:00Z"),
          checkedAt: new Date(),
        },
      ]);
      const on = await call("GET", "/api/v1/attacks/sources?pageSize=100&sort=score&dir=desc");
      expect(on.json?.items[0]).toMatchObject({
        ip: "198.51.100.77",
        osint: { score: 91, reports: 120, pageUrl: "https://www.abuseipdb.com/check/198.51.100.77" },
      });
      expect((await call("GET", "/api/v1/attacks/overview")).json?.osint).toEqual({
        enabled: true,
        provider: "abuseipdb",
        providerName: "AbuseIPDB",
      });
      await t.db.update(schema.attackSettings).set({ osintEnabled: false });
      const off = await call("GET", "/api/v1/attacks/sources?pageSize=100");
      expect(itemsOf(off).every((x) => x.osint === null)).toBe(true);
      expect(id).toBeTruthy();
    });
  });

  describe("settings", () => {
    it("starts with safe defaults: nothing leaves the network", async () => {
      const r = await call("GET", "/api/v1/attacks/settings");
      expect(r.json).toMatchObject({
        retentionDays: 90,
        wazuhConnected: false,
        geoip: { download: { enabled: false }, host: "download.db-ip.com" },
        osint: { enabled: false, keySet: false, topN: 20, dailyBudget: 300 },
      });
      expect(r.json?.geoip.urls.country).toBe(
        "https://download.db-ip.com/free/dbip-country-lite-YYYY-MM.csv.gz",
      );
      expect(r.json?.geoip.urls.asn).toBe("https://download.db-ip.com/free/dbip-asn-lite-YYYY-MM.csv.gz");
      expect(r.json?.geoip.attribution.text).toContain("DB-IP");
    });

    it("changes the retention: shorter freely, longer only with a recent sign-in, audited", async () => {
      expect(
        (await call("PATCH", "/api/v1/attacks/settings", { age: STALE, body: { retentionDays: 30 } })).status,
      ).toBe(204);
      const longer = await call("PATCH", "/api/v1/attacks/settings", {
        age: STALE,
        body: { retentionDays: 60 },
      });
      expect(problemCode(longer)).toBe("step-up-required");
      expect((await call("PATCH", "/api/v1/attacks/settings", { body: { retentionDays: 60 } })).status).toBe(
        204,
      );
      expect((await call("GET", "/api/v1/attacks/settings")).json?.retentionDays).toBe(60);
      for (const bad of [0, 366, 1.5, "30"]) {
        expect(
          (await call("PATCH", "/api/v1/attacks/settings", { body: { retentionDays: bad } })).status,
          String(bad),
        ).toBe(422);
      }
      expect((await call("PATCH", "/api/v1/attacks/settings", { body: { unknownField: 1 } })).status).toBe(
        422,
      );
      expect((await audits("attacks.settings_changed")).length).toBe(2);
    });

    it("switches the monthly download on only with a recent sign-in, and off at any time", async () => {
      const stale = await call("PATCH", "/api/v1/attacks/settings", {
        age: STALE,
        body: { geoipDownloadEnabled: true },
      });
      expect(problemCode(stale)).toBe("step-up-required");
      expect((await call("GET", "/api/v1/attacks/settings")).json?.geoip.download.enabled).toBe(false);
      expect(
        (await call("PATCH", "/api/v1/attacks/settings", { body: { geoipDownloadEnabled: true } })).status,
      ).toBe(204);
      const on = (await call("GET", "/api/v1/attacks/settings")).json?.geoip.download;
      expect(on.enabled).toBe(true);
      expect(on.enabledAt).not.toBeNull();
      expect(
        (
          await call("PATCH", "/api/v1/attacks/settings", {
            age: STALE,
            body: { geoipDownloadEnabled: false },
          })
        ).status,
      ).toBe(204);
      expect((await audits("attacks.geoip_download_enabled")).length).toBe(1);
      expect((await audits("attacks.geoip_download_disabled")).length).toBe(1);
    });

    describe("OSINT", () => {
      const ACK = ["addressesLeaveNetwork", "termsChecked"];
      const enable = (over: Json = {}) => ({
        osint: { enabled: true, provider: "abuseipdb", apiKey: API_KEY, acknowledge: ACK, ...over },
      });

      it("cannot be switched on without a key, without both confirmations or without a recent sign-in", async () => {
        const noKey = await call("PATCH", "/api/v1/attacks/settings", {
          body: { osint: { enabled: true, acknowledge: ACK } },
        });
        expect(noKey.status).toBe(422);
        const oneAck = await call("PATCH", "/api/v1/attacks/settings", {
          body: enable({ acknowledge: ["addressesLeaveNetwork"] }),
        });
        expect(oneAck.status).toBe(422);
        expect(JSON.stringify(oneAck.json)).toContain("ack_termsChecked");
        const noAck = await call("PATCH", "/api/v1/attacks/settings", {
          body: enable({ acknowledge: undefined }),
        });
        expect(noAck.status).toBe(422);
        const stale = await call("PATCH", "/api/v1/attacks/settings", { age: STALE, body: enable() });
        expect(problemCode(stale)).toBe("step-up-required");
        const settings = (await call("GET", "/api/v1/attacks/settings")).json?.osint;
        expect(settings).toMatchObject({ enabled: false, keySet: false });
        expect(await t.db.select().from(schema.secret)).toHaveLength(0);
      });

      it("refuses keys that cannot be right before storing anything", async () => {
        for (const apiKey of [
          "",
          "short",
          "x".repeat(200),
          "has spaces and symbols !!! 12345678901234567890",
        ]) {
          const r = await call("PATCH", "/api/v1/attacks/settings", { body: enable({ apiKey }) });
          expect(r.status, apiKey).toBe(422);
        }
        expect(await t.db.select().from(schema.secret)).toHaveLength(0);
      });

      it("seals the key in the vault and never returns, logs or audits it", async () => {
        const r = await call("PATCH", "/api/v1/attacks/settings", { body: enable() });
        expect(r.status).toBe(204);
        const state = (await call("GET", "/api/v1/attacks/settings")).json?.osint;
        expect(state).toMatchObject({ enabled: true, provider: "abuseipdb", keySet: true });
        expect(state.acknowledgedAt).not.toBeNull();
        expect(JSON.stringify(state)).not.toContain(API_KEY);

        const secrets = await t.db.select().from(schema.secret);
        expect(secrets).toHaveLength(1);
        expect(secrets[0]?.purpose).toBe("osint-api-key");
        expect(JSON.stringify(secrets[0]?.sealed)).not.toContain(API_KEY);
        const row = (await t.db.select().from(schema.attackSettings))[0];
        expect(row?.osintSecretId).toBe(secrets[0]?.id);
        // Only the vault's private key opens it (the worker's job), and only with the right binding.
        const plain = open(
          secrets[0]?.sealed,
          { organizationId: ORG, recordId: secrets[0]?.id as string, purpose: "osint-api-key" },
          loadVaultPrivateKey((queue.vault as { privateKeyPem: string }).privateKeyPem),
        );
        expect(plain.toString("utf8")).toBe(API_KEY);

        const everything = JSON.stringify([
          await t.db.select().from(schema.auditLog),
          await t.db.select().from(schema.attackSettings),
          r.text,
        ]);
        expect(everything).not.toContain(API_KEY);
        expect((await audits("attacks.osint_enabled"))[0]?.data).toMatchObject({
          provider: "abuseipdb",
          acknowledged: ["addressesLeaveNetwork", "termsChecked"],
        });
        expect((await audits("attacks.osint_key_changed")).length).toBe(1);
      });

      it("switches off without a recent sign-in, forgets what the provider said, and keeps the key for later", async () => {
        await call("PATCH", "/api/v1/attacks/settings", { body: enable() });
        await t.db.insert(schema.attackOsintResult).values({
          id: "osr_x",
          organizationId: ORG,
          provider: "abuseipdb",
          ip: "198.51.100.1",
          score: 50,
          reports: 3,
          checkedAt: new Date(),
        });
        const off = await call("PATCH", "/api/v1/attacks/settings", {
          age: STALE,
          body: { osint: { enabled: false } },
        });
        expect(off.status).toBe(204);
        expect(await t.db.select().from(schema.attackOsintResult)).toHaveLength(0);
        expect((await call("GET", "/api/v1/attacks/settings")).json?.osint).toMatchObject({
          enabled: false,
          keySet: true,
        });
        // Switching on again asks for both confirmations again.
        const again = await call("PATCH", "/api/v1/attacks/settings", { body: { osint: { enabled: true } } });
        expect(again.status).toBe(422);
        const ok = await call("PATCH", "/api/v1/attacks/settings", {
          body: { osint: { enabled: true, acknowledge: ACK } },
        });
        expect(ok.status).toBe(204);
        expect((await audits("attacks.osint_disabled")).length).toBe(1);
      });

      it("replaces the key (old one deleted) and removes it (OSINT off, nothing left)", async () => {
        await call("PATCH", "/api/v1/attacks/settings", { body: enable() });
        const first = (await t.db.select().from(schema.secret))[0];
        const next = "fedcba9876543210fedcba9876543210fedcba98";
        expect(
          (await call("PATCH", "/api/v1/attacks/settings", { age: STALE, body: { osint: { apiKey: next } } }))
            .status,
        ).toBe(403);
        expect(
          (await call("PATCH", "/api/v1/attacks/settings", { body: { osint: { apiKey: next } } })).status,
        ).toBe(204);
        const after = await t.db.select().from(schema.secret);
        expect(after).toHaveLength(1);
        expect(after[0]?.id).not.toBe(first?.id);
        expect(JSON.stringify(await t.db.select().from(schema.auditLog))).not.toContain(next);

        expect(
          (await call("PATCH", "/api/v1/attacks/settings", { body: { osint: { apiKey: null } } })).status,
        ).toBe(204);
        expect(await t.db.select().from(schema.secret)).toHaveLength(0);
        expect((await call("GET", "/api/v1/attacks/settings")).json?.osint).toMatchObject({
          enabled: false,
          keySet: false,
        });
        expect((await audits("attacks.osint_key_removed")).length).toBe(1);
      });

      it("bounds how many addresses and requests", async () => {
        for (const osint of [
          { topN: 0 },
          { topN: 51 },
          { dailyBudget: 9 },
          { dailyBudget: 901 },
          { provider: "someone" },
        ]) {
          expect(
            (await call("PATCH", "/api/v1/attacks/settings", { body: { osint } })).status,
            JSON.stringify(osint),
          ).toBe(422);
        }
        expect(
          (
            await call("PATCH", "/api/v1/attacks/settings", {
              body: { osint: { topN: 10, dailyBudget: 100 } },
            })
          ).status,
        ).toBe(204);
        expect((await call("GET", "/api/v1/attacks/settings")).json?.osint).toMatchObject({
          topN: 10,
          dailyBudget: 100,
        });
      });
    });
  });

  describe("GeoIP upload", () => {
    const country = csv(["198.51.100.0,198.51.100.255,DE", "203.0.113.0,203.0.113.255,FR"]);
    const asn = csv(["198.51.100.0,198.51.100.255,64500,Example Hosting GmbH"]);

    it("imports a country file and an ASN file, records the month and audits it", async () => {
      const a = await upload("country", country, { filename: "dbip-country-lite-2026-10.csv.gz" });
      expect(a.status).toBe(201);
      expect(a.json).toEqual({ rows: 2, month: "2026-10" });
      const b = await upload("asn", asn);
      expect(b.status).toBe(201);
      const status = (await call("GET", "/api/v1/attacks/settings")).json?.geoip.datasets as Json[];
      expect(status.find((d) => d.kind === "country")?.active).toMatchObject({
        rows: 2,
        month: "2026-10",
        source: "import",
      });
      expect(status.find((d) => d.kind === "asn")?.active).toMatchObject({ rows: 1, month: null });
      const imported = await audits("attacks.geoip_imported");
      expect(imported).toHaveLength(2);
      expect(imported[0]?.data).toMatchObject({
        kind: "country",
        rows: 2,
        month: "2026-10",
        source: "import",
      });
      expect(((imported[0]?.data ?? {}) as Json).sha256).toMatch(/^[0-9a-f]{64}$/);
    });

    it("needs the length up front and refuses a file over the limit before reading it", async () => {
      const none = await upload("country", country, { length: null });
      expect(none.status).toBe(411);
      const big = await upload("country", country, { length: 70 * 1024 * 1024 });
      expect(big.status).toBe(413);
      expect(big.json?.reason).toBe("tooLarge");
      expect(await t.db.select().from(schema.geoipDataset)).toHaveLength(0);
    });

    it("refuses the wrong kind, a wrong file name, a text file, damaged gzip and a huge line, and keeps the last good dataset", async () => {
      expect((await upload("country", country)).status).toBe(201);

      const wrongKind = await upload("country", asn);
      expect(wrongKind.status).toBe(422);
      expect(wrongKind.json?.reason).toBe("wrongKind");

      const named = await upload("country", country, { filename: "dbip-asn-lite-2026-10.csv.gz" });
      expect(named.status).toBe(422);
      expect(named.json?.reason).toBe("wrongKind");

      const text = await upload("country", Buffer.from("198.51.100.0,198.51.100.255,DE\n"));
      expect(text.json?.reason).toBe("notGzip");

      const damaged = Buffer.from(country);
      damaged[damaged.length - 5] = (damaged[damaged.length - 5] as number) ^ 0xff;
      expect((await upload("country", damaged)).json?.reason).toBe("corrupt");

      const huge = await upload(
        "country",
        gzipSync(Buffer.from(`198.51.100.0,198.51.100.255,DE\n${"A".repeat(100_000)}\n`)),
      );
      expect(huge.status).toBe(422);
      expect(huge.json?.reason).toBe("lineTooLong");

      const empty = await upload("country", gzipSync(Buffer.from("")));
      expect(empty.json?.reason).toBe("empty");

      const status = (await call("GET", "/api/v1/attacks/settings")).json?.geoip.datasets as Json[];
      const c = status.find((d) => d.kind === "country");
      expect(c?.active).toMatchObject({ rows: 2 });
      expect(c?.lastFailure).toMatchObject({ source: "import", error: "empty" });
      expect((await audits("attacks.geoip_import_failed")).length).toBe(5);
      // None of the hostile bytes ended up in the audit log.
      expect(JSON.stringify(await t.db.select().from(schema.auditLog))).not.toContain("AAAAAAAA");
    });

    it("replaces the dataset by a newer file", async () => {
      await upload("country", country, { filename: "dbip-country-lite-2026-09.csv.gz" });
      const newer = csv(["198.51.100.0,198.51.100.255,NL"]);
      expect((await upload("country", newer, { filename: "dbip-country-lite-2026-10.csv.gz" })).status).toBe(
        201,
      );
      const status = (await call("GET", "/api/v1/attacks/settings")).json?.geoip.datasets as Json[];
      expect(status.find((d) => d.kind === "country")?.active).toMatchObject({ rows: 1, month: "2026-10" });
      expect(
        (await t.db.select().from(schema.geoipDataset)).filter((d) => d.state === "active"),
      ).toHaveLength(1);
    });

    it("removes a dataset on request, audited", async () => {
      await upload("country", country);
      expect((await call("DELETE", "/api/v1/attacks/geoip/country")).status).toBe(204);
      expect((await call("DELETE", "/api/v1/attacks/geoip/country")).status).toBe(404);
      expect((await call("GET", "/api/v1/attacks/settings")).json?.geoip.datasets[0].active).toBeNull();
      expect((await audits("attacks.geoip_removed")).length).toBe(1);
      expect((await call("DELETE", "/api/v1/attacks/geoip/city")).status).toBe(422);
    });
  });

  describe("erasure", () => {
    it("deletes the stored addresses, the attack numbers and the OSINT results of the organisation only", async () => {
      await seedPage();
      const other = await seedConnection(OTHER);
      await seedWindow(other, "24h", {}, OTHER);
      await seedSources(other, "24h", [{ ip: "198.51.100.9", count: 1 }], OTHER);
      const r = await call("DELETE", "/api/v1/attacks/data");
      expect(r.json).toEqual({ sourceAddresses: 8, attackWindows: 1, osintResults: 0 });
      expect(
        await t.db.select().from(schema.wazuhSourceIp).where(eq(schema.wazuhSourceIp.organizationId, ORG)),
      ).toHaveLength(0);
      expect(
        await t.db.select().from(schema.wazuhSourceIp).where(eq(schema.wazuhSourceIp.organizationId, OTHER)),
      ).toHaveLength(1);
      expect((await audits("attacks.data_purged"))[0]?.data).toMatchObject({ sourceAddresses: 8 });
    });
  });

  describe("AI summary", () => {
    it("is refused while AI is off, asks for data, and queues one request at a time", async () => {
      const id = await seedPage();
      const notReady = await call("POST", "/api/v1/attacks/summary", { role: "member", body: {} });
      expect(notReady.status).toBe(409);
      expect(problemCode(notReady)).toBe("ai-not-ready");
      await t.db.insert(schema.aiSettings).values({
        organizationId: ORG,
        enabled: true,
        baseUrl: "https://llm.example.lan/v1",
        model: "example-model",
      } as never);
      expect((await call("POST", "/api/v1/attacks/summary", { role: "viewer", body: {} })).status).toBe(403);
      const ok = await call("POST", "/api/v1/attacks/summary", { role: "member", body: { language: "de" } });
      expect(ok.status).toBe(202);
      expect(queue.sent[0]).toMatchObject({ name: "attacks.summary", data: { summaryId: ok.json?.id } });
      const busy = await call("POST", "/api/v1/attacks/summary", { role: "member", body: {} });
      expect(busy.status).toBe(429);
      expect((await audits("ai.request"))[0]?.data).toMatchObject({
        kind: "attack-summary",
        model: "example-model",
      });
      // The request carries no address, however it was stored.
      expect(JSON.stringify(await t.db.select().from(schema.auditLog))).not.toMatch(
        /198\.51\.100\.7[78]|203\.0\.113\.9/,
      );
      const latest = await call("GET", "/api/v1/attacks/summary");
      expect(latest.json?.summary).toMatchObject({ status: "pending", language: "de", author: "Erika" });

      await t.db.delete(schema.wazuhAttackWindow).where(eq(schema.wazuhAttackWindow.connectionId, id));
      await t.db.update(schema.attackSummary).set({ status: "failed" });
      expect((await call("POST", "/api/v1/attacks/summary", { role: "member", body: {} })).status).toBe(409);
    });
  });
});
