/**
 * Grades A to F for repositories and servers (ADR 0018) against a throw-away PostgreSQL
 * database on the development server: the rules at query time (accepted risks while valid and
 * after they expire, known exploited, findings without a fix), never scanned and failed last
 * scan, sorting and filtering by grade through all pages, the reason with its example package,
 * and organisation isolation. Sessions are replaced by a header-driven actor; the queue is a
 * recorder. Skipped without the development PostgreSQL.
 */
import { type Grade, gradeCountsOf, gradeOf } from "@garnetops/core/grades";
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { Hono } from "hono";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();

const queue = vi.hoisted(() => ({
  db: null as unknown,
  vault: null as null | { publicKeyPem: string; privateKeyPem: string },
}));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null, boss: null, QUEUES: {} };
  const t = await create(target, "api_grades");
  queue.db = t;
  return {
    db: t.db,
    pool: t.pool,
    boss: { send: async () => "job" },
    QUEUES: {
      scanRepository: "scan.repository",
      fixPrCreate: "fix-pr.create",
      fixPrCheck: "fix-pr.check",
      fixPrRefresh: "fix-pr.refresh",
      hostAccessKey: "host.access-key",
      hostKeyscan: "host.keyscan",
      hostInventory: "host.inventory",
    },
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
const ORG = "org_gr_a";
const OTHER = "org_gr_b";
const DAY = 24 * 3600 * 1000;

interface Spec {
  severity: string;
  fixed?: boolean;
  kev?: boolean;
  pkg?: string;
  cvss?: number;
  state?: "open" | "accepted" | "resolved";
  until?: Date | null;
}

describe.skipIf(!adminUrl)("grades API", () => {
  let t: TestDatabase;
  let app: Hono;
  let counter = 0;

  async function get(path: string, org = ORG) {
    const res = await app.request(path, { headers: { "x-org": org } });
    const text = await res.text();
    return { status: res.status, json: (text ? JSON.parse(text) : null) as Json | null };
  }
  const itemsOf = (r: { json: Json | null }): Json[] => (r.json?.items ?? []) as Json[];
  const nameOf = (r: Json) => String(r.name);

  async function vulnerability(spec: Spec) {
    const id = `CVE-2099-${String(++counter).padStart(5, "0")}`;
    await t.db.insert(schema.vulnerability).values({
      id,
      severity: spec.severity,
      cvssScore: spec.cvss ?? null,
      knownExploited: spec.kev ?? false,
    });
    return id;
  }

  /** A repository, scanned by default. Its findings are inserted as given. */
  async function addRepo(
    name: string,
    findings: Spec[],
    options: { scanned?: boolean; org?: string; scans?: { state: string; ref?: string | null }[] } = {},
  ): Promise<string> {
    const org = options.org ?? ORG;
    const id = `repo_gr${String(++counter).padStart(8, "0")}`;
    const scanned = options.scanned ?? true;
    await t.db.insert(schema.repository).values({
      id,
      organizationId: org,
      name,
      url: `https://git.example.lan/team/${name}.git`,
      authKind: "none",
      lastScanId: scanned ? `scan_gr_ok_${id}` : null,
      lastScanAt: scanned ? new Date(Date.now() - DAY) : null,
    });
    let n = 0;
    for (const scan of options.scans ?? []) {
      await t.db.insert(schema.scan).values({
        id: `scan_gr_${id}_${++n}`,
        organizationId: org,
        repositoryId: id,
        state: scan.state as never,
        trigger: "manual",
        ref: scan.ref ?? null,
        createdAt: new Date(Date.now() - (10 - n) * 1000),
      });
    }
    for (const spec of findings) {
      const vulnerabilityId = await vulnerability(spec);
      const pkg = spec.pkg ?? `pkg-${counter}`;
      await t.db.insert(schema.finding).values({
        id: `fnd_gr${String(counter).padStart(8, "0")}`,
        organizationId: org,
        repositoryId: id,
        vulnerabilityId,
        dedupKey: `${id}|${vulnerabilityId}|npm|${pkg}`,
        packageName: pkg,
        packageVersion: "1.0.0",
        packageType: "npm",
        fixedIn: spec.fixed ? ["1.0.1"] : [],
        severity: spec.severity,
        severityRank: 1,
        state: spec.state ?? "open",
        acceptedReason: spec.state === "accepted" ? "Accepted for the test" : null,
        acceptedUntil: spec.state === "accepted" ? (spec.until ?? null) : null,
        firstSeenScanId: "scan_x",
        lastSeenScanId: "scan_x",
        firstSeenAt: new Date(),
        lastSeenAt: new Date(),
      });
    }
    return id;
  }

  async function addHost(
    name: string,
    findings: Spec[],
    options: { inventoried?: boolean; org?: string; lastError?: string | null; runs?: string[] } = {},
  ): Promise<string> {
    const org = options.org ?? ORG;
    const id = `host_gr${String(++counter).padStart(8, "0")}`;
    const inventoried = options.inventoried ?? true;
    await t.db.insert(schema.host).values({
      id,
      organizationId: org,
      name,
      address: `${name}.example.lan`,
      lastInventoryAt: inventoried ? new Date(Date.now() - DAY) : null,
      lastError: options.lastError ?? null,
    });
    let n = 0;
    for (const state of options.runs ?? []) {
      await t.db.insert(schema.hostInventoryRun).values({
        id: `hrun_gr_${id}_${++n}`,
        organizationId: org,
        hostId: id,
        state: state as never,
        trigger: "manual",
        createdAt: new Date(Date.now() - (10 - n) * 1000),
      });
    }
    for (const spec of findings) {
      const vulnerabilityId = await vulnerability(spec);
      const pkg = spec.pkg ?? `pkg-${counter}`;
      await t.db.insert(schema.hostFinding).values({
        id: `hfnd_gr${String(counter).padStart(8, "0")}`,
        organizationId: org,
        hostId: id,
        vulnerabilityId,
        dedupKey: `${id}|${vulnerabilityId}|deb|${pkg}`,
        packageName: pkg,
        packageVersion: "1.0.0",
        packageType: "deb",
        fixedIn: spec.fixed ? ["1.0.1"] : [],
        severity: spec.severity,
        severityRank: 1,
        state: spec.state === "resolved" ? "resolved" : "open",
        firstSeenRunId: "run_x",
        lastSeenRunId: "run_x",
        firstSeenAt: new Date(),
        lastSeenAt: new Date(),
      });
    }
    return id;
  }

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { repositoryRoutes } = await import("./repositories.ts");
    const { hostRoutes } = await import("./hosts.ts");
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
          role: "admin",
          ip: "198.51.100.7",
          strongAuthAt: new Date(),
        } as never,
      );
      await next();
    });
    v1.route("/repositories", repositoryRoutes as never);
    v1.route("/hosts", hostRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  });

  /** The list entry of one repository, found by name. */
  async function listed(name: string, org = ORG): Promise<Json> {
    const res = await get(`/api/v1/repositories?pageSize=100&q=${encodeURIComponent(name)}`, org);
    const row = itemsOf(res).find((r) => r.name === name);
    if (!row) throw new Error(`${name} is not in the list`);
    return row;
  }

  describe("repositories", () => {
    it("grades by the worst rule, with the deciding rule and its count in the reason", async () => {
      const cases: [string, Spec[], Grade, string, number][] = [
        ["g-clean", [], "A", "none", 0],
        ["g-low", [{ severity: "low", fixed: true }], "B", "other-open", 1],
        ["g-medium-nofix", [{ severity: "medium" }, { severity: "unknown" }], "B", "other-open", 2],
        ["g-medium-fix", [{ severity: "medium", fixed: true }], "C", "medium-with-fix", 1],
        ["g-high-nofix", [{ severity: "high" }], "C", "high-without-fix", 1],
        [
          "g-high-fix",
          [
            { severity: "high", fixed: true },
            { severity: "high", fixed: true },
          ],
          "D",
          "high-with-fix",
          2,
        ],
        ["g-critical-nofix", [{ severity: "critical" }], "D", "critical-without-fix", 1],
        ["g-critical-fix", [{ severity: "critical", fixed: true }], "E", "critical-with-fix", 1],
        ["g-kev-fix", [{ severity: "low", fixed: true, kev: true }], "F", "known-exploited-with-fix", 1],
        ["g-kev-nofix", [{ severity: "high", kev: true }], "C", "high-without-fix", 1],
      ];
      for (const [name, findings] of cases) await addRepo(name, findings);
      for (const [name, , grade, rule, count] of cases) {
        const row = await listed(name);
        expect(row.grade, name).toBe(grade);
        expect(row.gradeReason.rule, name).toBe(rule);
        expect(row.gradeReason.count, name).toBe(count);
        expect(row.gradeStale, name).toBe(false);
      }
    });

    it("names an example package: the one with the highest score among the matching findings", async () => {
      await addRepo("g-example", [
        { severity: "high", fixed: true, pkg: "lodash", cvss: 7.5 },
        { severity: "high", fixed: true, pkg: "axios", cvss: 8.8 },
        { severity: "critical", pkg: "left-pad", cvss: 9.9 },
      ]);
      const row = await listed("g-example");
      // D by "high with a fix", which comes before "critical without a fix" as the reason.
      expect(row.grade).toBe("D");
      expect(row.gradeReason).toEqual({ rule: "high-with-fix", count: 2, example: "axios" });
    });

    it("counts only open findings: resolved ones are gone, accepted ones while the acceptance is valid", async () => {
      await addRepo("g-resolved", [{ severity: "critical", fixed: true, state: "resolved" }]);
      await addRepo("g-accepted", [
        { severity: "critical", fixed: true, state: "accepted", until: new Date(Date.now() + 30 * DAY) },
      ]);
      // An acceptance without an end date does not expire (as in the gate evaluation).
      await addRepo("g-accepted-forever", [
        { severity: "critical", fixed: true, state: "accepted", until: null },
      ]);
      expect((await listed("g-resolved")).grade).toBe("A");
      expect((await listed("g-accepted")).grade).toBe("A");
      expect((await listed("g-accepted-forever")).grade).toBe("A");
    });

    it("counts an accepted risk again once its acceptance has expired, before any scan reopened it", async () => {
      await addRepo("g-expired", [
        {
          severity: "critical",
          fixed: true,
          pkg: "expired-pkg",
          state: "accepted",
          until: new Date(Date.now() - 1000),
        },
        { severity: "low", fixed: true, state: "accepted", until: new Date(Date.now() + DAY) },
      ]);
      const row = await listed("g-expired");
      expect(row.grade).toBe("E");
      expect(row.gradeReason).toEqual({ rule: "critical-with-fix", count: 1, example: "expired-pkg" });
    });

    it("has no grade before the first successful scan, not A", async () => {
      const id = await addRepo("g-never", [], { scanned: false });
      await addRepo("g-never-queued", [], { scanned: false, scans: [{ state: "queued" }] });
      await addRepo("g-never-failed", [], { scanned: false, scans: [{ state: "failed" }] });
      for (const name of ["g-never", "g-never-queued", "g-never-failed"]) {
        const row = await listed(name);
        expect(row.grade, name).toBeNull();
        expect(row.gradeReason, name).toBeNull();
        expect(row.gradeStale, name).toBe(false);
      }
      const detail = await get(`/api/v1/repositories/${id}`);
      expect(detail.json?.grade).toBeNull();
      expect(detail.json?.gradeReason).toBeNull();
    });

    it("keeps the grade of the last successful scan when the latest scan failed, marked stale", async () => {
      const id = await addRepo("g-failed", [{ severity: "high", fixed: true, pkg: "left-over" }], {
        scans: [{ state: "succeeded" }, { state: "failed" }],
      });
      const row = await listed("g-failed");
      expect(row.grade).toBe("D");
      expect(row.gradeStale).toBe(true);
      expect(row.gradeReason.example).toBe("left-over");
      const detail = await get(`/api/v1/repositories/${id}`);
      expect(detail.json?.grade).toBe("D");
      expect(detail.json?.gradeStale).toBe(true);
    });

    it("is not stale while a new scan runs or after the failed one was followed by a success", async () => {
      await addRepo("g-running", [{ severity: "low" }], {
        scans: [{ state: "failed" }, { state: "running" }],
      });
      await addRepo("g-recovered", [{ severity: "low" }], {
        scans: [{ state: "failed" }, { state: "succeeded" }],
      });
      expect((await listed("g-running")).gradeStale).toBe(false);
      expect((await listed("g-recovered")).gradeStale).toBe(false);
    });

    it("ignores a failed check of another ref (a pull request) for staleness", async () => {
      await addRepo("g-pr-check", [{ severity: "low" }], {
        scans: [{ state: "succeeded" }, { state: "failed", ref: "refs/pull/7/head" }],
      });
      expect((await listed("g-pr-check")).gradeStale).toBe(false);
    });

    it("the detail endpoint returns the same grade fields as the list", async () => {
      const id = await addRepo("g-detail", [{ severity: "medium", fixed: true, pkg: "mid-pkg" }]);
      const detail = await get(`/api/v1/repositories/${id}`);
      expect(detail.status).toBe(200);
      expect(detail.json?.grade).toBe("C");
      expect(detail.json?.gradeReason).toEqual({ rule: "medium-with-fix", count: 1, example: "mid-pkg" });
      expect(detail.json?.gradeStale).toBe(false);
      // The fields that existed before are unchanged.
      expect(detail.json?.open).toEqual({ medium: 1 });
    });

    it("SQL and the pure function agree on every kind of finding, as a grade, a sort key and a filter", async () => {
      const kinds: { severity: string; fixed: boolean; kev: boolean }[] = [];
      for (const severity of ["critical", "high", "medium", "low", "negligible", "unknown"])
        for (const fixed of [true, false])
          for (const kev of [true, false]) kinds.push({ severity, fixed, kev });
      const names = new Map<string, Grade>();
      for (const k of kinds) {
        const name = `kind-${k.severity}-${k.fixed ? "fix" : "nofix"}-${k.kev ? "kev" : "plain"}`;
        await addRepo(name, [k]);
        names.set(
          name,
          gradeOf(gradeCountsOf([{ severity: k.severity, hasFix: k.fixed, knownExploited: k.kev }])).grade,
        );
      }
      const all = itemsOf(await get("/api/v1/repositories?pageSize=100&q=kind-"));
      expect(all).toHaveLength(kinds.length);
      for (const row of all) expect(row.grade, nameOf(row)).toBe(names.get(nameOf(row)));
      for (const grade of ["A", "B", "C", "D", "E", "F"] as const) {
        const filtered = itemsOf(await get(`/api/v1/repositories?pageSize=100&q=kind-&grade=${grade}`));
        const expected = [...names].filter(([, g]) => g === grade).map(([n]) => n);
        expect(filtered.map(nameOf).sort(), grade).toEqual(expected.sort());
      }
    });

    it("sorts by grade, worst first, through all pages exactly once, and reverses", async () => {
      // "-" is in every name: the grade sort over all repositories of the organisation.
      const url = (extra: string) => `/api/v1/repositories?q=-&sort=grade${extra}`;
      const seen: Json[] = [];
      let cursor: string | null = null;
      let pages = 0;
      do {
        const res: { json: Json | null } = await get(
          url(`&pageSize=25${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`),
        );
        seen.push(...itemsOf(res));
        cursor = res.json?.next ?? null;
        pages++;
      } while (cursor && pages < 50);
      const total = (await get("/api/v1/repositories?q=-&pageSize=25")).json?.total;
      expect(total).toBeGreaterThan(25);
      expect(pages).toBeGreaterThan(1);
      expect(seen).toHaveLength(total);
      expect(new Set(seen.map((r) => r.id)).size).toBe(total);
      const rank = (r: Json) => (r.grade === null ? -1 : "ABCDEF".indexOf(r.grade as string));
      for (let i = 1; i < seen.length; i++) {
        const [a, b] = [seen[i - 1], seen[i]];
        if (a && b) expect(rank(a), `${a.name} before ${b.name}`).toBeGreaterThanOrEqual(rank(b));
      }
      expect(seen[0]?.grade).toBe("F");
      expect(seen[seen.length - 1]?.grade).toBeNull();

      // Ascending is the exact reverse, paged the same way.
      const ascending: string[] = [];
      let ascCursor: string | null = null;
      do {
        const res: { json: Json | null } = await get(
          url(`&dir=asc&pageSize=25${ascCursor ? `&cursor=${encodeURIComponent(ascCursor)}` : ""}`),
        );
        ascending.push(...itemsOf(res).map((r) => r.id as string));
        ascCursor = res.json?.next ?? null;
      } while (ascCursor);
      expect(ascending).toEqual([...seen.map((r) => r.id)].reverse());
    });

    it("pages backwards in a grade sort as well", async () => {
      const first = await get("/api/v1/repositories?q=-&sort=grade&pageSize=25");
      const second = await get(
        `/api/v1/repositories?q=-&sort=grade&pageSize=25&cursor=${encodeURIComponent(first.json?.next)}`,
      );
      const back = await get(
        `/api/v1/repositories?q=-&sort=grade&pageSize=25&cursor=${encodeURIComponent(second.json?.prev)}`,
      );
      expect(itemsOf(back).map((r) => r.id)).toEqual(itemsOf(first).map((r) => r.id));
    });

    it("filters by one grade, several grades and 'none', and counts the total of the filter", async () => {
      const f = await get("/api/v1/repositories?grade=F&pageSize=100&q=g-");
      expect(itemsOf(f).map(nameOf)).toEqual(["g-kev-fix"]);
      expect(f.json?.total).toBe(1);
      const fe = await get("/api/v1/repositories?grade=F,E&pageSize=100&q=g-");
      expect(itemsOf(fe).map(nameOf).sort()).toEqual(["g-critical-fix", "g-expired", "g-kev-fix"].sort());
      const none = await get("/api/v1/repositories?grade=none&pageSize=100&q=g-");
      expect(itemsOf(none).map(nameOf).sort()).toEqual(["g-never", "g-never-failed", "g-never-queued"]);
      const a = await get("/api/v1/repositories?grade=A&pageSize=100&q=g-");
      expect(itemsOf(a).map(nameOf).sort()).toEqual(
        ["g-accepted", "g-accepted-forever", "g-clean", "g-resolved"].sort(),
      );
    });

    it("refuses an unknown grade instead of showing everything", async () => {
      for (const bad of ["G", "a", "F,x", "'; drop table repository; --"]) {
        const res = await get(`/api/v1/repositories?grade=${encodeURIComponent(bad)}`);
        expect(res.status, bad).toBe(422);
      }
    });

    it("counts repositories per grade", async () => {
      const res = await get("/api/v1/repositories/grades?q=g-");
      expect(res.status).toBe(200);
      expect(res.json).toMatchObject({ F: 1, none: 3 });
      const total = Object.values(res.json ?? {}).reduce((a, b) => a + (b as number), 0);
      expect(total).toBe((await get("/api/v1/repositories?q=g-&pageSize=25")).json?.total);
    });

    it("keeps organisations apart", async () => {
      const otherId = await addRepo("g-other-org", [{ severity: "critical", fixed: true, kev: true }], {
        org: OTHER,
      });
      // The same names in both organisations grade independently.
      await addRepo("g-same-name", [{ severity: "low" }]);
      await addRepo("g-same-name", [{ severity: "critical", fixed: true }], { org: OTHER });
      expect((await listed("g-same-name")).grade).toBe("B");
      expect((await listed("g-same-name", OTHER)).grade).toBe("E");
      // Not visible, not countable, not readable from the other organisation.
      expect(itemsOf(await get("/api/v1/repositories?pageSize=100&q=g-other-org")).length).toBe(0);
      expect((await get(`/api/v1/repositories/${otherId}`, OTHER)).status).toBe(200);
      expect((await get(`/api/v1/repositories/${otherId}`, ORG)).status).toBe(404);
      const mine = await get("/api/v1/repositories/grades?q=g-other-org");
      expect(Object.values(mine.json ?? {}).every((n) => n === 0)).toBe(true);
      const theirs = await get("/api/v1/repositories/grades?q=g-other-org", OTHER);
      expect(theirs.json?.F).toBe(1);
      expect(itemsOf(await get("/api/v1/repositories?grade=F&pageSize=100&q=g-other", ORG)).length).toBe(0);
    });
  });

  describe("servers", () => {
    const listedHost = async (name: string, org = ORG): Promise<Json> => {
      const res = await get(`/api/v1/hosts?pageSize=100&q=${encodeURIComponent(name)}`, org);
      const row = itemsOf(res).find((r) => r.name === name);
      if (!row) throw new Error(`${name} is not in the list`);
      return row;
    };

    it("grades from the open host findings, with the same rules", async () => {
      const cases: [string, Spec[], Grade, string, number][] = [
        ["h-clean", [], "A", "none", 0],
        ["h-resolved", [{ severity: "critical", fixed: true, state: "resolved" }], "A", "none", 0],
        ["h-low", [{ severity: "low", fixed: true }], "B", "other-open", 1],
        ["h-medium-fix", [{ severity: "medium", fixed: true }], "C", "medium-with-fix", 1],
        ["h-high-nofix", [{ severity: "high" }], "C", "high-without-fix", 1],
        ["h-high-fix", [{ severity: "high", fixed: true }], "D", "high-with-fix", 1],
        ["h-critical-nofix", [{ severity: "critical" }], "D", "critical-without-fix", 1],
        [
          "h-critical-fix",
          [{ severity: "critical", fixed: true, pkg: "openssl" }],
          "E",
          "critical-with-fix",
          1,
        ],
        [
          "h-kev-fix",
          [{ severity: "medium", fixed: true, kev: true, pkg: "sudo" }],
          "F",
          "known-exploited-with-fix",
          1,
        ],
      ];
      for (const [name, findings] of cases) await addHost(name, findings);
      for (const [name, , grade, rule, count] of cases) {
        const row = await listedHost(name);
        expect(row.grade, name).toBe(grade);
        expect(row.gradeReason.rule, name).toBe(rule);
        expect(row.gradeReason.count, name).toBe(count);
        expect(row.gradeStale, name).toBe(false);
      }
      expect((await listedHost("h-critical-fix")).gradeReason.example).toBe("openssl");
      expect((await listedHost("h-kev-fix")).gradeReason.example).toBe("sudo");
    });

    it("has no grade before the first successful inventory", async () => {
      const id = await addHost("h-never", [], { inventoried: false });
      const row = await listedHost("h-never");
      expect(row.grade).toBeNull();
      expect(row.gradeReason).toBeNull();
      const detail = await get(`/api/v1/hosts/${id}`);
      expect(detail.json?.grade).toBeNull();
    });

    it("keeps the grade of the last good inventory when the latest run failed, marked stale", async () => {
      const id = await addHost("h-failed", [{ severity: "critical", fixed: true }], {
        lastError: "unreachable",
        runs: ["succeeded", "failed"],
      });
      const row = await listedHost("h-failed");
      expect(row.grade).toBe("E");
      expect(row.gradeStale).toBe(true);
      expect((await get(`/api/v1/hosts/${id}`)).json?.gradeStale).toBe(true);
      // First inventory failed: still nothing to grade.
      await addHost("h-first-failed", [], { inventoried: false, lastError: "unreachable", runs: ["failed"] });
      expect((await listedHost("h-first-failed")).grade).toBeNull();
    });

    it("sorts and filters by grade, and keeps organisations apart", async () => {
      // More servers than a page holds, so the sort has to continue across pages.
      const bulk: Spec[][] = [
        [],
        [{ severity: "low" }],
        [{ severity: "high" }],
        [{ severity: "high", fixed: true }],
      ];
      for (let i = 0; i < 30; i++) await addHost(`h-bulk-${String(i).padStart(2, "0")}`, bulk[i % 4] ?? []);
      const sorted = itemsOf(await get("/api/v1/hosts?q=h-&sort=grade&pageSize=100"));
      expect(sorted.length).toBeGreaterThan(25);
      const rank = (r: Json) => (r.grade === null ? -1 : "ABCDEF".indexOf(r.grade as string));
      for (let i = 1; i < sorted.length; i++) {
        const [a, b] = [sorted[i - 1], sorted[i]];
        if (a && b) expect(rank(a)).toBeGreaterThanOrEqual(rank(b));
      }
      expect(sorted[0]?.name).toBe("h-kev-fix");
      expect(sorted[sorted.length - 1]?.grade).toBeNull();

      const paged: string[] = [];
      let cursor: string | null = null;
      do {
        const res: { json: Json | null } = await get(
          `/api/v1/hosts?q=h-&sort=grade&pageSize=25${cursor ? `&cursor=${encodeURIComponent(cursor)}` : ""}`,
        );
        paged.push(...itemsOf(res).map((r) => r.id));
        cursor = res.json?.next ?? null;
      } while (cursor);
      expect(paged).toEqual(sorted.map((r) => r.id));

      const ed = itemsOf(await get("/api/v1/hosts?q=h-&grade=F,E&pageSize=100"))
        .map(nameOf)
        .sort();
      expect(ed).toEqual(["h-critical-fix", "h-failed", "h-kev-fix"]);
      expect(
        itemsOf(await get("/api/v1/hosts?q=h-&grade=none&pageSize=100"))
          .map(nameOf)
          .sort(),
      ).toEqual(["h-first-failed", "h-never"]);
      expect((await get("/api/v1/hosts?grade=Z")).status).toBe(422);

      await addHost("h-other-org", [{ severity: "critical", fixed: true, kev: true }], { org: OTHER });
      expect(itemsOf(await get("/api/v1/hosts?q=h-other-org&pageSize=100")).length).toBe(0);
      expect((await listedHost("h-other-org", OTHER)).grade).toBe("F");
      const mine = await get("/api/v1/hosts/grades?q=h-other-org");
      expect(Object.values(mine.json ?? {}).every((n) => n === 0)).toBe(true);
    });

    it("the findings of a server can be limited to those with a fix or to known exploited ones", async () => {
      const id = await addHost("h-links", [
        { severity: "high", fixed: true, pkg: "a" },
        { severity: "high", fixed: false, pkg: "b" },
        { severity: "medium", fixed: true, kev: true, pkg: "c" },
      ]);
      const names = async (query: string) => {
        const res = await get(`/api/v1/hosts/${id}/findings?${query}`);
        return {
          names: itemsOf(res)
            .map((r) => r.packageName as string)
            .sort(),
          total: res.json?.total,
        };
      };
      expect(await names("")).toEqual({ names: ["a", "b", "c"], total: 3 });
      expect(await names("fixable=1")).toEqual({ names: ["a", "c"], total: 2 });
      expect(await names("severity=high&fixable=1")).toEqual({ names: ["a"], total: 1 });
      expect(await names("kev=1&fixable=1")).toEqual({ names: ["c"], total: 1 });
      expect((await get(`/api/v1/hosts/${id}/findings?fixable=2`)).status).toBe(422);
    });
  });
});
