/**
 * The packages API against a throw-away database on the development server (0.1.8): the filters the repositories page has (status
 * by the worst open finding, grade, set aside), the package type, the counts behind the toggles and the menu, and the export.
 * Sessions are replaced by a header-driven actor. Skipped without the development PostgreSQL.
 */
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { desc, eq } from "drizzle-orm";
import { Hono } from "hono";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();
const holder = vi.hoisted(() => ({ db: null as unknown }));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null, boss: null, QUEUES: {} };
  const t = await create(target, "api_packages");
  holder.db = t;
  return { db: t.db, pool: t.pool, QUEUES: {}, boss: null };
});

vi.mock("../env.ts", () => ({ env: { PUBLIC_URL: "https://garnetops.example.test/" }, isProduction: false }));
vi.mock("../auth.ts", () => ({ auth: { api: {} } }));

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
const ORG = "org_pkg_a";

describe.skipIf(!adminUrl)("packages API", () => {
  let t: TestDatabase;
  let app: Hono;
  let counter = 0;
  let shared: string;
  let theirs: string;

  async function get(path: string, user = "usr_member") {
    const res = await app.request(`/api/v1/packages${path}`, {
      headers: { "x-org": ORG, "x-role": "member", "x-user": user },
    });
    const text = await res.text();
    return {
      status: res.status,
      json: (text?.startsWith("{") ? JSON.parse(text) : null) as Json | null,
    };
  }

  async function repo(name: string, options: { owner?: string; inactive?: boolean } = {}) {
    const id = `repo_pkg${++counter}`;
    await t.db.insert(schema.repository).values({
      id,
      organizationId: ORG,
      name,
      url: `https://git.example.lan/${name}.git`,
      authKind: "none",
      visibility: options.owner ? "private" : "organization",
      ownerUserId: options.owner ?? null,
      inactiveAt: options.inactive ? new Date() : null,
    });
    return id;
  }

  /** A package with open findings of these severities (with a fix each). */
  async function pkg(
    repositoryId: string,
    name: string,
    type: string,
    severities: ("critical" | "high" | "medium" | "low")[] = [],
  ) {
    const n = ++counter;
    await t.db.insert(schema.repositoryPackage).values({
      id: `pkg_t${n}`,
      organizationId: ORG,
      repositoryId,
      scanId: "scan_x",
      name,
      version: "1.0.0",
      type,
      purl: `pkg:${type}/${name}@1.0.0`,
      licenses: ["MIT"],
    });
    for (const [i, severity] of severities.entries()) {
      await t.db.insert(schema.finding).values({
        id: `fnd_t${n}_${i}`,
        organizationId: ORG,
        repositoryId,
        vulnerabilityId: "CVE-2099-0202",
        dedupKey: `${n}-${i}`,
        packageName: name,
        packageVersion: "1.0.0",
        packageType: type,
        severity,
        severityRank: { critical: 5, high: 4, medium: 3, low: 2 }[severity],
        state: "open",
        fixedIn: ["1.0.1"],
        firstSeenScanId: "scan_x",
        lastSeenScanId: "scan_x",
        firstSeenAt: new Date(),
        lastSeenAt: new Date(),
      });
    }
  }

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { packageRoutes } = await import("./packages.ts");
    t = holder.db as TestDatabase;
    await t.db.insert(schema.organization).values({ id: ORG, name: "A" });
    await t.db.insert(schema.user).values([
      { id: "usr_member", name: "Member", email: "member@example.com" },
      { id: "usr_other", name: "Other", email: "other@example.com" },
    ]);
    await t.db.insert(schema.vulnerability).values({ id: "CVE-2099-0202", severity: "high" });
    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        {
          userId: c.req.header("x-user"),
          organizationId: c.req.header("x-org"),
          role: c.req.header("x-role"),
          ip: null,
          strongAuthAt: new Date(),
        } as never,
      );
      await next();
    });
    v1.route("/packages", packageRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;

    shared = await repo("shared");
    theirs = await repo("theirs", { owner: "usr_other" });
    const old = await repo("old", { inactive: true });
    await pkg(shared, "alpha", "npm", ["critical", "medium"]);
    await pkg(shared, "bravo", "npm", ["high"]);
    await pkg(shared, "charlie", "python", ["medium"]);
    await pkg(shared, "delta", "python");
    await pkg(theirs, "echo", "npm", ["critical"]);
    await pkg(old, "foxtrot", "go-module", ["critical"]);
  });

  afterAll(async () => {
    await t?.drop();
  });

  const names = (body: Json | null) => ((body?.items ?? []) as { name: string }[]).map((i) => i.name);

  it("filters by the worst open finding, as the repositories page does, and gives each package its grade", async () => {
    const all = await get("");
    expect(names(all.json)).toEqual(["alpha", "bravo", "charlie", "delta"]);
    expect(((all.json?.items ?? []) as Json[]).map((i) => i.grade)).toEqual(["E", "D", "C", "A"]);
    expect(names((await get("?status=blocked")).json)).toEqual(["alpha"]);
    expect(names((await get("?status=attention")).json)).toEqual(["bravo"]);
    expect(names((await get("?status=clean")).json)).toEqual(["charlie", "delta"]);
    expect(names((await get("?grade=E,D")).json)).toEqual(["alpha", "bravo"]);
    expect(names((await get("?sort=grade")).json)).toEqual(["alpha", "bravo", "charlie", "delta"]);
    expect(names((await get("?type=python")).json)).toEqual(["charlie", "delta"]);
    expect((await get("?grade=X")).status).toBe(422);
  });

  it("lists the packages of repositories set aside on request, and of a chosen one whatever its state", async () => {
    expect(names((await get("?activity=inactive")).json)).toEqual(["foxtrot"]);
    expect(names((await get("?activity=all&status=blocked")).json)).toEqual(["alpha", "foxtrot"]);
  });

  it("counts per status, the packages set aside and the types, of the repositories the person sees", async () => {
    expect((await get("/counts")).json).toEqual({
      all: 4,
      blocked: 1,
      attention: 1,
      clean: 2,
      inactive: 1,
      types: ["go-module", "npm", "python"],
    });
    // Another filter narrows the counts; the status does not.
    expect((await get("/counts?type=npm&status=clean")).json).toMatchObject({
      all: 2,
      blocked: 1,
      attention: 1,
      clean: 0,
    });
    expect((await get("/counts", "usr_other")).json).toMatchObject({ all: 5, blocked: 2 });
    expect((await get("/grades")).json).toEqual({ A: 1, B: 0, C: 1, D: 1, E: 1, F: 0, none: 0 });
    expect((await get("/grades?status=blocked")).json).toMatchObject({ E: 1, A: 0 });
  });

  it("the affected view: one row per package over its repositories, worst first, with the version that fixes all", async () => {
    // "alpha" again in a second repository, with a critical fixed in 1.2.0 and a medium fixed in 1.0.5.
    const second = await repo("second");
    await pkg(second, "alpha", "npm", ["critical"]);
    await t.db
      .insert(schema.vulnerability)
      .values({ id: "CVE-2099-0303", severity: "critical" })
      .onConflictDoNothing();
    await t.db
      .update(schema.finding)
      .set({ fixedIn: ["1.2.0"], vulnerabilityId: "CVE-2099-0303" })
      .where(eq(schema.finding.repositoryId, second));
    try {
      const { json } = await get("/affected");
      expect(json?.total).toBe(3);
      const items = (json?.items ?? []) as Json[];
      expect(
        items.map((i) => [i.name, i.repositories, i.openFindings, i.worstSeverityRank, i.grade]),
      ).toEqual([
        ["alpha", 2, 3, 5, "E"],
        ["bravo", 1, 1, 4, "D"],
        ["charlie", 1, 1, 3, "C"],
      ]);
      const alpha = items[0];
      expect(alpha?.repositoryList.map((r: Json) => r.name)).toEqual(["second", "shared"]);
      expect(alpha?.fix).toEqual({ version: "1.2.0", majorUpgrade: false, unresolved: 0 });
      // Clean packages are only in the inventory; another person sees only their repositories.
      expect(JSON.stringify(json)).not.toContain("delta");
      expect(names((await get("/affected?status=attention")).json)).toEqual(["bravo"]);
      expect(names((await get("/affected?status=clean")).json)).toEqual(["charlie"]);
      expect(names((await get("/affected?sort=name&dir=desc")).json)).toEqual(["charlie", "bravo", "alpha"]);
      expect(names((await get("/affected?grade=E")).json)).toEqual(["alpha"]);
      const first = (await get("/affected?pageSize=25")).json;
      expect(first?.next).toBeNull();
      expect((await get("/affected?cursor=x")).status).toBe(422);
      expect((await get("/affected/counts")).json).toEqual({
        all: 3,
        blocked: 1,
        attention: 1,
        clean: 1,
        grades: { A: 0, B: 0, C: 1, D: 1, E: 1, F: 0, none: 0 },
      });
      expect((await get("/affected/counts", "usr_other")).json).toMatchObject({ all: 4, blocked: 2 });

      const file = await app.request("/api/v1/packages/export?format=txt&view=affected&lang=en", {
        headers: { "x-org": ORG, "x-role": "member", "x-user": "usr_member" },
      });
      const text = await file.text();
      expect(text.split("\n")[0]).toBe("Packages with vulnerabilities");
      expect(text).toMatch(/alpha\s+1\.0\.0\s+npm\s+Critical\s+3\s+1\.2\.0\s+2\s+second, shared/);
      expect(text).not.toContain("delta");
    } finally {
      await t.db.delete(schema.finding).where(eq(schema.finding.repositoryId, second));
      await t.db.delete(schema.repositoryPackage).where(eq(schema.repositoryPackage.repositoryId, second));
      await t.db.delete(schema.repository).where(eq(schema.repository.id, second));
    }
  });

  it("exports the list as filtered, and audits it", async () => {
    const download = (query: string) =>
      app.request(`/api/v1/packages/export?${query}`, {
        headers: { "x-org": ORG, "x-role": "member", "x-user": "usr_member" },
      });
    const txt = await download("format=txt&lang=en&tz=Europe/Berlin&status=clean");
    expect(txt.status).toBe(200);
    expect(txt.headers.get("cache-control")).toBe("no-store");
    expect(txt.headers.get("content-disposition")).toMatch(
      /filename="garnetops-packages-\d{4}-\d{2}-\d{2}\.txt"/,
    );
    const text = await txt.text();
    expect(text.split("\n")[0]).toBe("Packages");
    expect(text).toContain("Filters: worst open finding No critical or high");
    expect(text).toContain("Packages: 2");
    expect(text).toMatch(/charlie\s+1\.0\.0\s+python\s+shared\s+C\s+Medium\s+1/);
    expect(text).not.toMatch(/alpha|echo|foxtrot/);

    const xlsx = await download(`format=xlsx&lang=de&repositoryId=${shared}`);
    expect(xlsx.headers.get("content-disposition")).toContain("garnetops-packages-shared-");
    expect(
      Buffer.from(await xlsx.arrayBuffer())
        .subarray(0, 2)
        .toString(),
    ).toBe("PK");
    expect((await download(`format=csv&repositoryId=${theirs}`)).status).toBe(404);
    expect((await download("format=doc")).status).toBe(422);

    const [entry] = await t.db
      .select()
      .from(schema.auditLog)
      .where(eq(schema.auditLog.action, "package.exported"))
      .orderBy(desc(schema.auditLog.createdAt))
      .limit(1);
    expect(entry?.data).toMatchObject({ format: "xlsx", count: 4 });
  });
});
