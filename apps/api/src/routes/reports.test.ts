/**
 * The report API (ADR 0047) against a throw-away PostgreSQL database on the development server: each person's organisation
 * report counts only the repositories they see (another member's private repository stays out of every number and name), a
 * private repository's own report is a 404 for everybody but its owner, the period follows the reader's calendar days,
 * modules that are off answer 409, the PDF is a PDF, and the report mail can only be chosen with a mail channel. Sessions
 * are replaced by a header-driven actor. Skipped without the development PostgreSQL.
 */
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq } from "drizzle-orm";
import { Hono } from "hono";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();
const holder = vi.hoisted(() => ({ db: null as unknown }));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null };
  const t = await create(target, "api_reports");
  holder.db = t;
  return { db: t.db, pool: t.pool };
});

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
const ORG = "org_rep";
const OTHER = "org_rep_other";
/** Alex owns the private repository; Sam is another member of the same organisation. */
const ALEX = "user_rep_alex";
const SAM = "user_rep_sam";
const DAY = 24 * 3600_000;

describe.skipIf(!adminUrl)("report API", () => {
  let t: TestDatabase;
  let app: Hono;
  let counter = 0;

  async function call(method: string, path: string, user: string, body?: unknown, org = ORG) {
    const res = await app.request(path, {
      method,
      headers: {
        "x-user": user,
        "x-org": org,
        ...(body === undefined ? {} : { "content-type": "application/json" }),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const buffer = Buffer.from(await res.arrayBuffer());
    const type = res.headers.get("content-type") ?? "";
    return {
      status: res.status,
      type,
      disposition: res.headers.get("content-disposition"),
      buffer,
      json: type.includes("json") && buffer.length ? (JSON.parse(buffer.toString("utf8")) as Json) : null,
    };
  }

  async function repo(name: string, options: { visibility?: "organization" | "private"; org?: string } = {}) {
    const id = `repo_rep${++counter}`;
    await t.db.insert(schema.repository).values({
      id,
      organizationId: options.org ?? ORG,
      name,
      url: `https://git.example.lan/${name}.git`,
      authKind: "none",
      visibility: options.visibility ?? "organization",
      ownerUserId: ALEX,
    });
    return id;
  }

  async function scan(
    repositoryId: string,
    finishedAt: Date,
    state: "succeeded" | "failed" = "succeeded",
    org = ORG,
  ) {
    const id = `scan_rep${++counter}`;
    await t.db.insert(schema.scan).values({
      id,
      organizationId: org,
      repositoryId,
      state,
      trigger: "manual",
      finishedAt,
      createdAt: finishedAt,
      commitSha: "a".repeat(40),
      packageCount: 10,
    });
    await t.db
      .update(schema.repository)
      .set({ lastScanId: id, lastScanAt: finishedAt })
      .where(eq(schema.repository.id, repositoryId));
    return id;
  }

  async function finding(
    repositoryId: string,
    severity: string,
    options: {
      firstSeen?: Date;
      resolvedAt?: Date;
      state?: "open" | "accepted" | "resolved";
      org?: string;
    } = {},
  ) {
    const id = `fnd_rep${++counter}`;
    const seen = options.firstSeen ?? new Date(Date.now() - DAY);
    await t.db.insert(schema.finding).values({
      id,
      organizationId: options.org ?? ORG,
      repositoryId,
      vulnerabilityId: "CVE-2099-0201",
      dedupKey: id,
      packageName: `pkg-${counter}`,
      packageVersion: "1.0.0",
      packageType: "npm",
      fixedIn: ["1.0.1"],
      severity,
      severityRank: severity === "critical" ? 5 : 4,
      state: options.state ?? (options.resolvedAt ? "resolved" : "open"),
      firstSeenScanId: "scan_x",
      lastSeenScanId: "scan_x",
      firstSeenAt: seen,
      lastSeenAt: seen,
      resolvedAt: options.resolvedAt ?? null,
    });
  }

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { reportRoutes, reportMailRoutes } = await import("./reports.ts");
    t = holder.db as TestDatabase;
    await t.db.insert(schema.organization).values([
      { id: ORG, name: "Example", scanTimeZone: "Europe/Berlin" },
      { id: OTHER, name: "Elsewhere" },
    ]);
    await t.db.insert(schema.user).values([
      { id: ALEX, name: "Alex Example", email: "alex@example.test" },
      { id: SAM, name: "Sam Example", email: "sam@example.test", timeZone: "America/New_York" },
    ]);
    await t.db.insert(schema.membership).values([
      { organizationId: ORG, userId: ALEX, role: "member" },
      { organizationId: ORG, userId: SAM, role: "member" },
    ]);
    await t.db
      .insert(schema.vulnerability)
      .values({ id: "CVE-2099-0201", severity: "critical", knownExploited: true });

    const v1 = new Hono().use("*", async (c, next) => {
      c.set(
        "actor" as never,
        {
          userId: c.req.header("x-user"),
          email: "someone@example.test",
          name: "Someone",
          organizationId: c.req.header("x-org"),
          role: "member",
          ip: null,
        } as never,
      );
      await next();
    });
    v1.route("/reports", reportRoutes as never);
    v1.route("/me", reportMailRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;

    const shared = await repo("shared-app");
    const secret = await repo("alex-private-app", { visibility: "private" });
    const idle = await repo("never-scanned-app");
    void idle;
    await scan(shared, new Date(Date.now() - 2 * 3600_000));
    await scan(secret, new Date(Date.now() - 2 * 3600_000));
    await finding(shared, "critical");
    await finding(shared, "high", { firstSeen: new Date(Date.now() - 40 * DAY) });
    await finding(shared, "high", {
      firstSeen: new Date(Date.now() - 40 * DAY),
      resolvedAt: new Date(Date.now() - DAY),
    });
    await finding(secret, "critical");
    await finding(secret, "critical");
    const elsewhere = await repo("other-org-app", { org: OTHER });
    await finding(elsewhere, "critical", { org: OTHER });
  }, 60_000);

  afterAll(async () => {
    await t?.drop();
  });

  it("the organisation report counts only what each person sees", async () => {
    const sam = await call("GET", "/api/v1/reports/organization?days=7&tz=Europe/Berlin", SAM);
    expect(sam.status).toBe(200);
    expect(sam.json?.findings.open).toEqual({ critical: 1, high: 1, medium: 0, low: 0 });
    expect(sam.json?.findings.opened.critical).toBe(1);
    expect(sam.json?.findings.fixed.high).toBe(1);
    expect(sam.json?.repositories.total).toBe(2);
    expect(JSON.stringify(sam.json)).not.toContain("alex-private-app");
    expect(JSON.stringify(sam.json)).not.toContain("other-org-app");
    expect(sam.json?.repositories.neverScanned.map((r: Json) => r.name)).toEqual(["never-scanned-app"]);

    const alex = await call("GET", "/api/v1/reports/organization?days=7&tz=Europe/Berlin", ALEX);
    expect(alex.json?.findings.open.critical).toBe(3);
    expect(alex.json?.top.repositories[0].name).toBe("alex-private-app");
  });

  it("the period is the reader's calendar days", async () => {
    const res = await call("GET", "/api/v1/reports/organization?days=30&tz=Pacific/Kiritimati", SAM);
    expect(res.json?.period).toMatchObject({ days: 30, timeZone: "Pacific/Kiritimati" });
    expect(res.json?.findings.opened.high).toBe(0);
    expect((await call("GET", "/api/v1/reports/organization?days=8", SAM)).status).toBe(400);
    expect((await call("GET", "/api/v1/reports/organization?tz=Mars/Base", SAM)).status).toBe(400);
  });

  it("downloads the organisation report as PDF", async () => {
    const res = await call("GET", "/api/v1/reports/organization?days=7&format=pdf&lang=de&tz=UTC", SAM);
    expect(res.status).toBe(200);
    expect(res.type).toBe("application/pdf");
    expect(res.buffer.subarray(0, 8).toString("latin1")).toBe("%PDF-1.4");
    expect(res.disposition).toMatch(
      /^attachment; filename="garnetops-report-example-\d{4}-\d{2}-\d{2}\.pdf"$/,
    );
    const [entry] = await t.db
      .select()
      .from(schema.auditLog)
      .where(eq(schema.auditLog.action, "report.exported"))
      .limit(1);
    expect(entry?.actorUserId).toBe(SAM);
  });

  it("a private repository's report is a 404 for everybody but its owner", async () => {
    const [secret] = await t.db
      .select({ id: schema.repository.id })
      .from(schema.repository)
      .where(eq(schema.repository.name, "alex-private-app"));
    expect((await call("GET", `/api/v1/reports/repositories/${secret?.id}`, SAM)).status).toBe(404);
    expect((await call("GET", `/api/v1/reports/repositories/${secret?.id}?format=pdf`, SAM)).status).toBe(
      404,
    );
    const own = await call("GET", `/api/v1/reports/repositories/${secret?.id}`, ALEX);
    expect(own.status).toBe(200);
    expect(own.json?.open.critical).toBe(2);
    expect(own.json?.knownExploited).toBe(2);
    expect(own.json?.nextSteps.map((s: Json) => s.code)).toContain("knownExploited");
    expect(own.json?.top[0]).toMatchObject({ severity: "critical", vulnerabilityId: "CVE-2099-0201" });
  });

  it("a repository of another organisation is a 404", async () => {
    const [other] = await t.db
      .select({ id: schema.repository.id })
      .from(schema.repository)
      .where(eq(schema.repository.name, "other-org-app"));
    expect((await call("GET", `/api/v1/reports/repositories/${other?.id}`, ALEX)).status).toBe(404);
  });

  it("hosts and websites answer 409 while their module is off", async () => {
    expect((await call("GET", "/api/v1/reports/websites", SAM)).status).toBe(409);
    expect((await call("GET", "/api/v1/reports/hosts/host_x", SAM)).status).toBe(409);
  });

  it("the websites at a glance are worst first", async () => {
    await t.db.insert(schema.exposureSettings).values({ organizationId: ORG, enabled: true });
    await t.db.insert(schema.exposureAsset).values([
      {
        id: "ea_ok",
        organizationId: ORG,
        kind: "domain",
        value: "fine.example.com",
        verifyToken: "x".repeat(32),
      },
      {
        id: "ea_bad",
        organizationId: ORG,
        kind: "domain",
        value: "bad.example.com",
        verifyToken: "y".repeat(32),
        uptimeEnabled: true,
        uptimeState: "down",
      },
    ]);
    const res = await call("GET", "/api/v1/reports/websites", SAM);
    expect(res.status).toBe(200);
    expect(res.json?.items.map((w: Json) => w.value)).toEqual(["bad.example.com", "fine.example.com"]);
    expect(res.json?.items[0]).toMatchObject({ worst: "high", availability: { state: "down" } });
    const report = await call("GET", "/api/v1/reports/organization?days=7", SAM);
    expect(report.json?.websites).toHaveLength(2);
    expect(report.json?.nextSteps.map((s: Json) => s.code)).toContain("websitesDown");
  });

  it("the report mail needs a mail channel, and its zone is the person's own", async () => {
    const before = await call("GET", "/api/v1/me/report-mail", SAM);
    expect(before.json).toEqual({
      frequency: null,
      attachPdf: true,
      mailAvailable: false,
      timeZone: "America/New_York",
    });
    expect(
      (await call("PUT", "/api/v1/me/report-mail", SAM, { frequency: "weekly", attachPdf: true })).status,
    ).toBe(422);
    await t.db.insert(schema.notificationChannel).values({
      id: "nch_rep",
      organizationId: ORG,
      name: "Mail",
      kind: "smtp",
      enabled: true,
      events: [],
      config: { host: "mail.example.lan", port: 587, from: "garnetops@example.lan", to: [] },
    });
    const saved = await call("PUT", "/api/v1/me/report-mail", SAM, { frequency: "daily", attachPdf: false });
    expect(saved.json).toMatchObject({ frequency: "daily", attachPdf: false, mailAvailable: true });
    const [row] = await t.db
      .select()
      .from(schema.reportSubscription)
      .where(eq(schema.reportSubscription.userId, SAM));
    const since = row?.since;
    // The same frequency again keeps when it was chosen; another one starts anew.
    await call("PUT", "/api/v1/me/report-mail", SAM, { frequency: "daily", attachPdf: true });
    const [same] = await t.db
      .select()
      .from(schema.reportSubscription)
      .where(eq(schema.reportSubscription.userId, SAM));
    expect(same?.since.getTime()).toBe(since?.getTime());
    expect((await call("GET", "/api/v1/me/report-mail", ALEX)).json?.frequency).toBeNull();
    expect((await call("GET", "/api/v1/me/report-mail", ALEX)).json?.timeZone).toBe("Europe/Berlin");
    await call("PUT", "/api/v1/me/report-mail", SAM, { frequency: null });
    expect(await t.db.select().from(schema.reportSubscription)).toHaveLength(0);
  });
});
