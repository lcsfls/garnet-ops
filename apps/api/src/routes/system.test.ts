/**
 * The System status API (ADR 0024) against a throw-away PostgreSQL database on the development
 * server: who may read it, the shape of the answer, and the states for seeded situations: fresh,
 * stale, outdated, failed, blocked and not configured. The queue overview runs against a real
 * pg-boss schema, so a change in pg-boss's tables shows up here. Sessions are replaced by a
 * header-driven actor. Skipped without the development PostgreSQL.
 */
import { PINNED_SCANNERS } from "@garnetops/core/system-status";
import type { SystemStatus } from "@garnetops/core/system-status-view";
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { sql } from "drizzle-orm";
import { Hono } from "hono";
import { PgBoss } from "pg-boss";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import type { UpdaterFacts } from "../lib/system-status.ts";

const adminUrl = devDatabaseUrl();

const held = vi.hoisted(() => ({
  db: null as unknown,
  updater: { state: async () => null as unknown },
  updaterUrl: "",
}));

vi.mock("../db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null, boss: null, QUEUES: {} };
  const t = await create(target, "api_sysstatus");
  held.db = t;
  return { db: t.db, pool: t.pool, boss: null, QUEUES: {} };
});
vi.mock("../env.ts", () => ({
  env: {
    PUBLIC_URL: "https://garnetops.example.test/",
    get UPDATER_URL() {
      return held.updaterUrl;
    },
  },
  isProduction: false,
}));
vi.mock("../auth.ts", () => ({ auth: { api: {} } }));
vi.mock("../updater/client.ts", () => ({ updater: held.updater }));

// biome-ignore lint/suspicious/noExplicitAny: test helper for arbitrary response bodies
type Json = Record<string, any>;
type Role = "owner" | "admin" | "member" | "viewer";
const ORG = "org_ss_a";
const OTHER = "org_ss_b";
const NOW = new Date("2026-10-23T12:00:00.000Z");
const MIN = 60_000;
const HOUR = 3_600_000;
const DAY = 86_400_000;
const ago = (ms: number) => new Date(NOW.getTime() - ms);

describe.skipIf(!adminUrl)("System status API", () => {
  let t: TestDatabase;
  let app: Hono;
  let boss: PgBoss;
  let build: typeof import("../lib/system-status.ts").buildSystemStatus;
  let queues: typeof import("../lib/system-status.ts").readQueues;
  let counter = 0;

  async function call(role: Role = "admin", org = ORG) {
    const res = await app.request("/api/v1/system/status", { headers: { "x-role": role, "x-org": org } });
    const text = await res.text();
    return { status: res.status, json: JSON.parse(text) as Json, text, headers: res.headers };
  }
  /** The view for the fixed clock; the route itself reads the real one. */
  const view = (
    updater: UpdaterFacts = { configured: false, phase: null, latestAvailable: null },
  ): Promise<SystemStatus> => build(ORG, updater, NOW);
  const row = (status: SystemStatus, key: string) => status.integrations.find((i) => i.key === key);
  const partOf = (status: SystemStatus, key: string, part: string) =>
    row(status, key)?.parts.find((p) => p.key === part);

  const heartbeat = (beatAgoMs: number, version = "0.0.7") =>
    t.db.insert(schema.workerHeartbeat).values({
      instanceId: `wrk_${++counter}`,
      version,
      startedAt: ago(2 * HOUR),
      beatAt: ago(beatAgoMs),
    });
  const report = (key: string, data: unknown) =>
    t.db.insert(schema.systemReport).values({ key, data }).onConflictDoUpdate({
      target: schema.systemReport.key,
      set: { data },
    });
  const vulnDbReport = (builtAgoMs: number | null, extra: Record<string, unknown> = {}) =>
    report("vulndb", {
      checkedAt: ago(5 * MIN).toISOString(),
      valid: true,
      problem: null,
      schemaVersion: "6.1.5",
      builtAt: builtAgoMs === null ? null : ago(builtAgoMs).toISOString(),
      source: "anchore",
      providers: {
        available: true,
        items: [
          { name: "nvd", version: "6", capturedAt: ago(DAY).toISOString(), records: 250_000 },
          { name: "debian", version: "6", capturedAt: null, records: null },
        ],
      },
      ...extra,
    });

  beforeAll(async () => {
    const { handleError } = await import("../lib/problem.ts");
    const { systemRoutes } = await import("./system.ts");
    const lib = await import("../lib/system-status.ts");
    build = lib.buildSystemStatus;
    queues = lib.readQueues;
    t = held.db as TestDatabase;
    boss = new PgBoss({ connectionString: t.url });
    boss.on("error", () => {});
    await boss.start();
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
          ip: null,
          strongAuthAt: new Date(),
        } as never,
      );
      await next();
    });
    v1.route("/system", systemRoutes as never);
    app = new Hono().onError(handleError).route("/api/v1", v1) as unknown as Hono;
  }, 90_000);

  afterAll(async () => {
    await boss?.stop({ graceful: false }).catch(() => {});
    await t?.drop();
  });

  beforeEach(async () => {
    await t.pool.query(`truncate worker_heartbeat, system_report, scan, scan_schedule_run, ldap_config,
      ai_settings, notification_channel, notification_delivery, repository cascade`);
    held.updaterUrl = "";
    await t.db
      .update(schema.organization)
      .set({ scanScheduleEnabled: true, scanTimeZone: "Europe/Berlin", scanLocalTime: "04:00:00" });
  });

  describe("who may read it", () => {
    it("lets only owners and admins read the status", async () => {
      for (const role of ["owner", "admin"] as const) {
        const r = await call(role);
        expect(r.status, role).toBe(200);
        expect(r.headers.get("cache-control")).toBe("no-store");
      }
      for (const role of ["member", "viewer"] as const) {
        expect((await call(role)).status, role).toBe(403);
      }
    });

    it("keeps the small public facts open to every signed-in user", async () => {
      const res = await app.request("/api/v1/system", { headers: { "x-role": "viewer", "x-org": ORG } });
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ version: "0.0.7" });
    });

    it("shows nothing of another organisation", async () => {
      await t.db.insert(schema.notificationChannel).values({
        id: "nch_other",
        organizationId: OTHER,
        name: "Other channel",
        kind: "webhook",
        events: [],
        config: {},
      });
      await t.db.insert(schema.notificationDelivery).values({
        id: "ndl_other",
        organizationId: OTHER,
        channelId: "nch_other",
        event: "scan.failed",
        status: "failed",
        error: "timeout",
      });
      const r = await call("admin", ORG);
      expect(r.text).not.toContain("Other channel");
      const other = await call("admin", OTHER);
      expect(other.json.integrations.find((i: Json) => i.key === "notifications").count).toBe(1);
      expect(other.text).toContain("Other channel");
    });
  });

  describe("the shape", () => {
    it("has every section, the refresh interval and the app version", async () => {
      const r = await call();
      expect(Object.keys(r.json).sort()).toEqual(
        [
          "app",
          "generatedAt",
          "integrations",
          "localBuild",
          "overall",
          "refreshSeconds",
          "scanners",
          "vulnDb",
          "worker",
        ].sort(),
      );
      expect(r.json.refreshSeconds).toBe(60);
      expect(r.json.app.version).toBe("0.0.7");
      expect(r.json.integrations.map((i: Json) => i.key)).toEqual(["directory", "ai", "notifications"]);
      expect(r.json.scanners.items.map((s: Json) => s.name)).toEqual(["grype", "syft"]);
      expect(r.json.vulnDb.thresholds).toEqual({ staleAfterDays: 3, outdatedAfterDays: 7 });
    });

    it("never carries a secret, an address or a fingerprint", async () => {
      await t.db.insert(schema.notificationChannel).values({
        id: "nch_secret",
        organizationId: ORG,
        name: "Ops mail",
        kind: "smtp",
        events: [],
        config: { host: "smtp-secret.example.lan", recipients: ["ops@example.test"] },
        secretId: null,
      });
      await t.db.insert(schema.notificationDelivery).values({
        id: "ndl_secret",
        organizationId: ORG,
        channelId: "nch_secret",
        event: "scan.failed",
        status: "failed",
        error: "refused address",
      });
      await t.db.insert(schema.ldapConfig).values({
        organizationId: ORG,
        enabled: true,
        preset: "openldap",
        bindDn: "cn=reader,dc=example,dc=lan",
        userBaseDn: "ou=people,dc=example,dc=lan",
        userFilter: "(uid={{username}})",
        uniqueIdAttribute: "entryUUID",
        groupMode: "member-of",
        servers: [{ url: "ldaps://dc1.example.lan", pin: null, candidate: null, certStatus: "changed" }],
      });
      const r = await call();
      expect(r.text).toContain("Ops mail");
      for (const forbidden of [
        "example.lan",
        "example.test",
        "cn=reader",
        "secretId",
        "password",
        "apiKey",
        "fingerprint",
      ]) {
        expect(r.text, forbidden).not.toContain(forbidden);
      }
    });
  });

  describe("scanners", () => {
    it("matches the pinned versions", async () => {
      await report("scanners", {
        grype: { version: PINNED_SCANNERS.grype, reportedAt: ago(MIN).toISOString(), problem: null },
        syft: { version: PINNED_SCANNERS.syft, reportedAt: ago(MIN).toISOString(), problem: null },
      });
      const s = await view();
      expect(s.scanners.items.map((i) => [i.name, i.match, i.level, i.pinned])).toEqual([
        ["grype", "match", "ok", PINNED_SCANNERS.grype],
        ["syft", "match", "ok", PINNED_SCANNERS.syft],
      ]);
      expect(s.scanners.level).toBe("ok");
    });

    it("shows a different version as attention, and a missing binary as failed", async () => {
      await report("scanners", {
        grype: { version: "0.1.0", reportedAt: ago(MIN).toISOString(), problem: null },
        syft: { version: null, reportedAt: ago(MIN).toISOString(), problem: "missing" },
      });
      const s = await view();
      expect(s.scanners.items[0]).toMatchObject({ match: "differs", level: "attention", version: "0.1.0" });
      expect(s.scanners.items[1]).toMatchObject({ match: "unknown", level: "failed", problem: "missing" });
      expect(s.scanners.level).toBe("failed");
    });

    it("treats an unset syft as inactive and falls back to the latest scan before the worker reports", async () => {
      await report("scanners", {
        grype: { version: PINNED_SCANNERS.grype, reportedAt: ago(MIN).toISOString(), problem: null },
        syft: { version: null, reportedAt: ago(MIN).toISOString(), problem: "not_configured" },
      });
      expect((await view()).scanners.items[1]).toMatchObject({
        level: "inactive",
        problem: "not_configured",
      });

      await t.pool.query("truncate system_report");
      await t.db.insert(schema.repository).values({
        id: "repo_ss",
        organizationId: ORG,
        name: "app",
        url: "https://git.example.test/team/app.git",
        authKind: "none",
      });
      await t.db.insert(schema.scan).values({
        id: "scan_ss",
        organizationId: ORG,
        repositoryId: "repo_ss",
        state: "succeeded",
        trigger: "manual",
        finishedAt: ago(HOUR),
        scannerVersions: { grype: PINNED_SCANNERS.grype },
        vulnDbBuiltAt: ago(DAY),
      });
      const s = await view();
      expect(s.scanners.items[0]).toMatchObject({ version: PINNED_SCANNERS.grype, match: "match" });
      expect(s.scanners.items[1]).toMatchObject({ version: null, match: "unknown" });
      expect(s.vulnDb).toMatchObject({ reported: false, freshness: "current" });
    });
  });

  describe("the vulnerability database", () => {
    it("is current within three days", async () => {
      await vulnDbReport(DAY);
      const s = await view();
      expect(s.vulnDb).toMatchObject({
        reported: true,
        freshness: "current",
        level: "ok",
        valid: true,
        ageDays: 1,
        schemaVersion: "6.1.5",
        source: "anchore",
      });
      expect(s.vulnDb.providers.items).toEqual([
        { name: "nvd", version: "6", capturedAt: ago(DAY).toISOString(), records: 250_000 },
        { name: "debian", version: "6", capturedAt: null, records: null },
      ]);
    });

    it("is stale (attention) after three days and outdated (failed) after seven", async () => {
      await vulnDbReport(4 * DAY);
      expect(await view()).toMatchObject({ vulnDb: { freshness: "stale", level: "attention", ageDays: 4 } });
      await vulnDbReport(8 * DAY);
      expect(await view()).toMatchObject({ vulnDb: { freshness: "outdated", level: "failed", ageDays: 8 } });
    });

    it("fails when there is no usable database", async () => {
      await vulnDbReport(null, {
        valid: false,
        problem: "missing",
        schemaVersion: null,
        providers: { available: false, items: [] },
      });
      const s = await view();
      expect(s.vulnDb).toMatchObject({
        level: "failed",
        valid: false,
        problem: "missing",
        freshness: "unknown",
      });
    });

    it("says what happened to the last update, as a code", async () => {
      await vulnDbReport(DAY);
      await report("vulndb_update", {
        mode: "auto",
        lastAttemptAt: ago(2 * HOUR).toISOString(),
        lastSuccessAt: ago(DAY).toISOString(),
        lastResult: "failed",
        reason: "network",
        nextAt: new Date(NOW.getTime() + 22 * HOUR).toISOString(),
      });
      const s = await view();
      expect(s.vulnDb.update).toMatchObject({
        mode: "auto",
        lastResult: "failed",
        reason: { family: "vulndb-update", value: "network" },
      });
      // A failed update with a current database needs a look, but nothing is broken.
      expect(s.vulnDb.level).toBe("attention");
    });

    it("ignores a damaged report instead of failing", async () => {
      await report("vulndb", { valid: "yes" });
      await report("vulndb_update", "garbage");
      const s = await view();
      expect(s.vulnDb).toMatchObject({ reported: false, level: "attention" });
      expect(s.vulnDb.update).toMatchObject({ mode: null, lastResult: null });
    });
  });

  describe("the local build", () => {
    it("is not set up until a builder reports", async () => {
      expect(await view()).toMatchObject({
        localBuild: { state: "not_set_up", level: "inactive", providers: [] },
      });
    });

    it("lists what a builder reports per provider", async () => {
      await report("vulndb_build", {
        v: 1,
        enabled: true,
        lastBuildAt: ago(HOUR).toISOString(),
        extraFieldOfALaterVersion: true,
        providers: [
          {
            name: "nvd",
            lastRunAt: ago(HOUR).toISOString(),
            result: "ok",
            records: 250_000,
            durationMs: 420_000,
            reason: null,
          },
          {
            name: "debian",
            lastRunAt: ago(HOUR).toISOString(),
            result: "failed",
            records: null,
            durationMs: 900,
            reason: "network",
          },
        ],
      });
      const s = await view();
      expect(s.localBuild).toMatchObject({ state: "set_up", level: "failed" });
      expect(s.localBuild.providers.map((p) => [p.name, p.level, p.records, p.reason])).toEqual([
        ["nvd", "ok", 250_000, null],
        ["debian", "failed", null, "network"],
      ]);
    });
  });

  describe("integrations", () => {
    it("are all not configured on a fresh installation", async () => {
      const s = await view();
      for (const i of s.integrations) {
        expect(i, i.key).toMatchObject({
          state: "not_configured",
          level: "inactive",
          configured: false,
          count: 0,
          parts: [],
        });
      }
    });

    it("reads the directory check: ok, never run, could not ask, and a blocked service account", async () => {
      await t.db.insert(schema.ldapConfig).values({
        organizationId: ORG,
        enabled: true,
        preset: "openldap",
        bindDn: "cn=reader,dc=example,dc=lan",
        userBaseDn: "ou=people,dc=example,dc=lan",
        userFilter: "(uid={{username}})",
        uniqueIdAttribute: "entryUUID",
        groupMode: "member-of",
      });
      expect(partOf(await view(), "directory", "reconcile")).toMatchObject({
        state: "waiting",
        level: "attention",
      });

      await t.db
        .update(schema.ldapConfig)
        .set({ lastReconcileAt: ago(5 * MIN), lastReconcileResult: "ok", lastReconcileChecked: 12 });
      let s = await view();
      expect(partOf(s, "directory", "reconcile")).toMatchObject({
        state: "current",
        detail: { accountsChecked: 12 },
      });

      await t.db.update(schema.ldapConfig).set({ lastReconcileResult: "skipped" });
      s = await view();
      expect(partOf(s, "directory", "reconcile")).toMatchObject({
        state: "failed",
        reason: { family: "status", value: "directoryUnreachable" },
      });

      await t.db.update(schema.ldapConfig).set({ bindBlockedUntil: new Date(NOW.getTime() + HOUR) });
      expect(partOf(await view(), "directory", "reconcile")).toMatchObject({
        state: "blocked",
        blocked: "credentials",
      });

      await t.db.update(schema.ldapConfig).set({ enabled: false });
      expect(row(await view(), "directory")).toMatchObject({ state: "paused", level: "inactive" });
    });

    it("reads the AI endpoint: tested, failed, replaced since, and external without acknowledgement", async () => {
      const settings = {
        organizationId: ORG,
        baseUrl: "https://llm.example.lan/v1",
        model: "local-model",
        enabled: true,
        endpointScope: "private" as const,
      };
      await t.db.insert(schema.aiSettings).values(settings);
      expect(partOf(await view(), "ai", "probe")).toMatchObject({ state: "waiting", level: "attention" });

      await t.db
        .update(schema.aiSettings)
        .set({ lastProbeAt: ago(HOUR), lastProbeOk: true, lastProbeUrl: settings.baseUrl });
      let s = await view();
      expect(partOf(s, "ai", "probe")).toMatchObject({ state: "current", detail: { scope: "private" } });

      await t.db.update(schema.aiSettings).set({ lastProbeOk: false, lastProbeError: "auth" });
      s = await view();
      expect(partOf(s, "ai", "probe")).toMatchObject({
        state: "failed",
        reason: { family: "ai", value: "auth" },
      });

      await t.db.update(schema.aiSettings).set({ baseUrl: "https://other.example.lan/v1" });
      expect(partOf(await view(), "ai", "probe")?.state).toBe("waiting");

      await t.db.update(schema.aiSettings).set({
        baseUrl: "https://llm.example.com/v1",
        endpointScope: "external",
        lastProbeUrl: "https://llm.example.com/v1",
        lastProbeOk: true,
        lastProbeError: null,
      });
      expect(partOf(await view(), "ai", "probe")).toMatchObject({
        state: "blocked",
        blocked: "acknowledgement",
        detail: { scope: "external" },
      });
      await t.db.update(schema.aiSettings).set({ externalAckHost: "llm.example.com" });
      expect(partOf(await view(), "ai", "probe")).toMatchObject({ state: "current" });

      await t.db.update(schema.aiSettings).set({ enabled: false });
      expect(row(await view(), "ai")).toMatchObject({ state: "paused" });
    });

    it("reads the notification channels by their last delivery", async () => {
      const channel = (name: string, enabled = true) =>
        t.db.insert(schema.notificationChannel).values({
          id: `nch_${++counter}`,
          organizationId: ORG,
          name,
          kind: "webhook",
          events: [],
          config: {},
          enabled,
        });
      await channel("Chat");
      await channel("Mail");
      await channel("Old", false);
      const [chat, mail] = await t.db
        .select()
        .from(schema.notificationChannel)
        .orderBy(schema.notificationChannel.name);
      const delivery = (
        channelId: string,
        status: "sent" | "failed",
        agoMs: number,
        error: string | null = null,
      ) =>
        t.db.insert(schema.notificationDelivery).values({
          id: `ndl_${++counter}`,
          organizationId: ORG,
          channelId,
          event: "scan.finished",
          status,
          error,
          createdAt: ago(agoMs),
        });
      // Never delivered anything: nothing is wrong.
      expect(partOf(await view(), "notifications", "delivery")).toMatchObject({
        state: "current",
        lastAttemptOk: null,
      });

      await delivery(chat?.id as string, "sent", 2 * HOUR);
      await delivery(chat?.id as string, "failed", HOUR, "timeout");
      await delivery(mail?.id as string, "sent", 30 * MIN);
      const p = partOf(await view(), "notifications", "delivery");
      expect(p).toMatchObject({
        state: "failed",
        lastAttemptOk: false,
        lastSuccessAt: ago(30 * MIN).toISOString(),
        reason: { family: "raw", value: "timeout" },
        detail: { connections: 3, enabled: 2, failed: 1 },
      });
      expect(p?.instances).toEqual([
        {
          name: "Chat",
          state: "failed",
          lastSuccessAt: ago(2 * HOUR).toISOString(),
          reason: { family: "raw", value: "timeout" },
          blocked: null,
        },
      ]);
      // A newer delivery that worked ends the failure.
      await delivery(chat?.id as string, "sent", 10 * MIN);
      expect(partOf(await view(), "notifications", "delivery")).toMatchObject({
        state: "current",
        lastAttemptOk: true,
      });
    });
  });

  describe("the worker", () => {
    it("is missing without a heartbeat, running with a recent one, late after three missed beats", async () => {
      expect((await view()).worker).toMatchObject({ liveness: "missing", heartbeat: null });
      await heartbeat(20_000, "0.0.7");
      let s = await view();
      expect(s.worker).toMatchObject({
        liveness: "running",
        heartbeat: {
          version: "0.0.7",
          instances: 1,
          startedAt: ago(2 * HOUR).toISOString(),
          beatAt: ago(20_000).toISOString(),
        },
      });
      await t.pool.query("truncate worker_heartbeat");
      await heartbeat(3 * MIN);
      s = await view();
      expect(s.worker.liveness).toBe("late");
      expect(s.worker.level).toBe("failed");
    });

    it("counts the workers that beat and reports the newest", async () => {
      await heartbeat(10_000, "0.0.7");
      await heartbeat(20_000, "0.0.7");
      await heartbeat(HOUR, "0.0.7");
      expect((await view()).worker.heartbeat).toMatchObject({ version: "0.0.7", instances: 2 });
    });

    it("reports the database size and that every migration is applied", async () => {
      const s = await view();
      expect(s.worker.database.sizeBytes).toBeGreaterThan(0);
      expect(s.worker.database.migrations.applied).toBe(s.worker.database.migrations.expected);
      expect(s.worker.database.migrations.latest).toMatch(/^\d{4}_/);
      expect(s.worker.database.level).toBe("ok");
    });

    it("tells the last nightly run and the next one", async () => {
      // 04:00 Europe/Berlin; NOW is 14:00 CEST on the 23rd.
      await t.db.insert(schema.repository).values({
        id: "repo_n",
        organizationId: ORG,
        name: "app",
        url: "https://git.example.test/team/app.git",
        authKind: "none",
      });
      const run = ago(10 * HOUR);
      await t.db
        .insert(schema.scanScheduleRun)
        .values({ organizationId: ORG, localDate: "2026-10-23", queuedScans: 3, createdAt: run });
      const scan = (
        id: string,
        state: "queued" | "running" | "succeeded" | "failed",
        trigger: "schedule" | "manual",
        at: Date,
      ) =>
        t.db
          .insert(schema.scan)
          .values({ id, organizationId: ORG, repositoryId: "repo_n", state, trigger, createdAt: at });
      await scan("scan_n1", "succeeded", "schedule", new Date(run.getTime() + 500));
      await scan("scan_n2", "failed", "schedule", new Date(run.getTime() + 600));
      await scan("scan_n3", "running", "schedule", new Date(run.getTime() + 700));
      await scan("scan_n4", "succeeded", "manual", new Date(run.getTime() + 800));
      await scan("scan_n0", "succeeded", "schedule", ago(2 * DAY));
      const { nightly } = (await view()).worker;
      expect(nightly).toMatchObject({
        enabled: true,
        localTime: "04:00:00",
        timeZone: "Europe/Berlin",
        lastRun: {
          at: run.toISOString(),
          localDate: "2026-10-23",
          queued: 3,
          succeeded: 1,
          failed: 1,
          pending: 1,
        },
        // The run for the 23rd exists, so the next one is the 24th at 04:00 CEST.
        nextAt: "2026-10-24T02:00:00.000Z",
      });
    });

    it("has no next run when the schedule is off", async () => {
      await t.db.update(schema.organization).set({ scanScheduleEnabled: false });
      expect((await view()).worker.nightly).toMatchObject({ enabled: false, nextAt: null, lastRun: null });
    });
  });

  describe("the queues, against a real pg-boss schema", () => {
    afterAll(async () => {
      for (const name of ["status.idle", "status.busy", "status.failing"])
        await boss.deleteQueue(name).catch(() => {});
    });
    const stateOf = (name: string) => queues().then((q) => q.items.find((i) => i.name === name));

    it("leaves out pg-boss's own housekeeping queues", async () => {
      const names = (await queues()).items.map((i) => i.name);
      expect(names.some((n) => n.startsWith("__pgboss__"))).toBe(false);
      const all = await t.db.execute(sql`select name from pgboss.queue where left(name, 10) = '__pgboss__'`);
      // The test is only meaningful if pg-boss really made such a queue.
      expect(all.rows.length).toBeGreaterThan(0);
    });

    it("lists every queue, with zero counts for an idle one", async () => {
      await boss.createQueue("status.idle");
      expect(await stateOf("status.idle")).toEqual({
        name: "status.idle",
        level: "ok",
        queued: 0,
        active: 0,
        failed24h: 0,
        oldestQueuedSeconds: null,
      });
    });

    it("counts queued, active and failed jobs and the wait of the oldest ready one", async () => {
      const name = "status.busy";
      await boss.createQueue(name);
      const ready = await boss.send(name, { n: 1 });
      await boss.send(name, { n: 2 });
      await boss.send(name, { n: 3 }, { startAfter: 3600 }); // not ready: does not count as waiting
      await t.db.execute(
        sql`update pgboss.job set start_after = now() - interval '20 minutes' where id = ${ready}`,
      );
      const busy = await stateOf(name);
      expect(busy).toMatchObject({ queued: 3, active: 0, failed24h: 0, level: "attention" });
      expect(busy?.oldestQueuedSeconds).toBeGreaterThanOrEqual(1199);
      expect(busy?.oldestQueuedSeconds).toBeLessThan(1260);

      const jobs = await boss.fetch(name, { batchSize: 2 });
      expect(jobs).toHaveLength(2);
      expect(await stateOf(name)).toMatchObject({ queued: 1, active: 2 });
    });

    it("counts failed jobs of the last 24 hours only", async () => {
      const name = "status.failing";
      await boss.createQueue(name, { retryLimit: 0 } as never);
      await boss.send(name, { n: 1 }, { retryLimit: 0 });
      await boss.send(name, { n: 2 }, { retryLimit: 0 });
      const [a, b] = await boss.fetch(name, { batchSize: 2 });
      await boss.fail(name, a?.id as string);
      await boss.fail(name, b?.id as string);
      expect(await stateOf(name)).toMatchObject({ failed24h: 2, active: 0, level: "attention" });
      await t.db.execute(
        sql`update pgboss.job set completed_on = now() - interval '25 hours' where id = ${a?.id as string}`,
      );
      expect(await stateOf(name)).toMatchObject({ failed24h: 1 });
    });

    it("says so instead of guessing when pg-boss's tables are not what it expects", async () => {
      const quiet = vi.spyOn(console, "error").mockImplementation(() => {});
      await t.db.execute(sql`alter table pgboss.queue rename to queue_away`);
      try {
        expect(await queues()).toEqual({ available: false, items: [] });
        const s = await view();
        expect(s.worker.queues).toMatchObject({ available: false, level: "attention" });
      } finally {
        await t.db.execute(sql`alter table pgboss.queue_away rename to queue`);
        quiet.mockRestore();
      }
    });
  });

  describe("the app and its updater", () => {
    it("has no updater to report when none is set up", async () => {
      const s = await view({ configured: false, phase: null, latestAvailable: null });
      expect(s.app).toMatchObject({
        version: "0.0.7",
        updater: { configured: false, reachable: false, level: "inactive" },
      });
    });

    it("reports the sidecar's phase and the newest release it knows", async () => {
      const s = await view({ configured: true, phase: "idle", latestAvailable: "0.0.7" });
      expect(s.app.updater).toEqual({
        configured: true,
        reachable: true,
        level: "ok",
        phase: "idle",
        latestAvailable: "0.0.7",
      });
      expect(
        (await view({ configured: true, phase: "failed", latestAvailable: null })).app.updater.level,
      ).toBe("failed");
      expect(
        (await view({ configured: true, phase: null, latestAvailable: null })).app.updater,
      ).toMatchObject({
        reachable: false,
        level: "attention",
      });
    });

    it("asks the sidecar through the route, and a sidecar that is down is a fact, not an error", async () => {
      held.updaterUrl = "http://updater.example.test:8090";
      held.updater.state = async () => ({ phase: "scheduled", updater: { latestAvailable: "0.0.7" } });
      let r = await call();
      expect(r.json.app.updater).toMatchObject({
        configured: true,
        reachable: true,
        phase: "scheduled",
        latestAvailable: "0.0.7",
      });
      held.updater.state = async () => {
        throw new Error("connection refused");
      };
      r = await call();
      expect(r.status).toBe(200);
      expect(r.json.app.updater).toMatchObject({ configured: true, reachable: false, level: "attention" });
    });
  });

  describe("the overall verdict", () => {
    it("counts what needs a look and what failed, and ignores what is not set up", async () => {
      await heartbeat(10_000);
      await vulnDbReport(DAY);
      await report("scanners", {
        grype: { version: PINNED_SCANNERS.grype, reportedAt: ago(MIN).toISOString(), problem: null },
        syft: { version: PINNED_SCANNERS.syft, reportedAt: ago(MIN).toISOString(), problem: null },
      });
      let s = await view();
      expect(s.overall).toEqual({ level: "ok", attention: 0, failed: 0 });

      await vulnDbReport(5 * DAY); // stale
      s = await view();
      expect(s.overall).toEqual({ level: "attention", attention: 1, failed: 0 });

      await t.db.insert(schema.notificationChannel).values({
        id: "nch_v",
        organizationId: ORG,
        name: "Chat",
        kind: "webhook",
        events: [],
        config: {},
      });
      await t.db.insert(schema.notificationDelivery).values({
        id: "ndl_v",
        organizationId: ORG,
        channelId: "nch_v",
        event: "scan.failed",
        status: "failed",
        error: "timeout",
        createdAt: ago(MIN),
      });
      s = await view();
      expect(s.overall).toEqual({ level: "failed", attention: 1, failed: 1 });
    });
  });
});
