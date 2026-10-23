/**
 * What the worker reports for the System status page (ADR 0024), against a throw-away PostgreSQL
 * database on the development server and fake scanner binaries (small shell scripts that print what
 * the real tools print, set through the same configurable binary paths the worker uses): the
 * version of each scanner, the database metadata with its providers and counts, the automatic
 * update's result as a short code, and the heartbeat. Skipped without the development PostgreSQL or
 * a POSIX shell.
 */
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import {
  scannersReportSchema,
  vulnDbReportSchema,
  vulnDbUpdateReportSchema,
} from "@garnetops/core/system-status";
import { schema } from "@garnetops/db";
import { devDatabaseUrl, type TestDatabase } from "@garnetops/db/testing";
import { eq, sql } from "drizzle-orm";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";

const adminUrl = devDatabaseUrl();
const posix = process.platform !== "win32";

const work = mkdtempSync(join(tmpdir(), "garnetops-system-report-test-"));
afterAll(() => rmSync(work, { recursive: true, force: true }));

const held = vi.hoisted(() => ({
  t: null as unknown,
  env: {} as Record<string, string | undefined>,
}));

vi.mock("./db.ts", async () => {
  const { createTestDatabase: create, devDatabaseUrl: url } = await import("@garnetops/db/testing");
  const target = url();
  if (!target) return { db: null, pool: null };
  const t = await create(target, "worker_sysrep");
  held.t = t;
  return { db: t.db, pool: t.pool };
});
vi.mock("./env.ts", () => ({ env: held.env }));

/** A fake `grype` that answers like the real one for the commands the worker runs. */
function fakeGrype(
  dir: string,
  options: { dbFile: string; updateExit?: number; updateError?: string; noDb?: boolean },
) {
  const file = join(dir, `grype-${Math.random().toString(36).slice(2)}`);
  const providers = JSON.stringify([
    {
      name: "nvd",
      version: "6",
      processor: "vunnel",
      dateCaptured: "2026-10-22T04:00:00Z",
      inputDigest: "xxh64:aa",
    },
    {
      name: "github",
      version: "6",
      processor: "vunnel",
      dateCaptured: "2026-10-22T04:10:00Z",
      inputDigest: "xxh64:bb",
    },
    {
      name: "debian",
      version: "6",
      processor: "vunnel",
      dateCaptured: "0001-01-01T00:00:00Z",
      inputDigest: "xxh64:cc",
    },
  ]);
  const status = JSON.stringify({
    schemaVersion: "6.1.5",
    from: "https://grype.example.com/databases/v6/vulnerability-db_example.tar.zst",
    built: "2026-10-22T06:39:15Z",
    path: options.dbFile,
    valid: true,
  });
  writeFileSync(
    file,
    `#!/bin/sh
case "$*" in
  "version") printf 'Application:         grype\\nVersion:             0.120.1\\nBuildDate:           2026-10-06T20:41:29Z\\n' ;;
  "db status -o json" | "db providers -o json")
    # Like the real tool, a database older than five days is invalid unless the age check is switched off.
    [ "$GRYPE_DB_VALIDATE_AGE" = "false" ] && [ "$GRYPE_DB_VALIDATE_BY_HASH_ON_START" = "false" ] && [ "$GRYPE_DB_AUTO_UPDATE" = "false" ] || { echo 'validation failed' >&2; exit 1; }
    case "$*" in
  "db status -o json")
    ${
      options.noDb
        ? `echo '{"schemaVersion":"","valid":false,"error":"database does not exist"}'; echo 'ERROR database does not exist' >&2; exit 1`
        : `echo '${status}'`
    } ;;
  "db providers -o json") echo '${providers}' ;;
    esac ;;
  "db update")
    ${options.updateError ? `echo '${options.updateError}' >&2;` : ""} exit ${options.updateExit ?? 0} ;;
  *) echo "unexpected: $*" >&2; exit 2 ;;
esac
`,
  );
  chmodSync(file, 0o755);
  return file;
}

function fakeSyft(dir: string, version: string) {
  const file = join(dir, `syft-${Math.random().toString(36).slice(2)}`);
  writeFileSync(file, `#!/bin/sh\nprintf 'Application:   syft\\nVersion:       ${version}\\n'\n`);
  chmodSync(file, 0o755);
  return file;
}

describe.skipIf(!adminUrl || !posix)("system report", () => {
  let t: TestDatabase;
  let dbFile: string;
  let mod: typeof import("./system-report.ts");

  beforeAll(async () => {
    mod = await import("./system-report.ts");
    t = held.t as TestDatabase;
    mkdirSync(join(work, "db"), { recursive: true });
    dbFile = join(work, "db", "vulnerability.db");
    const sqlite = new DatabaseSync(dbFile);
    sqlite.exec("create table vulnerability_handles (id integer primary key, name text, provider_id text)");
    const insert = sqlite.prepare("insert into vulnerability_handles (name, provider_id) values (?, ?)");
    for (let i = 0; i < 5; i++) insert.run(`CVE-2099-${i}`, "nvd");
    for (let i = 0; i < 3; i++) insert.run(`GHSA-${i}`, "github");
    sqlite.close();
    held.env.GARNETOPS_WORK_DIR = work;
    held.env.GARNETOPS_GRYPE_DB_DIR = join(work, "db");
  }, 60_000);
  afterAll(async () => {
    await t?.drop();
  });
  beforeEach(async () => {
    await t.db.delete(schema.systemReport);
    await t.db.delete(schema.workerHeartbeat);
  });

  const reportOf = async (key: string) =>
    (await t.db.select().from(schema.systemReport).where(eq(schema.systemReport.key, key)))[0]?.data;

  it("reports the version each scanner binary prints", async () => {
    held.env.GARNETOPS_GRYPE_BIN = fakeGrype(work, { dbFile });
    held.env.GARNETOPS_SYFT_BIN = fakeSyft(work, "1.55.0");
    await mod.reportScannerVersions();
    const report = scannersReportSchema.parse(await reportOf("scanners"));
    expect(report.grype).toMatchObject({ version: "0.120.1", problem: null });
    expect(report.syft).toMatchObject({ version: "1.55.0", problem: null });
  });

  it("says so when a binary is missing, unreadable or not configured, with codes and no output", async () => {
    held.env.GARNETOPS_GRYPE_BIN = join(work, "does-not-exist");
    held.env.GARNETOPS_SYFT_BIN = undefined;
    await mod.reportScannerVersions();
    let report = scannersReportSchema.parse(await reportOf("scanners"));
    expect(report.grype).toMatchObject({ version: null, problem: "missing" });
    expect(report.syft).toMatchObject({ version: null, problem: "not_configured" });

    const odd = join(work, "odd");
    writeFileSync(odd, "#!/bin/sh\necho 'something else entirely'\n");
    chmodSync(odd, 0o755);
    held.env.GARNETOPS_GRYPE_BIN = odd;
    await mod.reportScannerVersions();
    report = scannersReportSchema.parse(await reportOf("scanners"));
    expect(report.grype).toMatchObject({ version: null, problem: "unreadable" });
    expect(JSON.stringify(await reportOf("scanners"))).not.toContain("something else");
  });

  it("takes the versions a scan names and leaves the other scanner's entry alone", async () => {
    held.env.GARNETOPS_GRYPE_BIN = fakeGrype(work, { dbFile });
    held.env.GARNETOPS_SYFT_BIN = fakeSyft(work, "1.55.0");
    await mod.reportScannerVersions();
    await mod.reportScanFacts({ grypeVersion: "v0.119.0", syftVersion: null });
    const report = scannersReportSchema.parse(await reportOf("scanners"));
    expect(report.grype?.version).toBe("0.119.0");
    expect(report.syft?.version).toBe("1.55.0");
    // Garbage from a scan is ignored.
    await mod.reportScanFacts({ grypeVersion: "not a version" });
    expect(scannersReportSchema.parse(await reportOf("scanners")).grype?.version).toBe("0.119.0");
  });

  it("reads the database metadata, its providers and the advisories per provider", async () => {
    held.env.GARNETOPS_GRYPE_BIN = fakeGrype(work, { dbFile });
    held.env.GARNETOPS_GRYPE_DB_UPDATE = "auto";
    await mod.probeVulnDb();
    const report = vulnDbReportSchema.parse(await reportOf("vulndb"));
    expect(report).toMatchObject({
      valid: true,
      problem: null,
      schemaVersion: "6.1.5",
      builtAt: "2026-10-22T06:39:15.000Z",
      source: "anchore",
    });
    expect(report.providers.available).toBe(true);
    const byName = Object.fromEntries(report.providers.items.map((p) => [p.name, p]));
    expect(byName.nvd).toMatchObject({ records: 5, capturedAt: "2026-10-22T04:00:00.000Z" });
    expect(byName.github?.records).toBe(3);
    // Listed by grype but without advisories in the database: no count is not a count of zero.
    expect(byName.debian).toMatchObject({ records: null, capturedAt: null });
    // The URL grype prints for the download is not kept.
    expect(JSON.stringify(await reportOf("vulndb"))).not.toContain("example.com");
  });

  it("calls the source a manual import when the worker does not update by itself", async () => {
    held.env.GARNETOPS_GRYPE_BIN = fakeGrype(work, { dbFile });
    held.env.GARNETOPS_GRYPE_DB_UPDATE = "off";
    await mod.probeVulnDb();
    expect(vulnDbReportSchema.parse(await reportOf("vulndb")).source).toBe("manual");
  });

  it("reports a missing database as a problem code and no providers", async () => {
    held.env.GARNETOPS_GRYPE_BIN = fakeGrype(work, { dbFile, noDb: true });
    await mod.probeVulnDb();
    const report = vulnDbReportSchema.parse(await reportOf("vulndb"));
    expect(report).toMatchObject({ valid: false, problem: "missing", builtAt: null });
    expect(report.providers).toEqual({ available: false, items: [] });
  });

  it("lists the providers without counts when the database cannot be counted", async () => {
    const emptyDb = join(work, "db", "empty.db");
    new DatabaseSync(emptyDb).close(); // no table at all
    held.env.GARNETOPS_GRYPE_BIN = fakeGrype(work, { dbFile: emptyDb });
    await mod.probeVulnDb();
    const report = vulnDbReportSchema.parse(await reportOf("vulndb"));
    expect(report.providers.available).toBe(true);
    expect(report.providers.items.every((p) => p.records === null)).toBe(true);
  });

  it("keeps earlier facts when the update report is changed", async () => {
    await mod.reportVulnDbUpdate({
      mode: "auto",
      lastAttemptAt: "2026-10-22T05:00:00.000Z",
      lastSuccessAt: "2026-10-22T05:00:00.000Z",
      lastResult: "ok",
    });
    await mod.reportVulnDbUpdate({ mode: "auto", lastResult: "failed", reason: "network" });
    expect(vulnDbUpdateReportSchema.parse(await reportOf("vulndb_update"))).toMatchObject({
      lastSuccessAt: "2026-10-22T05:00:00.000Z",
      lastResult: "failed",
      reason: "network",
    });
  });

  it("records an automatic update's result and next time, a failure only as a code", async () => {
    const { startVulnDbUpdates } = await import("./vulndb.ts");
    held.env.GARNETOPS_GRYPE_DB_UPDATE = "auto";
    held.env.GARNETOPS_GRYPE_BIN = fakeGrype(work, {
      dbFile,
      updateExit: 1,
      updateError: "failed to download: dial tcp: lookup grype.example.com: no such host",
    });
    let stop = startVulnDbUpdates();
    await vi.waitFor(async () => {
      expect(vulnDbUpdateReportSchema.parse(await reportOf("vulndb_update")).lastResult).toBe("failed");
    });
    stop();
    const failed = vulnDbUpdateReportSchema.parse(await reportOf("vulndb_update"));
    expect(failed).toMatchObject({
      mode: "auto",
      lastResult: "failed",
      reason: "network",
      lastSuccessAt: null,
    });
    expect(new Date(failed.nextAt as string).getTime()).toBeGreaterThan(Date.now() + 23 * 3600_000);
    expect(JSON.stringify(failed)).not.toContain("example.com");

    held.env.GARNETOPS_GRYPE_BIN = fakeGrype(work, { dbFile });
    stop = startVulnDbUpdates();
    await vi.waitFor(async () => {
      expect(vulnDbUpdateReportSchema.parse(await reportOf("vulndb_update")).lastResult).toBe("ok");
    });
    stop();
    const ok = vulnDbUpdateReportSchema.parse(await reportOf("vulndb_update"));
    expect(ok).toMatchObject({ lastResult: "ok", reason: null });
    expect(ok.lastSuccessAt).not.toBeNull();
    // The metadata is read again after an update.
    await vi.waitFor(async () => expect(await reportOf("vulndb")).not.toBeUndefined());
  });

  it("only notes that updates are off when the operator imports the database", async () => {
    const { startVulnDbUpdates } = await import("./vulndb.ts");
    held.env.GARNETOPS_GRYPE_DB_UPDATE = "off";
    startVulnDbUpdates()();
    await vi.waitFor(async () =>
      expect(await reportOf("vulndb_update")).toMatchObject({ mode: "off", nextAt: null }),
    );
  });

  it("writes a heartbeat with the version and start time, keeps beating, and removes its row on a clean stop", async () => {
    const stale = new Date(Date.now() - 10 * 60_000);
    await t.db
      .insert(schema.workerHeartbeat)
      .values({ instanceId: "wrk_stopped_long_ago", version: "0.0.1", startedAt: stale, beatAt: stale });
    const stop = mod.startHeartbeat();
    await vi.waitFor(async () => {
      const rows = await t.db.select().from(schema.workerHeartbeat);
      expect(rows.map((r) => r.instanceId)).not.toContain("wrk_stopped_long_ago");
      expect(rows).toHaveLength(1);
    });
    const [row] = await t.db.select().from(schema.workerHeartbeat);
    expect(row).toMatchObject({ version: mod.workerVersion });
    expect(row?.startedAt.getTime()).toBeLessThanOrEqual(Date.now());
    expect(Date.now() - (row?.beatAt.getTime() ?? 0)).toBeLessThan(10_000);
    await stop();
    expect(await t.db.select().from(schema.workerHeartbeat)).toHaveLength(0);
  });

  it("never throws when it cannot write, and says only what kind of error it was", async () => {
    await t.db.execute(sql`alter table system_report rename to system_report_away`);
    const quiet = vi.spyOn(console, "error").mockImplementation(() => {});
    try {
      await expect(mod.reportScanFacts({ grypeVersion: "0.120.1" })).resolves.toBeUndefined();
      expect(quiet).toHaveBeenCalledTimes(1);
      expect(String(quiet.mock.calls[0]?.[0])).toMatch(/^system report \(scan\): \w+$/);
    } finally {
      quiet.mockRestore();
      await t.db.execute(sql`alter table system_report_away rename to system_report`);
    }
  });
});
