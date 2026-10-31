/**
 * Early warnings (ADR 0029) against a real database: a stand-in grype answers the package URL list with
 * a recorded shape, and a small advisory database gives the dates. Needs the development PostgreSQL.
 */
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath } from "node:url";
import { generateVaultKeyPair } from "@garnetops/core/vault";
import { createDb, schema } from "@garnetops/db";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const root = fileURLToPath(new URL("../../../", import.meta.url));

function devDatabaseUrl(): string | null {
  try {
    const line = readFileSync(join(root, ".data", "dev.env"), "utf8")
      .split("\n")
      .find((l) => l.startsWith("DATABASE_URL="));
    return line ? line.slice("DATABASE_URL=".length).trim() : null;
  } catch {
    return null;
  }
}
const adminUrl = devDatabaseUrl();

const LAST_SCAN_DB = new Date("2026-10-01T04:00:00Z");
const NEW_DB = "2026-10-28T04:00:00.000Z";

/** grype for `purl:<file> -o json --file <out> -q`: lodash and minimist match, left-pad does not. */
const report = {
  matches: [
    {
      vulnerability: {
        id: "GHSA-new-0001",
        severity: "High",
        fix: { versions: ["4.17.21"], state: "fixed" },
      },
      artifact: { name: "lodash", version: "4.17.20", type: "npm", purl: "pkg:npm/lodash@4.17.20" },
    },
    {
      // Already a finding of the repository: no early warning.
      vulnerability: { id: "GHSA-known-0002", severity: "Critical" },
      artifact: { name: "lodash", version: "4.17.20", type: "npm", purl: "pkg:npm/lodash@4.17.20" },
    },
    {
      // Published before the last scan's database: the scan would have seen it, so not new.
      vulnerability: { id: "GHSA-old-0003", severity: "Medium" },
      artifact: { name: "minimist", version: "1.2.5", type: "npm", purl: "pkg:npm/minimist@1.2.5" },
    },
  ],
  descriptor: { version: "0.120.1", db: { status: { built: NEW_DB } } },
};

describe.skipIf(!adminUrl)("early warnings", () => {
  const dbName = `garnetops_early_warning_test_${process.pid}`;
  const work = mkdtempSync(join(tmpdir(), "garnetops-early-warning-test-"));
  let admin: ReturnType<typeof createDb>;
  let conn: ReturnType<typeof createDb>;
  let workerPool: { end(): Promise<void> };
  let check: typeof import("./early-warning.ts")["checkEarlyWarnings"];
  const sent: { channelId: string; payload: Record<string, unknown> }[] = [];
  const boss = { send: async (_q: string, data: (typeof sent)[number]) => void sent.push(data) };

  beforeAll(async () => {
    admin = createDb(adminUrl as string, { max: 1 });
    await admin.pool.query(`drop database if exists ${dbName} with (force)`);
    await admin.pool.query(`create database ${dbName}`);
    const url = new URL(adminUrl as string);
    url.pathname = `/${dbName}`;

    const grype = join(work, "grype");
    writeFileSync(join(work, "report.json"), JSON.stringify(report));
    // Checks that it was given package URLs, then answers with the recorded report.
    writeFileSync(
      grype,
      `#!/bin/sh\ncase "$1" in purl:*) ;; *) exit 9;; esac\ngrep -q '^pkg:npm/lodash@4.17.20$' "\${1#purl:}" || exit 8\ncp "${join(work, "report.json")}" "$5"\n`,
      { mode: 0o755 },
    );
    const dbDir = join(work, "db");
    mkdirSync(join(dbDir, "6"), { recursive: true });
    const advisories = new DatabaseSync(join(dbDir, "6", "vulnerability.db"));
    advisories.exec(
      "create table vulnerability_handles (name text, published_date text, modified_date text)",
    );
    const insert = advisories.prepare("insert into vulnerability_handles values (?, ?, ?)");
    insert.run("GHSA-new-0001", "2026-10-20 10:00:00+00:00", "2026-10-21 10:00:00+00:00");
    insert.run("GHSA-known-0002", "2026-10-20 10:00:00+00:00", null);
    insert.run("GHSA-old-0003", "2025-01-01 10:00:00+00:00", "2025-02-01 10:00:00+00:00");
    advisories.close();

    const keyFile = join(work, "vault.key.pem");
    writeFileSync(keyFile, generateVaultKeyPair().privateKeyPem, { mode: 0o600 });
    Object.assign(process.env, {
      NODE_ENV: "test",
      DATABASE_URL: url.toString(),
      GARNETOPS_VAULT_PRIVATE_KEY_FILE: keyFile,
      GARNETOPS_GRYPE_BIN: grype,
      GARNETOPS_GRYPE_DB_DIR: dbDir,
      GARNETOPS_WORK_DIR: work,
      PUBLIC_URL: "https://garnetops.example.com",
    });
    delete process.env.GARNETOPS_SCANNER_SOCKET;
    delete process.env.GARNETOPS_SCANNER_WORK_DIR;

    conn = createDb(url.toString(), { max: 2 });
    const { runMigrations } = await import("@garnetops/db");
    await runMigrations(conn.db);
    ({ checkEarlyWarnings: check } = await import("./early-warning.ts"));
    ({ pool: workerPool } = await import("./db.ts"));

    const d = conn.db;
    await d.insert(schema.organization).values({ id: "org_ew", name: "Example" });
    await d.insert(schema.repository).values({
      id: "repo_ew",
      organizationId: "org_ew",
      name: "app",
      url: "https://git.example.test/team/app.git",
      authKind: "none",
    });
    await d.insert(schema.scan).values({
      id: "scan_ew",
      organizationId: "org_ew",
      repositoryId: "repo_ew",
      state: "succeeded",
      trigger: "manual",
      vulnDbBuiltAt: LAST_SCAN_DB,
    });
    await d
      .update(schema.repository)
      .set({ lastScanId: "scan_ew" })
      .where(eq(schema.repository.id, "repo_ew"));
    await d.insert(schema.repositoryPackage).values(
      [
        ["lodash", "4.17.20"],
        ["minimist", "1.2.5"],
        ["left-pad", "1.3.0"],
      ].map(([name, version]) => ({
        id: `pkg_${name}`,
        organizationId: "org_ew",
        repositoryId: "repo_ew",
        scanId: "scan_ew",
        name: name as string,
        version: version as string,
        type: "npm",
        purl: `pkg:npm/${name}@${version}`,
      })),
    );
    await d.insert(schema.vulnerability).values({ id: "GHSA-known-0002", severity: "critical" });
    await d.insert(schema.finding).values({
      id: "fnd_known",
      organizationId: "org_ew",
      repositoryId: "repo_ew",
      vulnerabilityId: "GHSA-known-0002",
      dedupKey: "repo_ew|GHSA-known-0002|npm|lodash",
      packageName: "lodash",
      packageVersion: "4.17.20",
      packageType: "npm",
      severity: "critical",
      severityRank: 5,
      state: "resolved",
      firstSeenScanId: "scan_ew",
      lastSeenScanId: "scan_ew",
      firstSeenAt: LAST_SCAN_DB,
      lastSeenAt: LAST_SCAN_DB,
    });
    await d.insert(schema.notificationChannel).values({
      id: "nch_ew",
      organizationId: "org_ew",
      name: "chat",
      kind: "webhook",
      format: "discord",
      events: ["advisory.new"],
      config: {},
    });
  }, 60_000);

  afterAll(async () => {
    await workerPool?.end();
    await conn?.pool.end();
    for (let attempt = 0; attempt < 50; attempt++) {
      const dropped = await admin?.pool.query(`drop database if exists ${dbName}`).then(
        () => true,
        () => false,
      );
      if (dropped) break;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
    await admin?.pool.query(`drop database if exists ${dbName} with (force)`);
    await admin?.pool.end();
    rmSync(work, { recursive: true, force: true });
  });

  const reportVulnDb = (builtAt: string | null) =>
    conn.db
      .insert(schema.systemReport)
      .values({
        key: "vulndb",
        data: {
          checkedAt: new Date().toISOString(),
          valid: builtAt !== null,
          problem: builtAt ? null : "missing",
          schemaVersion: "6.1.5",
          builtAt,
          source: "anchore",
          providers: { available: false, items: [] },
        },
      })
      .onConflictDoUpdate({
        target: schema.systemReport.key,
        set: {
          data: {
            checkedAt: new Date().toISOString(),
            valid: builtAt !== null,
            problem: builtAt ? null : "missing",
            schemaVersion: "6.1.5",
            builtAt,
            source: "anchore",
            providers: { available: false, items: [] },
          },
        },
      });

  it("does nothing without a usable database", async () => {
    await reportVulnDb(null);
    expect(await check(boss as never)).toBeNull();
  });

  it("warns of a new advisory for a stored package, not of known or older ones, and tells the channel", async () => {
    await reportVulnDb(NEW_DB);
    expect(await check(boss as never)).toBe(1);
    const warnings = await conn.db.select().from(schema.earlyWarning);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatchObject({
      repositoryId: "repo_ew",
      vulnerabilityId: "GHSA-new-0001",
      packageName: "lodash",
      packageVersion: "4.17.20",
      severity: "high",
      state: "open",
      fixedIn: ["4.17.21"],
    });
    expect(sent).toHaveLength(1);
    expect(sent[0]?.payload).toMatchObject({
      event: "advisory.new",
      repository: { id: "repo_ew", name: "app" },
      findings: { critical: 0, high: 1, medium: 0, low: 0 },
      link: "https://garnetops.example.com/early-warnings?repositoryId=repo_ew",
    });
    expect(JSON.stringify(sent)).not.toMatch(/GHSA-|lodash/);
  });

  it("checks each database build once, and a warning is never added twice", async () => {
    expect(await check(boss as never)).toBeNull();
    await reportVulnDb("2026-10-29T04:00:00.000Z");
    expect(await check(boss as never)).toBe(0);
    expect(await conn.db.select().from(schema.earlyWarning)).toHaveLength(1);
  });
  it("leaves a repository that is set aside out (ADR 0043)", async () => {
    await conn.db.delete(schema.earlyWarning);
    await conn.db
      .update(schema.repository)
      .set({ inactiveAt: new Date() })
      .where(eq(schema.repository.id, "repo_ew"));
    await reportVulnDb("2026-10-30T04:00:00.000Z");
    expect(await check(boss as never)).toBe(0);
    expect(await conn.db.select().from(schema.earlyWarning)).toEqual([]);
    await conn.db
      .update(schema.repository)
      .set({ inactiveAt: null })
      .where(eq(schema.repository.id, "repo_ew"));
  });
});
