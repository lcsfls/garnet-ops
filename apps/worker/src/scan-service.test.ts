/**
 * A whole scan through the scanner service (ADR 0028) against a real database: the worker clones
 * into the shared directory, the service runs the real syft and a stand-in grype that returns the
 * recorded report (grype 0.120.1 on test/fixtures/npm-vulnerable). Needs the development PostgreSQL
 * and syft from `pnpm scanners:fetch`; no network, no vulnerability database.
 */
import { existsSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { mkdir, mkdtemp, rm } from "node:fs/promises";
import type { Server } from "node:http";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateVaultKeyPair } from "@garnetops/core/vault";
import { createDb, schema } from "@garnetops/db";
import { eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { copyFixtureRepo } from "../test/fixture-repo.ts";
import { createScannerService } from "./scanner-service.ts";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const fixtures = fileURLToPath(new URL("../test/fixtures/", import.meta.url));
const syftBin = join(root, ".tools", "syft", "syft");

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
const ready = Boolean(adminUrl) && existsSync(syftBin) && process.platform !== "win32";

/** Where the replaced clone put the repository and git's home, per scan. */
const clones = vi.hoisted(() => [] as { dir: string; home: string }[]);
vi.mock("./git.ts", () => ({
  sshClient: async () => ({ bin: "ssh", kex: [] }),
  shallowClone: async (options: { dir: string; home: string }) => {
    clones.push({ dir: options.dir, home: options.home });
    await copyFixtureRepo("npm-vulnerable", options.dir);
    return { commitSha: "b".repeat(40), branch: "main" };
  },
}));
vi.mock("./grype.ts", async (original) => ({
  ...(await original<typeof import("./grype.ts")>()),
  addAdvisoryDates: () => {},
}));

describe.skipIf(!ready)("scan through the scanner service", () => {
  const dbName = `garnetops_scan_service_test_${process.pid}`;
  const org = "org_svc";
  const repo = "repo_svc";
  let admin: ReturnType<typeof createDb>;
  let conn: ReturnType<typeof createDb>;
  let base: string;
  let shared: string;
  let socket: string;
  let server: Server;
  let runScan: (scanId: string) => Promise<void>;
  let workerPool: { end(): Promise<void> };
  let n = 0;

  beforeAll(async () => {
    admin = createDb(adminUrl as string, { max: 1 });
    await admin.pool.query(`drop database if exists ${dbName} with (force)`);
    await admin.pool.query(`create database ${dbName}`);
    const url = new URL(adminUrl as string);
    url.pathname = `/${dbName}`;

    base = await mkdtemp(join(tmpdir(), "garnetops-scan-service-test-"));
    shared = join(base, "shared");
    socket = join(base, "scanner.sock");
    await Promise.all(["shared", "private", "bin"].map((d) => mkdir(join(base, d))));
    const keyFile = join(base, "vault.key.pem");
    writeFileSync(keyFile, generateVaultKeyPair().privateKeyPem, { mode: 0o600 });
    // grype: `sbom:<file> -o json --file <out> -q`; answers with the recorded report.
    const grype = join(base, "bin", "grype");
    writeFileSync(grype, `#!/bin/sh\ncp "${join(fixtures, "grype-npm-vulnerable.json")}" "$5"\n`, {
      mode: 0o755,
    });

    server = createScannerService({
      workDir: shared,
      grypeBin: grype,
      syftBin,
      grypeDbDir: join(base, "db"),
      concurrency: 1,
      version: "0.0.9",
    });
    await new Promise<void>((resolve) => server.listen(socket, resolve));

    Object.assign(process.env, {
      NODE_ENV: "test",
      DATABASE_URL: url.toString(),
      GARNETOPS_VAULT_PRIVATE_KEY_FILE: keyFile,
      // The worker's own scanners must not be used: these paths do not exist.
      GARNETOPS_GRYPE_BIN: join(base, "missing-grype"),
      GARNETOPS_SYFT_BIN: join(base, "missing-syft"),
      GARNETOPS_GRYPE_DB_DIR: join(base, "db"),
      GARNETOPS_WORK_DIR: join(base, "private"),
      GARNETOPS_SCANNER_SOCKET: socket,
      GARNETOPS_SCANNER_WORK_DIR: shared,
    });
    conn = createDb(url.toString(), { max: 2 });
    const { runMigrations } = await import("@garnetops/db");
    await runMigrations(conn.db);
    ({ runScan } = await import("./scan.ts"));
    ({ pool: workerPool } = await import("./db.ts"));
    await conn.db.insert(schema.organization).values({ id: org, name: "Service test" });
    await conn.db.insert(schema.repository).values({
      id: repo,
      organizationId: org,
      name: "fixture",
      url: "https://git.example.test/team/fixture.git",
      authKind: "none",
    });
  }, 60_000);

  afterAll(async () => {
    if (server?.listening) await new Promise((resolve) => server.close(resolve));
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
    for (const key of ["GARNETOPS_SCANNER_SOCKET", "GARNETOPS_SCANNER_WORK_DIR"]) delete process.env[key];
    if (base) await rm(base, { recursive: true, force: true });
  });

  async function scan() {
    const id = `scan_svc_${++n}`;
    await conn.db.insert(schema.scan).values({
      id,
      organizationId: org,
      repositoryId: repo,
      state: "queued",
      trigger: "manual",
    });
    await runScan(id);
    const [row] = await conn.db.select().from(schema.scan).where(eq(schema.scan.id, id));
    return row;
  }

  it("clones into the shared directory, scans there and keeps everything else private", async () => {
    // Two open early warnings (ADR 0029): the scan finds the first and not the second.
    await conn.db
      .insert(schema.vulnerability)
      .values([
        { id: "GHSA-35jh-r3h4-6jhm", severity: "high" },
        { id: "GHSA-none-0000", severity: "high" },
      ])
      .onConflictDoNothing();
    const warning = (id: string, vulnerabilityId: string) => ({
      id,
      organizationId: org,
      repositoryId: repo,
      vulnerabilityId,
      packageName: "lodash",
      packageVersion: "4.17.15",
      packageType: "npm",
      severity: "high",
      severityRank: 4,
    });
    await conn.db
      .insert(schema.earlyWarning)
      .values([warning("ewn_found", "GHSA-35jh-r3h4-6jhm"), warning("ewn_gone", "GHSA-none-0000")]);
    const s = await scan();
    const closed = await conn.db.select().from(schema.earlyWarning).orderBy(schema.earlyWarning.id);
    expect(closed.map((w) => [w.id, w.state, w.closedByScanId])).toEqual([
      ["ewn_found", "confirmed", s?.id],
      ["ewn_gone", "cleared", s?.id],
    ]);
    expect(s?.error).toBeNull();
    expect(s?.state).toBe("succeeded");
    // Only the clone was in the volume the service reads; git's home stayed in the worker's directory.
    const clone = clones.at(-1);
    expect(clone?.dir.startsWith(`${shared}/scan-`)).toBe(true);
    expect(clone?.home.startsWith(join(base, "private"))).toBe(true);
    // The recorded report has one critical and three high findings; syft's inventory was stored.
    const findings = await conn.db.select().from(schema.finding).where(eq(schema.finding.repositoryId, repo));
    expect(findings.filter((f) => f.severity === "critical")).toHaveLength(1);
    expect(findings.filter((f) => f.severity === "high")).toHaveLength(3);
    const packages = await conn.db
      .select()
      .from(schema.repositoryPackage)
      .where(eq(schema.repositoryPackage.repositoryId, repo));
    expect(packages.length).toBeGreaterThan(0);
    // Both directories are removed after the scan.
    expect(readdirSync(shared)).toEqual([]);
    expect(readdirSync(join(base, "private"))).toEqual([]);
  }, 120_000);

  it("fails the scan, never scans in the worker, when the service does not answer", async () => {
    await new Promise((resolve) => server.close(resolve));
    const s = await scan();
    expect(s?.state).toBe("failed");
    expect(s?.error).toBe("The scanner service did not answer. An admin can check it under System status.");
    expect(readdirSync(shared)).toEqual([]);
  }, 60_000);
});
