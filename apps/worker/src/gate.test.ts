/**
 * Gate evaluation in the worker (ADR 0008) against a real database, with a recorded grype
 * report (grype 0.120.1 on test/fixtures/npm-vulnerable): one critical and three high
 * findings with fixes. Needs the development PostgreSQL; no scanner, no network.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { cp, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateVaultKeyPair } from "@garnetops/core/vault";
import { createDb, schema } from "@garnetops/db";
import { and, count, eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";

const root = fileURLToPath(new URL("../../../", import.meta.url));
const fixtures = fileURLToPath(new URL("../test/fixtures/", import.meta.url));

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

const COMMIT = "a".repeat(40);
vi.mock("./git.ts", () => ({
  sshClient: async () => ({ bin: "ssh", kex: [] }),
  shallowClone: async (options: { dir: string; ref?: string | null }) => {
    await cp(join(fixtures, "npm-vulnerable"), options.dir, { recursive: true });
    return { commitSha: "a".repeat(40), branch: options.ref ?? "main" };
  },
}));
vi.mock("./grype.ts", async (original) => ({
  ...(await original<typeof import("./grype.ts")>()),
  scanTarget: async () => JSON.parse(readFileSync(join(fixtures, "grype-npm-vulnerable.json"), "utf8")),
  addAdvisoryDates: () => {},
}));

describe.skipIf(!adminUrl)("quality gate of a scan", () => {
  const dbName = `garnetops_gate_test_${process.pid}`;
  const org = "org_gate";
  const repo = "repo_gate";
  let admin: ReturnType<typeof createDb>;
  let conn: ReturnType<typeof createDb>;
  let workDir: string;
  let runScan: (scanId: string) => Promise<void>;
  let workerPool: { end(): Promise<void> };
  let n = 0;

  beforeAll(async () => {
    admin = createDb(adminUrl as string, { max: 1 });
    await admin.pool.query(`drop database if exists ${dbName} with (force)`);
    await admin.pool.query(`create database ${dbName}`);
    const url = new URL(adminUrl as string);
    url.pathname = `/${dbName}`;
    workDir = await mkdtemp(join(tmpdir(), "garnetops-gate-test-"));
    const keyFile = join(workDir, "vault.key.pem");
    writeFileSync(keyFile, generateVaultKeyPair().privateKeyPem, { mode: 0o600 });
    Object.assign(process.env, {
      NODE_ENV: "test",
      DATABASE_URL: url.toString(),
      GARNETOPS_VAULT_PRIVATE_KEY_FILE: keyFile,
      GARNETOPS_GRYPE_BIN: "grype-not-used",
      GARNETOPS_GRYPE_DB_DIR: workDir,
      GARNETOPS_WORK_DIR: workDir,
    });
    delete process.env.GARNETOPS_SYFT_BIN;
    conn = createDb(url.toString(), { max: 2 });
    const { runMigrations } = await import("@garnetops/db");
    await runMigrations(conn.db);
    ({ runScan } = await import("./scan.ts"));
    ({ pool: workerPool } = await import("./db.ts"));
    await conn.db.insert(schema.organization).values({ id: org, name: "Gate test" });
    await conn.db.insert(schema.repository).values({
      id: repo,
      organizationId: org,
      name: "fixture",
      url: "https://git.example.test/team/fixture.git",
      authKind: "none",
    });
  }, 60_000);

  afterAll(async () => {
    await workerPool?.end();
    await conn?.pool.end();
    // pool.end() resolves before every socket has closed; dropping with force right away would
    // terminate them and surface as unhandled errors (same as packages/db/src/testing.ts).
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
    if (workDir) await rm(workDir, { recursive: true, force: true });
  });

  async function scan(extra: { ref?: string; expectedSha?: string } = {}) {
    const id = `scan_gate_${++n}`;
    await conn.db.insert(schema.scan).values({
      id,
      organizationId: org,
      repositoryId: repo,
      state: "queued",
      trigger: extra.ref ? "ci" : "manual",
      ref: extra.ref ?? null,
      expectedSha: extra.expectedSha ?? null,
    });
    await runScan(id);
    const [row] = await conn.db.select().from(schema.scan).where(eq(schema.scan.id, id));
    const [run] = await conn.db.select().from(schema.gateRun).where(eq(schema.gateRun.scanId, id));
    return { scan: row, run };
  }

  it("reports by default and never blocks without an admin's choice", async () => {
    const { scan: s, run } = await scan();
    expect(s?.state).toBe("succeeded");
    expect(run?.result).toBe("notes");
    expect(run?.matches).toEqual({
      "critical-fixable": { count: 1, mode: "report" },
      "high-fixable": { count: 3, mode: "report" },
    });
  });

  it("blocks once the rule is set to block, and counts no accepted risk", async () => {
    await conn.db
      .insert(schema.gateRule)
      .values({ organizationId: org, rule: "critical-fixable", mode: "block" });
    expect((await scan()).run?.result).toBe("blocked");

    await conn.db
      .update(schema.finding)
      .set({
        state: "accepted",
        acceptedReason: "Not reachable in production.",
        acceptedUntil: new Date(Date.now() + 86_400_000),
      })
      .where(and(eq(schema.finding.repositoryId, repo), eq(schema.finding.severity, "critical")));
    const { run } = await scan();
    expect(run?.result).toBe("notes");
    expect(run?.matches).toEqual({ "high-fixable": { count: 3, mode: "report" } });
  });

  it("checks a pull request ref without touching the repository's findings", async () => {
    const before = await conn.db.select().from(schema.repository).where(eq(schema.repository.id, repo));
    const [findingsBefore] = await conn.db
      .select({ n: count() })
      .from(schema.finding)
      .where(eq(schema.finding.repositoryId, repo));
    const { scan: s, run } = await scan({ ref: "refs/pull/1/head", expectedSha: COMMIT });
    expect(s?.state).toBe("succeeded");
    expect(s?.branch).toBe("refs/pull/1/head");
    expect(run?.result).toBe("notes");
    const after = await conn.db.select().from(schema.repository).where(eq(schema.repository.id, repo));
    const [findingsAfter] = await conn.db
      .select({ n: count() })
      .from(schema.finding)
      .where(eq(schema.finding.repositoryId, repo));
    expect(after[0]?.lastScanId).toBe(before[0]?.lastScanId);
    expect(findingsAfter?.n).toBe(findingsBefore?.n);
  });

  it("fails a check whose ref points to another commit than expected, without a result", async () => {
    const { scan: s, run } = await scan({ ref: "refs/pull/1/head", expectedSha: "b".repeat(40) });
    expect(s?.state).toBe("failed");
    expect(s?.error).toBe("The ref points to a different commit than the gate check expected.");
    expect(run).toBeUndefined();
  });
});
