/**
 * Gate evaluation in the worker (ADR 0008) against a real database, with a recorded grype
 * report (grype 0.120.1 on test/fixtures/npm-vulnerable): one critical and three high
 * findings with fixes. Needs the development PostgreSQL; no scanner, no network.
 */

import { readFileSync, writeFileSync } from "node:fs";
import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { generateVaultKeyPair, loadVaultPublicKey, seal } from "@garnetops/core/vault";
import { createDb, schema } from "@garnetops/db";
import { and, count, eq } from "drizzle-orm";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { copyFixtureRepo } from "../test/fixture-repo.ts";

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
    await copyFixtureRepo("npm-vulnerable", options.dir);
    // A real commit, like the clone makes, so that the scan can read the manifests from its tree (ADR 0014).
    const { execFileSync } = await import("node:child_process");
    const git = (...args: string[]) =>
      execFileSync("git", ["-C", options.dir, ...args], {
        stdio: "ignore",
        env: {
          PATH: process.env.PATH,
          GIT_CONFIG_GLOBAL: "/dev/null",
          GIT_CONFIG_NOSYSTEM: "1",
          GIT_AUTHOR_NAME: "t",
          GIT_AUTHOR_EMAIL: "t@example.test",
          GIT_COMMITTER_NAME: "t",
          GIT_COMMITTER_EMAIL: "t@example.test",
        },
      });
    git("init", "--quiet");
    git("add", "-A");
    git("commit", "--quiet", "-m", "fixture");
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
  let vaultPublic = "";

  beforeAll(async () => {
    admin = createDb(adminUrl as string, { max: 1 });
    await admin.pool.query(`drop database if exists ${dbName} with (force)`);
    await admin.pool.query(`create database ${dbName}`);
    const url = new URL(adminUrl as string);
    url.pathname = `/${dbName}`;
    workDir = await mkdtemp(join(tmpdir(), "garnetops-gate-test-"));
    const keyFile = join(workDir, "vault.key.pem");
    const keys = generateVaultKeyPair();
    vaultPublic = keys.publicKeyPem;
    writeFileSync(keyFile, keys.privateKeyPem, { mode: 0o600 });
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
    // The first scan finds the critical vulnerability: that is a notification (ADR 0010).
    const { eventsForScan } = await import("./notify.ts");
    const events = await eventsForScan(s?.id as string);
    expect(events?.payloads.map((p) => p.event)).toEqual(["finding.new_critical", "finding.new"]);
    expect(events?.payloads[0]?.counts).toEqual({ critical: 1, knownExploited: 0 });
    expect(events?.payloads[1]?.findings).toMatchObject({ critical: 1, high: 3 });
    expect(JSON.stringify(events)).not.toMatch(/GHSA-|lodash|minimist/);

    // Each channel gets what its events and filters ask for (0.0.10): the minimum severity of
    // finding.new (high by default) and its repositories.
    const channel = (id: string, events: string[], filters: Record<string, unknown>) => ({
      id,
      organizationId: org,
      name: id,
      kind: "webhook" as const,
      format: "discord",
      events,
      filters,
      config: {},
    });
    await conn.db
      .insert(schema.notificationChannel)
      .values([
        channel("nch_all", ["finding.new"], {}),
        channel("nch_critical", ["finding.new"], { minSeverity: "critical" }),
        channel("nch_other_repo", ["finding.new", "finding.new_critical"], { repositoryIds: ["repo_other"] }),
        channel("nch_this_repo", ["finding.new_critical"], { repositoryIds: [repo] }),
      ]);
    const sent: { channelId: string; payload: { event: string; findings?: Record<string, number> } }[] = [];
    const boss = { send: async (_queue: string, data: (typeof sent)[number]) => void sent.push(data) };
    const { queueNotifications } = await import("./notify.ts");
    await queueNotifications(boss as never, org, events?.payloads ?? []);
    expect(sent.map((s) => `${s.channelId} ${s.payload.event}`).sort()).toEqual([
      "nch_all finding.new",
      "nch_critical finding.new",
      "nch_this_repo finding.new_critical",
    ]);
    expect(sent.find((s) => s.channelId === "nch_critical")?.payload.findings).toEqual({
      critical: 1,
      high: 0,
      medium: 0,
      low: 0,
    });
    await conn.db.delete(schema.notificationChannel);
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
    const blocked = await scan();
    expect(blocked.run?.result).toBe("blocked");
    const { eventsForScan } = await import("./notify.ts");
    // Nothing new this time, but the gate blocked.
    expect((await eventsForScan(blocked.scan?.id as string))?.payloads).toEqual([
      expect.objectContaining({ event: "gate.blocked", gate: { blockingRules: 1 } }),
    ]);

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
    // Pull request checks are reported by the pipeline, not by notifications.
    const { eventsForScan } = await import("./notify.ts");
    expect(await eventsForScan(s?.id as string)).toBeNull();
  });

  it("opens a channel's sealed webhook URL, refuses an unsafe one and records the failure", async () => {
    const vault = loadVaultPublicKey(vaultPublic);
    const secretId = "sec_hook";
    await conn.db.insert(schema.secret).values({
      id: secretId,
      organizationId: org,
      purpose: "webhook-url",
      sealed: seal(
        "https://localhost/hooks/token-never-logged",
        { organizationId: org, recordId: secretId, purpose: "webhook-url" },
        vault,
      ),
      vaultKeyId: vault.id,
    });
    await conn.db.insert(schema.notificationChannel).values({
      id: "nch_gate",
      organizationId: org,
      name: "Chat",
      kind: "webhook",
      format: "discord",
      events: ["gate.blocked"],
      config: { host: "localhost" },
      secretId,
    });
    const { deliver } = await import("./notify.ts");
    const payload = {
      event: "test" as const,
      organization: "Gate test",
      repository: null,
      link: "https://garnetops.example.com",
      at: new Date().toISOString(),
    };
    await expect(deliver("nch_gate", payload)).rejects.toThrow("This address is not allowed");
    const rows = await conn.db
      .select()
      .from(schema.notificationDelivery)
      .where(eq(schema.notificationDelivery.channelId, "nch_gate"));
    expect(rows).toEqual([
      expect.objectContaining({ status: "failed", error: "This address is not allowed", event: "test" }),
    ]);
    expect(JSON.stringify(rows)).not.toContain("token-never-logged");
  });

  it("fails a check whose ref points to another commit than expected, without a result", async () => {
    const { scan: s, run } = await scan({ ref: "refs/pull/1/head", expectedSha: "b".repeat(40) });
    expect(s?.state).toBe("failed");
    expect(s?.error).toBe("The ref points to a different commit than the gate check expected.");
    expect(run).toBeUndefined();
  });

  it("records the manifests of the scanned commit, and a check of another ref leaves them alone", async () => {
    await scan();
    const manifests = await conn.db
      .select()
      .from(schema.repositoryManifest)
      .where(eq(schema.repositoryManifest.repositoryId, repo));
    expect(manifests).toHaveLength(1);
    expect(manifests[0]).toMatchObject({ path: "package.json", kind: "npm", organizationId: org });
    expect(manifests[0]?.blobSha).toMatch(/^[0-9a-f]{40}$/);
    expect(
      ((manifests[0]?.dependencies ?? []) as { name: string; spec: string }[]).map((d) => [d.name, d.spec]),
    ).toEqual([
      ["lodash", "4.17.15"],
      ["minimist", "1.2.0"],
    ]);
    // A second scan replaces the rows instead of adding to them.
    const second = await scan();
    expect(
      await conn.db
        .select()
        .from(schema.repositoryManifest)
        .where(eq(schema.repositoryManifest.repositoryId, repo)),
    ).toHaveLength(1);
    await scan({ ref: "refs/pull/9/head" });
    const after = await conn.db
      .select()
      .from(schema.repositoryManifest)
      .where(eq(schema.repositoryManifest.repositoryId, repo));
    expect(after).toHaveLength(1);
    expect(after[0]?.scanId).toBe(second.scan?.id);
  });
});
